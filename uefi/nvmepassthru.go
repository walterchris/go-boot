// Copyright (c) The go-boot authors. All Rights Reserved.
//
// Use of this source code is governed by the license
// that can be found in the LICENSE file.

package uefi

import (
	"encoding/binary"
	"errors"
	"runtime"
)

// EFI_NVM_EXPRESS_PASS_THRU_PROTOCOL_GUID identifies the protocol that submits raw
// NVM Express commands to a controller (UEFI 2.10 §14.16). It is the carrier for
// TCG Opal IF-SEND/IF-RECV expressed as the NVMe Security Send (0x81) / Security
// Receive (0x82) admin commands — the same path the OS NVMe driver uses, and
// unlike EFI_STORAGE_SECURITY_COMMAND_PROTOCOL it is not mediated by a firmware
// TCG stack (which on some platforms virtualizes the ComID and refuses host
// StartSession).
var EFI_NVM_EXPRESS_PASS_THRU_PROTOCOL_GUID = MustParseGUID("52c78312-8edc-4233-98f2-1a1aa5e388a5")

// EFI_NVM_EXPRESS_PASS_THRU_PROTOCOL member offsets (Mode, then PassThru).
const nvmePassThru = 0x08

// NVMe Security Send/Receive admin opcodes.
const (
	nvmeSecuritySend    = 0x81
	nvmeSecurityReceive = 0x82
)

// EFI_NVM_EXPRESS_PASS_THRU_COMMAND_PACKET QueueType: Security commands are admin
// commands.
const nvmeAdminQueue = 0x00

// cdwFlagsCdw10Cdw11 marks Command Dwords 10 and 11 valid in
// EFI_NVM_EXPRESS_COMMAND.Flags (the only Dwords Security Send/Receive set besides
// the opcode).
const cdwFlagsCdw10Cdw11 = 0x04 | 0x08 // CDW10_VALID | CDW11_VALID

// NVMePassThru is a located EFI_NVM_EXPRESS_PASS_THRU_PROTOCOL instance bound to
// one NVMe controller.
type NVMePassThru struct {
	base     uint64 // protocol structure address (the This pointer)
	passThru uint64 // address of the PassThru member slot
}

// LocateNVMePassThruHandles returns the handles exposing
// EFI_NVM_EXPRESS_PASS_THRU_PROTOCOL (one per NVMe controller). The caller selects
// the Opal SED among them (a Level-0 Discovery probe), as it does for Storage
// Security carriers.
func (s *BootServices) LocateNVMePassThruHandles() ([]uint64, error) {
	return s.LocateHandleBuffer(ByProtocol, EFI_NVM_EXPRESS_PASS_THRU_PROTOCOL_GUID)
}

// GetNVMePassThruByHandle resolves EFI_NVM_EXPRESS_PASS_THRU_PROTOCOL on a handle.
func (s *BootServices) GetNVMePassThruByHandle(handle uint64) (*NVMePassThru, error) {
	base, err := s.HandleProtocol(handle, EFI_NVM_EXPRESS_PASS_THRU_PROTOCOL_GUID)
	if err != nil {
		return nil, err
	}
	return newNVMePassThru(base)
}

// newNVMePassThru resolves the PassThru member slot from a located protocol
// interface address, failing closed on a corrupt (NULL-pointer) instance.
//
// Like every service dispatch, passThru holds the address of the member slot —
// not the function pointer stored in it — because callFn performs the dereference.
func newNVMePassThru(base uint64) (*NVMePassThru, error) {
	var fn struct {
		Mode     uint64
		PassThru uint64
	}
	if err := decode(&fn, base); err != nil {
		return nil, err
	}
	if fn.PassThru == 0 {
		return nil, errors.New("nvme passthru: NULL PassThru pointer")
	}
	return &NVMePassThru{base: base, passThru: base + nvmePassThru}, nil
}

// nvmeCommand builds an EFI_NVM_EXPRESS_COMMAND for a Security Send/Receive: opcode
// in Cdw0, namespace 0 (controller), Cdw10 = (SECP<<24)|(SPSP<<8) and Cdw11 = the
// transfer length. SPSP carries the TCG ComID in NVMe's native order — no byte
// swap (the swap that EFI_STORAGE_SECURITY_COMMAND_PROTOCOL needs is a property of
// that protocol's marshalling, not of NVMe).
func nvmeCommand(opcode uint8, securityProtocol uint8, spSpecific uint16, length uint32) []byte {
	cmd := make([]byte, 44)
	binary.LittleEndian.PutUint32(cmd[0:], uint32(opcode)) // Cdw0
	cmd[4] = cdwFlagsCdw10Cdw11                            // Flags
	// cmd[8:12] Nsid = 0 (admin / controller)
	binary.LittleEndian.PutUint32(cmd[20:], uint32(securityProtocol)<<24|uint32(spSpecific)<<8) // Cdw10
	binary.LittleEndian.PutUint32(cmd[24:], length)                                             // Cdw11
	return cmd
}

// submit issues one NVMe command packet (admin queue) carrying data and returns
// the firmware status. cmd, data and completion are referenced from the packet
// only by raw address, so they are kept alive across the call for the GC.
func (p *NVMePassThru) submit(cmd, data, completion []byte) error {
	packet := make([]byte, 56)
	// CommandTimeout (0) at [0:8].
	if len(data) > 0 {
		binary.LittleEndian.PutUint64(packet[8:], ptrval(&data[0])) // TransferBuffer
		binary.LittleEndian.PutUint32(packet[16:], uint32(len(data)))
	}
	// MetadataBuffer (0) at [24:32], MetadataLength (0) at [32:36].
	packet[36] = nvmeAdminQueue                                 // QueueType
	binary.LittleEndian.PutUint64(packet[40:], ptrval(&cmd[0])) // NvmeCmd
	binary.LittleEndian.PutUint64(packet[48:], ptrval(&completion[0]))

	status := callService(p.passThru, []uint64{
		p.base,
		0, // NamespaceId: 0 = controller (admin Security commands)
		ptrval(&packet[0]),
		0, // Event: NULL = blocking
	})

	runtime.KeepAlive(cmd)
	runtime.KeepAlive(data)
	runtime.KeepAlive(completion)
	runtime.KeepAlive(packet)
	return parseStatus(status)
}

// SecuritySend issues an NVMe Security Send (IF-SEND) for the given security
// protocol and ComID (SP-specific). payload is transferred to the controller.
func (p *NVMePassThru) SecuritySend(securityProtocol uint8, comID uint16, payload []byte) error {
	cmd := nvmeCommand(nvmeSecuritySend, securityProtocol, comID, uint32(len(payload)))
	completion := make([]byte, 16)
	return p.submit(cmd, payload, completion)
}

// SecurityReceive issues an NVMe Security Receive (IF-RECV) and returns size bytes
// (the controller transfers up to the allocation length into the buffer).
func (p *NVMePassThru) SecurityReceive(securityProtocol uint8, comID uint16, size int) ([]byte, error) {
	cmd := nvmeCommand(nvmeSecurityReceive, securityProtocol, comID, uint32(size))
	completion := make([]byte, 16)
	buf := make([]byte, size)
	if err := p.submit(cmd, buf, completion); err != nil {
		return nil, err
	}
	return buf, nil
}

// NVMe Identify admin command (opcode 0x06); Cdw10 CNS=0x01 selects Identify
// Controller. The controller returns a 4096-byte data structure whose Serial
// Number (SN) is 20 ASCII bytes at offset 4 (NVMe Base spec, Identify Controller).
const (
	nvmeIdentify    = 0x06
	cnsIdentifyCtrl = 0x01
	cdwFlagsCdw10   = 0x04 // CDW10_VALID (Identify sets only Cdw10)
	nvmeIdentifyLen = 4096
	nvmeSerialOff   = 4
	nvmeSerialLen   = 20
)

// IdentifyController issues NVMe Identify Controller (CNS=1) and returns the raw
// 4096-byte identify data.
func (p *NVMePassThru) IdentifyController() ([]byte, error) {
	cmd := make([]byte, 44)
	binary.LittleEndian.PutUint32(cmd[0:], nvmeIdentify)     // Cdw0: opcode
	cmd[4] = cdwFlagsCdw10                                   // Flags: CDW10 valid
	binary.LittleEndian.PutUint32(cmd[20:], cnsIdentifyCtrl) // Cdw10: CNS
	data := make([]byte, nvmeIdentifyLen)
	completion := make([]byte, 16)
	if err := p.submit(cmd, data, completion); err != nil {
		return nil, err
	}
	return data, nil
}

// SerialNumber returns the controller's 20-byte Serial Number (Identify Controller
// bytes 4..23), space-padded ASCII as reported by the drive. It is returned
// exactly as-is (no trimming): callers that use it as a salt — e.g. the sedutil
// PBKDF2 credential derivation, whose salt is these raw 20 bytes — must match the
// drive's own encoding.
func (p *NVMePassThru) SerialNumber() ([]byte, error) {
	id, err := p.IdentifyController()
	if err != nil {
		return nil, err
	}
	sn := make([]byte, nvmeSerialLen)
	copy(sn, id[nvmeSerialOff:nvmeSerialOff+nvmeSerialLen])
	return sn, nil
}
