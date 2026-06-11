// Copyright (c) The go-boot authors. All Rights Reserved.
//
// Use of this source code is governed by the license
// that can be found in the LICENSE file.

package uefi

import "errors"

// ErrTruncated indicates a ReceiveData transfer size larger than the supplied
// buffer (a misbehaving firmware/device); the caller must fail closed.
var ErrTruncated = errors.New("storage security: transfer size exceeds buffer")

// EFI_STORAGE_SECURITY_COMMAND_PROTOCOL_GUID identifies the protocol used to issue
// SECURITY PROTOCOL IN/OUT (Trusted Receive/Send) commands to a storage device —
// the carrier for TCG Opal IF-RECV/IF-SEND.
var EFI_STORAGE_SECURITY_COMMAND_PROTOCOL_GUID = MustParseGUID("c88b0b6d-0dfc-49a7-9cb4-49074b4c3a78")

// EFI_STORAGE_SECURITY_COMMAND_PROTOCOL member offsets
const (
	receiveData = 0x00
	sendData    = 0x08
)

// StorageSecurity is a located EFI_STORAGE_SECURITY_COMMAND_PROTOCOL instance.
type StorageSecurity struct {
	base uint64 // protocol structure address (the This pointer)
	recv uint64 // address of the ReceiveData member slot
	send uint64 // address of the SendData member slot
}

// GetStorageSecurity locates the first EFI_STORAGE_SECURITY_COMMAND_PROTOCOL
// instance and resolves its ReceiveData/SendData entry points.
//
// Like every service dispatch, recv/send hold the address of the member slot —
// not the function pointer stored in it — because callFn performs the
// dereference (memory-indirect CALL). The decode below only validates that the
// slots hold non-NULL pointers, failing closed on a corrupt protocol instance.
func (s *BootServices) GetStorageSecurity() (ssc *StorageSecurity, err error) {
	base, err := s.LocateProtocol(EFI_STORAGE_SECURITY_COMMAND_PROTOCOL_GUID)
	if err != nil {
		return nil, err
	}

	var fn struct {
		ReceiveData uint64
		SendData    uint64
	}
	if err = decode(&fn, base); err != nil {
		return nil, err
	}
	if fn.ReceiveData == 0 || fn.SendData == 0 {
		return nil, errors.New("storage security: NULL ReceiveData/SendData pointer")
	}

	return &StorageSecurity{base: base, recv: base + receiveData, send: base + sendData}, nil
}

// SendData calls EFI_STORAGE_SECURITY_COMMAND_PROTOCOL.SendData() (SECURITY
// PROTOCOL OUT) with the given security protocol ID and SP-specific value (the TCG
// ComID for Opal). timeout is in 100 ns units (0 = no timeout).
func (p *StorageSecurity) SendData(mediaID uint32, timeout uint64, securityProtocol uint8, spSpecific uint16, payload []byte) error {
	var ptr uint64
	if len(payload) > 0 {
		ptr = ptrval(&payload[0])
	}
	status := callService(p.send, []uint64{
		p.base,
		uint64(mediaID),
		timeout,
		uint64(securityProtocol),
		uint64(spSpecific),
		uint64(len(payload)),
		ptr,
	})
	return parseStatus(status)
}

// ReceiveData calls EFI_STORAGE_SECURITY_COMMAND_PROTOCOL.ReceiveData() (SECURITY
// PROTOCOL IN), returning the valid prefix of the transfer (PayloadTransferSize).
func (p *StorageSecurity) ReceiveData(mediaID uint32, timeout uint64, securityProtocol uint8, spSpecific uint16, size int) ([]byte, error) {
	buf := make([]byte, size)
	var xfer uintptr
	var ptr uint64
	if size > 0 {
		ptr = ptrval(&buf[0])
	}
	status := callService(p.recv, []uint64{
		p.base,
		uint64(mediaID),
		timeout,
		uint64(securityProtocol),
		uint64(spSpecific),
		uint64(size),
		ptr,
		ptrval(&xfer),
	})
	if err := parseStatus(status); err != nil {
		return nil, err
	}
	if int(xfer) > size {
		return nil, ErrTruncated
	}
	return buf[:xfer], nil
}
