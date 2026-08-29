// Copyright (c) The go-boot authors. All Rights Reserved.
//
// Use of this source code is governed by the license
// that can be found in the LICENSE file.

package uefi

import (
	"encoding/binary"
	"errors"
)

// EFI_TCG2_PROTOCOL_GUID identifies the TCG2 protocol, which extends measurements
// into the platform TPM 2.0 PCRs and appends them to the firmware TCG event log.
var EFI_TCG2_PROTOCOL_GUID = MustParseGUID("607f766c-7455-42be-930b-e4d76db2720f")

// EFI_TCG2_PROTOCOL member offset (x64, one machine word each): HashLogExtendEvent
// is the third member (after GetCapability at 0x00 and GetEventLog at 0x08).
const tcg2HashLogExtendEvent = 0x10

// EFI_TCG2_EVENT header sizes (the structure is packed, per the TCG EFI Protocol
// specification): a UINT32 Size, then EFI_TCG2_EVENT_HEADER { UINT32 HeaderSize;
// UINT16 HeaderVersion; UINT32 PCRIndex; UINT32 EventType } = 14 bytes, then the
// event body.
const (
	tcg2EventHeaderSize = 14
	tcg2EventPrefixSize = 4 + tcg2EventHeaderSize // Size field + header
)

// TCG2 is a located EFI_TCG2_PROTOCOL instance.
type TCG2 struct {
	base   uint64 // protocol interface address (the This pointer)
	extend uint64 // address of the HashLogExtendEvent member slot
}

// GetTCG2 locates the EFI_TCG2_PROTOCOL. It returns an error if the platform
// exposes no TPM 2.0 measurement protocol (no measured boot available).
func (s *BootServices) GetTCG2() (*TCG2, error) {
	base, err := s.LocateProtocol(EFI_TCG2_PROTOCOL_GUID)
	if err != nil {
		return nil, err
	}
	var fn struct {
		GetCapability      uint64
		GetEventLog        uint64
		HashLogExtendEvent uint64
	}
	if err := decode(&fn, base); err != nil {
		return nil, err
	}
	if fn.HashLogExtendEvent == 0 {
		return nil, errors.New("tcg2: NULL HashLogExtendEvent pointer")
	}
	return &TCG2{base: base, extend: base + tcg2HashLogExtendEvent}, nil
}

// HashLogExtendEvent hashes data, extends the digest into PCR pcrIndex across every
// active bank, and appends an event of eventType (carrying data as its body) to the
// TCG event log. flags is 0 for a normal measured-and-logged event. Convenience form
// where the hashed data and the logged event body are identical.
func (p *TCG2) HashLogExtendEvent(flags uint64, pcrIndex uint32, eventType uint32, data []byte) error {
	return p.HashLogExtendEventEx(flags, pcrIndex, eventType, data, data)
}

// HashLogExtendEventEx is HashLogExtendEvent with the hashed data (dataToHash) and the
// logged event body separated — required for a PE/COFF image measurement, where the
// firmware hashes the image (with EFI_TCG2_PE_COFF_IMAGE) but the log carries a
// UEFI_IMAGE_LOAD_EVENT body instead of the image bytes.
func (p *TCG2) HashLogExtendEventEx(flags uint64, pcrIndex uint32, eventType uint32, dataToHash []byte, eventBody []byte) error {
	ev := make([]byte, tcg2EventPrefixSize+len(eventBody))
	binary.LittleEndian.PutUint32(ev[0:], uint32(len(ev)))     // EFI_TCG2_EVENT.Size
	binary.LittleEndian.PutUint32(ev[4:], tcg2EventHeaderSize) // Header.HeaderSize
	binary.LittleEndian.PutUint16(ev[8:], 1)                   // Header.HeaderVersion
	binary.LittleEndian.PutUint32(ev[10:], pcrIndex)           // Header.PCRIndex
	binary.LittleEndian.PutUint32(ev[14:], eventType)          // Header.EventType
	copy(ev[tcg2EventPrefixSize:], eventBody)                  // Event[]

	var dptr uint64
	if len(dataToHash) > 0 {
		dptr = ptrval(&dataToHash[0])
	}
	status := callService(p.extend, []uint64{
		p.base,
		flags,
		dptr,
		uint64(len(dataToHash)),
		ptrval(&ev[0]),
	})
	return parseStatus(status)
}
