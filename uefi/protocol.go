// Copyright (c) The go-boot authors. All Rights Reserved.
//
// Use of this source code is governed by the license
// that can be found in the LICENSE file.

package uefi

// EFI Boot Services offsets
const (
	handleProtocol     = 0x098
	locateHandleBuffer = 0x138
	locateProtocol     = 0x140
)

// EFI_LOCATE_SEARCH_TYPE values (UEFI 2.10 §7.3.15).
const (
	AllHandles = iota
	ByRegisterNotify
	ByProtocol
)

// HandleProtocol calls EFI_BOOT_SERVICES.HandleProtocol().
func (s *BootServices) HandleProtocol(handle uint64, guid GUID) (addr uint64, err error) {
	status := callService(s.base+handleProtocol,
		[]uint64{
			handle,
			ptrval(&guid[0]),
			ptrval(&addr),
		},
	)

	return addr, parseStatus(status)
}

// LocateProtocol calls EFI_BOOT_SERVICES.LocateProtocol().
func (s *BootServices) LocateProtocol(guid GUID) (addr uint64, err error) {
	status := callService(s.base+locateProtocol,
		[]uint64{
			ptrval(&guid[0]),
			0,
			ptrval(&addr),
		},
	)

	return addr, parseStatus(status)
}

// LocateHandleBuffer calls EFI_BOOT_SERVICES.LocateHandleBuffer() and returns the
// handles matching the search. For ByProtocol, guid selects the protocol (pass a
// zero GUID for AllHandles). Unlike LocateProtocol it yields the device handles
// themselves, so a caller can resolve several protocols on the same handle (e.g.
// Storage Security and Block I/O on one device). The firmware pool-allocates the
// result buffer; it is freed here, so the caller owns only the returned slice.
func (s *BootServices) LocateHandleBuffer(searchType uint64, guid GUID) (handles []uint64, err error) {
	var noHandles uint64
	var buffer uint64

	status := callService(s.base+locateHandleBuffer,
		[]uint64{
			searchType,
			ptrval(&guid[0]),
			0, // SearchKey (unused for AllHandles/ByProtocol)
			ptrval(&noHandles),
			ptrval(&buffer),
		},
	)
	if err = parseStatus(status); err != nil {
		return nil, err
	}
	if noHandles == 0 || buffer == 0 {
		return nil, nil
	}

	handles = make([]uint64, noHandles)
	if err = decode(handles, buffer); err != nil {
		return nil, err
	}

	// Release the firmware-allocated buffer; the decoded slice is our own copy.
	_ = s.FreePool(buffer)

	return handles, nil
}
