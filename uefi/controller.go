// Copyright (c) The go-boot authors. All Rights Reserved.
//
// Use of this source code is governed by the license
// that can be found in the LICENSE file.

package uefi

// EFI Boot Services offsets for driver/controller connection.
const (
	connectController    = 0x108
	disconnectController = 0x110
)

// ConnectController calls EFI_BOOT_SERVICES.ConnectController() (UEFI 2.10
// §7.3.12), binding drivers to a controller handle. driverImageHandle (a
// NULL-terminated handle array) and remainingDevicePath may be 0; recursive
// connects the controller and the device subtree it produces. Re-running it after
// DisconnectController makes the managing bus driver re-initialise the controller.
func (s *BootServices) ConnectController(controllerHandle, driverImageHandle, remainingDevicePath uint64, recursive bool) error {
	var rec uint64
	if recursive {
		rec = 1
	}
	status := callService(s.base+connectController, []uint64{
		controllerHandle,
		driverImageHandle,
		remainingDevicePath,
		rec,
	})
	return parseStatus(status)
}

// DisconnectController calls EFI_BOOT_SERVICES.DisconnectController() (UEFI 2.10
// §7.3.13), unbinding drivers from a controller handle. A zero driverImageHandle
// disconnects all managing drivers; a zero childHandle destroys all child handles.
func (s *BootServices) DisconnectController(controllerHandle, driverImageHandle, childHandle uint64) error {
	status := callService(s.base+disconnectController, []uint64{
		controllerHandle,
		driverImageHandle,
		childHandle,
	})
	return parseStatus(status)
}
