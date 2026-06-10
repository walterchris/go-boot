// Copyright (c) The go-boot authors. All Rights Reserved.
//
// Use of this source code is governed by the license
// that can be found in the LICENSE file.

package uefi

import (
	"errors"
)

// LoadImageBuffer calls EFI_BOOT_SERVICES.LoadImage() with a caller-supplied
// SourceBuffer, instead of re-reading the named file as LoadImage() does. This
// lets a caller verify an image and then hand the firmware those exact bytes,
// guaranteeing that the bytes verified are the bytes executed (no
// verify-then-load window).
//
// The EFI Device Path passed to the firmware is built from root and name
// exactly as in LoadImage(), so the loaded image still receives its device
// handle and file path context; name must identify the file buf was read
// from. BootPolicy is FALSE (the firmware ignores it when SourceBuffer is
// non-NULL).
//
// The returned image handle can be passed to StartImage().
func (s *BootServices) LoadImageBuffer(root *FS, name string, buf []byte) (imageHandle uint64, err error) {
	if len(buf) == 0 {
		return 0, errors.New("load image: empty source buffer")
	}

	_, _, devicePath, err := root.FilePath(name)

	if err != nil {
		return
	}

	status := callService(s.base+loadImage,
		[]uint64{
			0, // BootPolicy = FALSE
			s.imageHandle,
			ptrval(&devicePath[0]),
			ptrval(&buf[0]),
			uint64(len(buf)),
			ptrval(&imageHandle),
		},
	)

	return imageHandle, parseStatus(status)
}
