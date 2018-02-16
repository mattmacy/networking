// Go interface to VPC syscalls on FreeBSD.
//
// SPDX-License-Identifier: BSD-2-Clause-FreeBSD
//
// Copyright (c) 2018 Joyent, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
// ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
// OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
// LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
// OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
// SUCH DAMAGE.

package vpc

import (
	"syscall"
	"unsafe"

	"github.com/pkg/errors"
)

const (
	SYS_VPC_OPEN = 580
	SYS_VPC_CTL  = 581
)

// Open obtains a VPC handle to a given object type.  Obtaining an open Handle
// affords no privilges beyond validating that an ID exists on this system.  In
// all other cases Open returns a handle to a resource.  If the id can not be
// found, Open returns ENOENT unless the Create flag is set in flags.  If the
// Create flag is set and the id is found, Open returns EEXIST.  If an invalid
// Flag is set, Open returns EINVAL.  If the HandleType is out of bounds, Open
// returns EOPNOTSUPP.
func Open(id ID, ht HandleType, flags OpenFlags) (h Handle, err error) {
	// 580     AUE_VPC         NOSTD   { int vpc_open(const vpc_id_t *vpc_id, vpc_type_t obj_type, \
	//                                   vpc_flags_t flags); }
	r0, _, e1 := syscall.Syscall(SYS_VPC_OPEN, uintptr(unsafe.Pointer(&id)), uintptr(ht), uintptr(flags))
	h = Handle(r0)
	if e1 != 0 {
		return ErrorHandle, syscall.Errno(e1)
	}

	return h, nil
}

// Ctl manipulates the Handle based on the args
func Ctl(h Handle, op OpFlag, in []byte, out *[]byte) error {
	// // syscall 581:
	// 581     AUE_VPC         NOSTD   { int vpc_ctl(int vpcd, vpc_op_t op, size_t innbyte, \
	//                                     const void *in, size_t *outnbyte, void *out); }

	// Implementation sanity checking
	switch {
	case op.In() && len(in) == 0:
		return errors.New("operation requires non-zero length input")
	case op.Out() && out == nil:
		return errors.New("operation requires non-nil output")
	}

	return errors.New("not implemented")
}
