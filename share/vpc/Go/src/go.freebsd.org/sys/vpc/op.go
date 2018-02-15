// Go interface to VPC Operations
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

// OpFlag is the Operation being performed.  An OpFlag encodes:
//
// 1. The direction of the arguments (in or out)
// 2. The object type
// 3. The per-type operation
type OpFlag uint32

// Constants used to test or extract information from an OpFlag.
const (
	// Constants taken from: sys/sys/ioccom.h and sys/net/if_vpc.h

	MutateBit OpFlag = 0x20000000
	OutBit    OpFlag = 0x40000000
	InBit     OpFlag = 0x80000000

	OpMask      OpFlag = 0xFFFF0000
	ObjTypeMask OpFlag = 0xFF00FFFF
)

// In returns true if the OpFlag requires input when passed to vpc.Ctl()
func (op OpFlag) In() bool {
	return op&InBit != 0
}

// Out returns true if the OpFlag requires an output argument when passed to
// vpc.Ctl().
func (op OpFlag) Out() bool {
	return op&OutBit != 0
}

// Mutate returns true if the OpFlag indicates that the behavior of the Op will
// change the state of the world.
func (op OpFlag) Mutate() bool {
	return op&MutateBit != 0
}

// ObjType returns the encoded ObjType in the OpFlag.
func (op OpFlag) ObjType() ObjType {
	return ObjType((op &^ ObjTypeMask) >> 16)
}
