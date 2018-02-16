// Tests for VPC OpFlags
//
// SPDX-License-Identifier: BSD-2-Clause-FreeBSD
//
// Copyright (C) 2018 Sean Chittenden <seanc@joyent.com>
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

package vpc_test

import (
	"testing"

	"go.freebsd.org/sys/vpc"
)

func TestOpFlagType(t *testing.T) {
	tests := []struct {
		op        vpc.OpFlag
		inBit     bool
		outBit    bool
		mutateBit bool
		objType   vpc.ObjType
	}{
		{
			op:        0x00000000,
			outBit:    false,
			inBit:     false,
			mutateBit: false,
			objType:   0x00000000,
		},
		{
			op:        0xffffffff,
			outBit:    true,
			inBit:     true,
			mutateBit: true,
			objType:   0x000000ff,
		},
		{
			op:        0x20010000,
			outBit:    false,
			inBit:     false,
			mutateBit: true,
			objType:   0x00000001,
		},
		{
			op:        0x40200000,
			outBit:    true,
			inBit:     false,
			mutateBit: false,
			objType:   0x00000020,
		},
		{
			op:        0x80ff0000,
			outBit:    false,
			inBit:     true,
			mutateBit: false,
			objType:   0x000000ff,
		},
	}

	for i, test := range tests {
		if test.op.Mutate() != test.mutateBit {
			t.Errorf("[%d] Mutate wrong", i)
		}

		if test.op.Out() != test.outBit {
			t.Errorf("[%d] Out wrong", i)
		}

		if test.op.In() != test.inBit {
			t.Errorf("[%d] In wrong", i)
		}

		if test.op.ObjType() != test.objType {
			t.Errorf("[%d] ObjType wrong: 0x%04x 0x%04x", i, test.op.ObjType(), test.objType)
		}
	}
}
