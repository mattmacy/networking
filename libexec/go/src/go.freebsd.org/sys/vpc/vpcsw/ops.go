// Go interface to VPC Switch objects.
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

package vpcsw

import (
	"github.com/pkg/errors"
	"go.freebsd.org/sys/vpc"
)

/*
 * Cmd
 *   Direction
 *   ObjType
 *   Op
 *
 * InArg
 *   []byte
 * OutArg
 *   *[]byte
 */

// _SwitchCmd is the encoded type of operations that can be performed on a VPC
// Switch.
type _SwitchCmd vpc.Cmd

// _SwitchCmdSetArgType is the value used by a VPC Switch Set operation.
type _SwitchSetOpArgType uint64

const (
	// Bits for input
	_DownBit _SwitchSetOpArgType = 0x00000000
	_UpBit   _SwitchSetOpArgType = 0x00000001
)

// Ops that can be encoded into a vpc.Cmd
const (
	_OpInvalid       = vpc.Op(0)
	_OpPortAdd       = vpc.Op(1)
	_OpPortDel       = vpc.Op(2)
	_OpPortUplinkSet = vpc.Op(3)
	_OpPortUplinkGet = vpc.Op(4)
	_OpStateGet      = vpc.Op(5)
	_OpStateSet      = vpc.Op(6)
	_OpReset         = vpc.Op(7)
)

// Template commands that can be passed to vpc.Ctl() with a valid VPC Switch
// Handle.
var (
	_PortAddCmd    _SwitchCmd
	_PortDelCmd    _SwitchCmd
	_PortUplinkSet _SwitchCmd
	_PortUplinkGet _SwitchCmd
	_PortStateSet  _SwitchCmd
	_PortStateGet  _SwitchCmd
	_ResetCmd      _SwitchCmd
)

func init() {
	// {
	// 	createOp := vpc.MutateBit | vpc.InBit
	// 	_CreateOp = _SwitchOp(createOp)
	// }

	// {
	// 	resetCmd := vpc.MutateBit | _ResetCmd
	// 	_ResetCmd = _SwitchCmd(resetCmd)
	// }
}

// Reset resets the VPC Switch.
func (sw *VPCSW) Reset() error {
	if vpc.HandleFD(sw.h.FD()) <= 0 {
		return nil
	}

	// TODO(seanc@): Test to see make sure the descriptor has the mutate bit set.

	if err := vpc.Ctl(sw.h, vpc.Cmd(_ResetCmd), nil, nil); err != nil {
		return errors.Wrap(err, "unable to reset VPC Switch")
	}

	return nil
}
