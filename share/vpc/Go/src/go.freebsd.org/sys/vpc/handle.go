// Go interface for VPC Handles.
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

package vpc

import "github.com/pkg/errors"

// Handle is the descriptor associated with an opened VPC Object.
type Handle int

const (
	// ErrorHandle is the value returned when an error occurss during a call to
	// Open.
	ErrorHandle Handle = -1

	// ClosedHandle is the value used to indicate a Handle has been closed.
	ClosedHandle Handle = -2

	errVersion HandleType = 0x1
)

// HandleVersion is the version number of the VPC API and controls the ABI used
// to talk with a VPC Handle.
type HandleVersion uint64

// HandleTypeInput is passed to the constructor NewHandleType
type HandleTypeInput struct {
	Version HandleVersion
	Type    ObjType
}

// HandleType is the Object Type.  In sys/amd64/vmm/net/vmmnet.c this is
// defined as:
//
//    typedef struct {
//      uint64_t vht_version:4;
//      uint64_t vht_pad1:4;
//      uint64_t vht_obj_type:8;
//      uint64_t vht_pad2:48;
//    } vpc_handle_type_t;
type HandleType uint64

// NewHandleType constructs a new HandleType
func NewHandleType(cfg HandleTypeInput) (ht HandleType, err error) {
	if ht, err = ht.SetVersion(cfg.Version); err != nil {
		return errVersion, err
	}

	if ht, err = ht.SetObjType(cfg.Type); err != nil {
		return errVersion, err
	}

	return ht, err
}

const (
	objTypeMask HandleType = 0x00ff000000000000
	versionMask HandleType = 0xf000000000000000
)

// Version returns the HandleVersion being opened
func (t HandleType) Version() HandleVersion {
	return HandleVersion(t >> (64 - 4))
}

// SetVersion returns a new HandleType with the version encoded in the result.
func (t HandleType) SetVersion(ver HandleVersion) (HandleType, error) {
	switch {
	case ver > ((2 << 4) - 1):
		return errVersion, errors.New("API version too large")
	}

	// clear version
	tu := uint64(t)
	tu = tu &^ uint64(versionMask)

	// set version
	uVer := uint64(ver)
	uVer = uVer << (64 - 4)
	return HandleType(tu | uVer), nil
}

// ObjType returns the ObjType from a given HandleType
func (t HandleType) ObjType() ObjType {
	t &= objTypeMask
	t = t >> (64 - 8 - 8)
	return ObjType(t)
}

// SetObjType encodes the ObjType into a copy of the HandleType receiver and
// returns a new HandleType with the ObjType encoded.
func (t HandleType) SetObjType(objType ObjType) (HandleType, error) {
	// clear version
	tu := uint64(t)
	tu = tu &^ uint64(objTypeMask)

	// set ObjType
	uVer := uint64(objType)
	uVer = uVer << (64 - 8 - 8)
	return HandleType(tu | uVer), nil
}
