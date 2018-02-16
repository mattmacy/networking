// Go interface to OS-independent VPC syscalls.
//
// SPDX-License-Identifier: BSD-2-Clause-FreeBSD
//
// Copyright (C) 2018 Sean Chittenden <seanc@joyent.com>
// Copyright (c) 2018 Joyent, Inc.
// All rights reserved.
//
// This software was developed by Sean Chittenden <seanc@FreeBSD.org> at Joyent,
// Inc.
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
	"crypto/rand"
	"encoding/binary"
	"syscall"

	"github.com/pkg/errors"
)

// VNI is the type for VXLAN Network Identifiers ("VNI")
type VNI int32

const (
	// VNIMax is the largest permitted VNI
	VNIMax VNI = (1 << 24) - 1

	// VNIMin is the smallest permitted VNI.  NOTE: a VNI of 0 implies
	// un-encapsulated frames.
	VNIMin VNI = 0
)

// ID is the globally unique identifier for a VPC object.
type ID struct {
	TimeLow     uint32
	TimeMid     uint16
	TimeHi      uint16
	ClockSeqHi  uint8
	ClockSeqLow uint8
	Node        [6]uint8
}

// GenID randomly generates a new UUID
func GenID() ID {
	randUint8 := func() uint8 {
		var b [1]byte
		if _, err := rand.Read(b[:]); err != nil {
			panic("bad")
		}
		return uint8(b[0])
	}

	randUint16 := func() uint16 {
		var b [2]byte
		if _, err := rand.Read(b[:]); err != nil {
			panic("bad")
		}
		return uint16(binary.LittleEndian.Uint16(b[:]))
	}

	randUint32 := func() uint32 {
		var b [4]byte
		if _, err := rand.Read(b[:]); err != nil {
			panic("bad")
		}
		return uint32(binary.LittleEndian.Uint32(b[:]))
	}

	randNode := func() [6]byte {
		var b [6]byte
		if _, err := rand.Read(b[:]); err != nil {
			panic("bad")
		}
		return b
	}

	// FIXME(seanc@): I took the bruteforce way of populating a struct with random
	// data vs just populating a [16]byte slice w/ random data and casting it to
	// an ID because I didn't want to fight with the language, but this should be
	// done better and differently.
	return ID{
		TimeLow:     randUint32(),
		TimeMid:     randUint16(),
		TimeHi:      randUint16(),
		ClockSeqHi:  randUint8(),
		ClockSeqLow: randUint8(),
		Node:        randNode(),
	}
}

// OpenFlags is the flags passed to Open
type OpenFlags uint64

const (
	// FlagCreate is used to signal that a given ID should be created on Open.
	FlagCreate OpenFlags = 1 << iota

	// FlagOpen is used to signal that a given ID must already exist in order to
	// be successfully opened.
	FlagOpen
)

// ObjType distinguishes the different types of supported VPC Object Types.
type ObjType uint8

// Exported enumerated types of available VPC objects.
const (
	ObjTypeInvalid    ObjType = 0
	ObjTypeSwitch     ObjType = 1
	ObjTypeSwitchPort ObjType = 2
	ObjTypeRouter     ObjType = 3
	ObjTypeNAT        ObjType = 4
	ObjTypeLinkVPC    ObjType = 5
	ObjTypeNIC        ObjType = 6
	ObjTypeMgmt       ObjType = 7
	ObjTypeLinkL2     ObjType = 8
)

// Close closes a VPC Handle.  Closing a VPC Handle does not destroy any
// resources.
func (h *Handle) Close() error {
	// TODO(seanc@): verify that we don't need to wrap this close in a loop
	if err := syscall.Close(int(*h)); err != nil {
		return errors.Wrap(err, "unable to close VPC handle")
	}

	*h = ClosedHandle

	return nil
}
