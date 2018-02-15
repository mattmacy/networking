// Go interface to VPC Switch objects.
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

package vpcsw

import (
	"github.com/pkg/errors"
	"go.freebsd.org/sys/vpc"
)

// Config is the configuration used to populate a given VPC Switch.
type Config struct {
	ID  vpc.ID
	VNI vpc.VNI
}

// VPCSW is an opaque struct representing a VPC Switch.
type VPCSW struct {
	h   vpc.Handle
	ht  vpc.HandleType
	vni vpc.VNI
}

// New creates a new VPC Switch using the Config parameters.  Callers are
// expected to Close a given VPCSW (otherwise a file descriptor would leak).
func New(cfg Config) (*VPCSW, error) {
	switch {
	case cfg.VNI < vpc.VNIMin:
		return nil, errors.Errorf("VNI %d too small", cfg.VNI)
	case cfg.VNI > vpc.VNIMax:
		return nil, errors.Errorf("VNI %d exceeds max value", cfg.VNI)
	}

	ht, err := vpc.NewHandleType(vpc.HandleTypeInput{
		Version: 1,
		Type:    vpc.ObjTypeSwitch,
	})
	if err != nil {
		return nil, errors.Wrap(err, "unable to create a new VPC Switch handle type")
	}

	h, err := vpc.Open(cfg.ID, ht, vpc.FlagCreate)
	if err != nil {
		return nil, errors.Wrap(err, "unable to open VPC Switch handle")
	}

	return &VPCSW{
		h:   h,
		ht:  ht,
		vni: cfg.VNI,
	}, nil
}

// Create actually creates a VPC Switch using the existing vpc.Handle.
func (sw *VPCSW) Create() error {
	// 1) open a vpc handle
	if err := vpc.Ctl(sw.h, vpc.OpFlag(_CreateOp), nil, nil); err != nil {
		return errors.Wrap(err, "unable to create VPC Switch")
	}

	// 2) issue a switch create
	return errors.New("not implemented")
}

// Close closes the VPC Handle descriptor.  Created VPC Switches will not be
// destroyed when the VPCSW is closed.
func (sw *VPCSW) Close() error {
	if sw.h <= 0 {
		return nil
	}

	if err := sw.h.Close(); err != nil {
		return errors.Wrap(err, "unable to close VPC handle")
	}

	return nil
}
