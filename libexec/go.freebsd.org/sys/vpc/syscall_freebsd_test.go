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

package vpc_test

import (
	"testing"

	"github.com/rs/zerolog/log"
	"go.freebsd.org/sys/vpc"
)

func TestVPCOpenClose(t *testing.T) {
	h1ID := vpc.GenID()

	ht, err := vpc.NewHandleType(vpc.HandleTypeInput{
		Version: 1,
		Type:    vpc.ObjTypeSwitch,
	})
	if err != nil {
		t.Fatalf("unable to construct a HandleType: %v", err)
	}

	log.Debug().Msg("creating vpcsw0")
	vpcsw0CreateFD, err := vpc.Open(h1ID, ht, vpc.FlagCreate)
	if err != nil {
		t.Fatalf("vpc_open(2) failed: %v", err)
	}

	if vpcsw0CreateFD == 0 {
		t.Errorf("vpc_open(2) return an FD of 0")
	}

	log.Debug().Msg("opening vpcsw0")
	vpcsw0OpenFD, err := vpc.Open(h1ID, ht, vpc.FlagOpen)
	if err != nil {
		t.Fatalf("vpc_open(2) failed: %v", err)
	}
	defer func() {
		if err := vpcsw0OpenFD.Close(); err != nil {
			t.Fatalf("unable to close(2) VPC Handle : %v", err)
		}
	}()

	if vpcsw0OpenFD == vpcsw0CreateFD {
		t.Errorf("vpc_open(2) open and create FDs are identical")
	}

	h2ID := vpc.GenID()

	log.Debug().Msg("creating vpcsw1")
	vpcsw1CreateFD, err := vpc.Open(h2ID, ht, vpc.FlagCreate)
	if err != nil {
		t.Fatalf("vpc_open(2) failed: %v", err)
	}
	defer func() {
		if err := vpcsw1CreateFD.Close(); err != nil {
			t.Fatalf("unable to close(2) vpcsw1CreateFD VPC Handle : %v", err)
		}
	}()

	log.Debug().Int("vpcsw0CreateFD", int(vpcsw0CreateFD)).Msg("closing vpcsw0 create")
	if err := vpcsw0CreateFD.Close(); err != nil {
		t.Fatalf("unable to close(2) VPC Handle : %v", err)
	}
	if vpcsw0CreateFD != vpc.ClosedHandle {
		t.Fatalf("handle set to wrong value in vpc.Close()")
	}

	if err := vpcsw0CreateFD.Close(); err != nil {
		t.Fatalf("unable to close(2) VPC Handle : %v", err)
	}

	// TODO(seanc@): programmatically verify that vpcsw0 is still present
	//time.Sleep(30 * time.Second)

	log.Debug().Msg("closing vpcsw0 open")
	if err := vpcsw0OpenFD.Close(); err != nil {
		t.Fatalf("unable to close(2) VPC Handle : %v", err)
	}

	// TODO(seanc@): programmatically verify that vpcsw0 disappeared after the
	// openfd was closed
	//time.Sleep(30 * time.Second)

	log.Debug().Msg("closing vpcsw1 open")
	if err := vpcsw1CreateFD.Close(); err != nil {
		t.Fatalf("unable to close(2) VPC Handle : %v", err)
	}

	// TODO(seanc@): programmatically verify that vpcsw1 disappeared
	//time.Sleep(30 * time.Second)
}
