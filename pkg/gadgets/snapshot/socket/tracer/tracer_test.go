// Copyright 2022-2023 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build linux
// +build linux

package tracer

import (
	"fmt"
	"net"
	"reflect"
	"testing"

	utilstest "github.com/inspektor-gadget/inspektor-gadget/internal/test"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/snapshot/socket/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

func TestSocketTracerCreate(t *testing.T) {
	t.Parallel()

	utilstest.RequireRoot(t)

	tracer, err := NewTracer(types.ALL)
	if err != nil {
		t.Fatalf("creating tracer: %v", err)
	}

	tracer.CloseIters()
}

func TestSocketTCPv4(t *testing.T) {
	t.Parallel()

	utilstest.RequireRoot(t)

	tracer, err := NewTracer(types.TCP)
	if err != nil {
		t.Fatalf("creating tracer: %v", err)
	}
	defer tracer.CloseIters()

	addr := "127.0.0.1"
	port := uint16(8082)
	conn, err := net.Listen("tcp", fmt.Sprintf("%s:%d", addr, port))
	if err != nil {
		t.Fatalf("listening to %s: %v", addr, err)
	}
	defer conn.Close()

	events, err := tracer.RunCollector(1, "", "", "")
	if err != nil {
		t.Fatalf("running collector: %v", err)
	}

	expectedEvent := types.Event{
		Event:    eventtypes.Event{Type: eventtypes.NORMAL},
		Protocol: "TCP",
		Status:   "LISTEN",
		SrcEndpoint: eventtypes.L4Endpoint{
			L3Endpoint: eventtypes.L3Endpoint{
				Addr: addr,
			},
			Port: port,
		},
	}

	for _, event := range events {
		// Normalize few fields before comparing:
		// 1. There is no connection in this test, so there is no remote address.
		// 2. This is hard to guess the inode number, let's normalize it for the
		// moment.
		// 3. We do not want to get the net namespace ID associated to PID 1, so
		// let's normalize it too.
		event.DstEndpoint.Addr = ""
		event.InodeNumber = 0
		event.NetNsID = 0

		if reflect.DeepEqual(*event, expectedEvent) {
			return
		}
	}

	t.Fatalf("no socket found wich corresponds to %v", expectedEvent)
}

func TestSocketUDPv4(t *testing.T) {
	t.Parallel()

	utilstest.RequireRoot(t)

	tracer, err := NewTracer(types.UDP)
	if err != nil {
		t.Fatalf("creating tracer: %v", err)
	}
	defer tracer.CloseIters()

	addr := "127.0.0.1"
	port := 8082
	udpAddr := &net.UDPAddr{
		Port: port,
		IP:   net.ParseIP(addr),
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		t.Fatalf("listening to %s: %v", addr, err)
	}
	defer conn.Close()

	events, err := tracer.RunCollector(1, "", "", "")
	if err != nil {
		t.Fatalf("running collector: %v", err)
	}

	expectedEvent := types.Event{
		Event:    eventtypes.Event{Type: eventtypes.NORMAL},
		Protocol: "UDP",
		Status:   "INACTIVE",
		SrcEndpoint: eventtypes.L4Endpoint{
			L3Endpoint: eventtypes.L3Endpoint{
				Addr: addr,
			},
			Port: uint16(port),
		},
	}

	for _, event := range events {
		// Normalize few fields before comparing:
		// 1. There is no connection in this test, so there is no remote address.
		// 2. This is hard to guess the inode number, let's normalize it for the
		// moment.
		// 3. We do not want to get the net namespace ID associated to PID 1, so
		// let's normalize it too.
		event.DstEndpoint.Addr = ""
		event.InodeNumber = 0
		event.NetNsID = 0

		if reflect.DeepEqual(*event, expectedEvent) {
			return
		}
	}

	t.Fatalf("no socket found wich corresponds to %v", expectedEvent)
}
