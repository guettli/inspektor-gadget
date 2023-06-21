// Copyright 2021-2023 The Inspektor Gadget authors
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

//go:build !withoutebpf

package tracer

import (
	"bufio"
	"fmt"
	"unsafe"

	"github.com/cilium/ebpf/link"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	containerutils "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	socketcollectortypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/snapshot/socket/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/netnsenter"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang iterTCP ./bpf/tcp-collector.c -- -I../../../../${TARGET} -Werror -O2 -g -c -x c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang iterUDP ./bpf/udp-collector.c -- -I../../../../${TARGET} -Werror -O2 -g -c -x c

type Tracer struct {
	iters map[socketcollectortypes.Proto]*link.Iter

	// visitedNamespaces is a map where the key is the netns inode number and
	// the value is the pid of one of the containers that share that netns. Such
	// pid is used by NetnsEnter. TODO: Improve NetnsEnter to also work with the
	// netns directly.
	visitedNamespaces map[uint64]uint32
	protocols         socketcollectortypes.Proto
	eventHandler      func([]*socketcollectortypes.Event)
}

// Format from socket_bpf_seq_print() in bpf/socket_common.h
func parseStatus(proto string, statusUint uint8) (string, error) {
	statusMap := [...]string{
		"ESTABLISHED", "SYN_SENT", "SYN_RECV",
		"FIN_WAIT1", "FIN_WAIT2", "TIME_WAIT", "CLOSE", "CLOSE_WAIT",
		"LAST_ACK", "LISTEN", "CLOSING", "NEW_SYN_RECV",
	}

	// Kernel enum starts from 1, adjust it to the statusMap
	if statusUint == 0 || len(statusMap) <= int(statusUint-1) {
		return "", fmt.Errorf("invalid %s status: %d", proto, statusUint)
	}
	status := statusMap[statusUint-1]

	// Transform TCP status into something more suitable for UDP
	if proto == "UDP" {
		switch status {
		case "ESTABLISHED":
			status = "ACTIVE"
		case "CLOSE":
			status = "INACTIVE"
		default:
			return "", fmt.Errorf("unexpected %s status %s", proto, status)
		}
	}

	return status, nil
}

func getTCPIter() (*link.Iter, error) {
	objs := iterTCPObjects{}
	if err := loadIterTCPObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("loading TCP BPF objects: %w", err)
	}
	defer objs.Close()

	it, err := link.AttachIter(link.IterOptions{
		Program: objs.IgSnapTcp,
	})
	if err != nil {
		return nil, fmt.Errorf("attaching TCP BPF iterator: %w", err)
	}

	return it, nil
}

func getUDPIter() (*link.Iter, error) {
	objs := iterUDPObjects{}
	if err := loadIterUDPObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("loading UDP BPF objects: %w", err)
	}
	defer objs.Close()

	it, err := link.AttachIter(link.IterOptions{
		Program: objs.IgSnapUdp,
	})
	if err != nil {
		return nil, fmt.Errorf("attaching UDP BPF iterator: %w", err)
	}

	return it, nil
}

// RunCollector is currently exported so it can be called from Collect()
func (t *Tracer) RunCollector(pid uint32, podname, namespace, node string) ([]*socketcollectortypes.Event, error) {
	sockets := []*socketcollectortypes.Event{}
	err := netnsenter.NetnsEnter(int(pid), func() error {
		for iterKey, it := range t.iters {
			if t.protocols != socketcollectortypes.ALL && t.protocols != iterKey {
				continue
			}

			reader, err := it.Open()
			if err != nil {
				return fmt.Errorf("opening BPF iterator: %w", err)
			}
			defer reader.Close()

			scanner := bufio.NewScanner(reader)
			for scanner.Scan() {
				var status, proto string
				var destp, srcp, fam uint16
				dest := make([]byte, 16, 16)
				src := make([]byte, 16, 16)
				var hexStatus uint8
				var inodeNumber uint64

				line := scanner.Text()

				matched, err := fmt.Sscanf(line, "%s %04X", &proto, &fam)
				if err != nil {
					return fmt.Errorf("parsing sockets protocol and family: %w", err)
				}
				if matched != 2 {
					return fmt.Errorf("expecting to match 2 elements, matched: %d", matched)
				}

				family := gadgets.IPVerFromAF(fam)
				switch family {
				case 4:
					matched, err = fmt.Sscanf(line, "%s %04X %08X %04X %08X %04X %02X %d",
						&proto, &fam, &((*[4]uint32)(unsafe.Pointer(&src[0])))[0], &srcp, &((*[4]uint32)(unsafe.Pointer(&dest[0])))[0], &destp, &hexStatus, &inodeNumber)

					if matched != 8 {
						return fmt.Errorf("expecting to match 8 elements, matched: %d", matched)
					}
				case 6:
					var srcIPv6, destIPv6 string

					matched, err = fmt.Sscanf(line, "%s %04X %s %04X %s %04X %02X %d",
						&proto, &fam, &srcIPv6, &srcp, &destIPv6, &destp, &hexStatus, &inodeNumber)
					if matched != 8 {
						return fmt.Errorf("expecting to match 8 elements, matched: %d", matched)
					}

					s, err := gadgets.IPStringToByteArray(srcIPv6)
					if err != nil {
						return fmt.Errorf("parsing source IPv6 address: %w", err)
					}
					src = s[:]

					d, err := gadgets.IPStringToByteArray(destIPv6)
					if err != nil {
						return fmt.Errorf("parsing destination IPv6 address: %w", err)
					}
					dest = d[:]
				default:
					return fmt.Errorf("expecting IP version 4 or 6, got: %d", family)
				}

				if err != nil {
					return fmt.Errorf("parsing sockets information: %w", err)
				}

				status, err = parseStatus(proto, hexStatus)
				if err != nil {
					return err
				}

				// TODO: Receive the netns from caller
				netns, err := containerutils.GetNetNs(int(pid))
				if err != nil {
					return fmt.Errorf("getting netns for pid %d: %w", pid, err)
				}

				sockets = append(sockets, &socketcollectortypes.Event{
					Event: eventtypes.Event{
						Type: eventtypes.NORMAL,
						// TODO: This can be removed as events will be enriched
						//  by the eventHandler
						CommonData: eventtypes.CommonData{
							Node:      node,
							Namespace: namespace,
							Pod:       podname,
						},
					},
					Protocol: proto,
					SrcEndpoint: eventtypes.L4Endpoint{
						L3Endpoint: eventtypes.L3Endpoint{
							Addr: gadgets.IPStringFromBytes(*(*[16]byte)(src), family),
						},
						Port: srcp,
					},
					DstEndpoint: eventtypes.L4Endpoint{
						L3Endpoint: eventtypes.L3Endpoint{
							Addr: gadgets.IPStringFromBytes(*(*[16]byte)(dest), family),
						},
						Port: destp,
					},
					Status:      status,
					InodeNumber: inodeNumber,
					WithNetNsID: eventtypes.WithNetNsID{NetNsID: netns},
				})
			}

			if err := scanner.Err(); err != nil {
				return fmt.Errorf("reading output of BPF iterator: %w", err)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return sockets, nil
}

// ---

func NewTracer(protocols socketcollectortypes.Proto) (*Tracer, error) {
	tracer := &Tracer{
		visitedNamespaces: make(map[uint64]uint32),
		protocols:         protocols,
		iters:             make(map[socketcollectortypes.Proto]*link.Iter),
	}

	if err := tracer.openIters(); err != nil {
		tracer.CloseIters()
		return nil, fmt.Errorf("installing tracer: %w", err)
	}

	return tracer, nil
}

func (g *GadgetDesc) NewInstance() (gadgets.Gadget, error) {
	return &Tracer{
		visitedNamespaces: make(map[uint64]uint32),
		iters:             make(map[socketcollectortypes.Proto]*link.Iter),
	}, nil
}

func (t *Tracer) AttachContainer(container *containercollection.Container) error {
	if _, ok := t.visitedNamespaces[container.Netns]; ok {
		return nil
	}
	t.visitedNamespaces[container.Netns] = container.Pid
	return nil
}

func (t *Tracer) DetachContainer(container *containercollection.Container) error {
	return nil
}

func (t *Tracer) SetEventHandlerArray(handler any) {
	nh, ok := handler.(func(ev []*socketcollectortypes.Event))
	if !ok {
		panic("event handler invalid")
	}
	t.eventHandler = nh
}

// CloseIters is currently exported so it can be called from Collect()
func (t *Tracer) CloseIters() {
	for _, it := range t.iters {
		it.Close()
	}
	t.iters = nil
}

func (t *Tracer) openIters() error {
	var it *link.Iter
	var err error

	if t.protocols == socketcollectortypes.TCP || t.protocols == socketcollectortypes.ALL {
		it, err = getTCPIter()
		if err != nil {
			return err
		}
		t.iters[socketcollectortypes.TCP] = it
	}

	if t.protocols == socketcollectortypes.UDP || t.protocols == socketcollectortypes.ALL {
		it, err = getUDPIter()
		if err != nil {
			return err
		}
		t.iters[socketcollectortypes.UDP] = it
	}

	return nil
}

func (t *Tracer) Run(gadgetCtx gadgets.GadgetContext) error {
	protocols := gadgetCtx.GadgetParams().Get(ParamProto).AsString()
	t.protocols, _ = socketcollectortypes.ProtocolsMap[protocols]

	defer t.CloseIters()
	if err := t.openIters(); err != nil {
		return fmt.Errorf("installing tracer: %w", err)
	}

	allSockets := []*socketcollectortypes.Event{}
	for netns, pid := range t.visitedNamespaces {
		// TODO: Remove podname, namespace and node arguments from RunCollector.
		// The enrichment will be done in the event handler. In addition, pass
		// the netns to avoid retrieving it again in RunCollector.
		sockets, err := t.RunCollector(pid, "", "", "")
		if err != nil {
			return fmt.Errorf("snapshotting sockets in netns %d: %w", netns, err)
		}
		allSockets = append(allSockets, sockets...)
	}

	t.eventHandler(allSockets)
	return nil
}
