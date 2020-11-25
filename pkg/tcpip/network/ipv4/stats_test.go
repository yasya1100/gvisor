// Copyright 2020 The gVisor Authors.
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

package ipv4

import (
	"reflect"
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/network/testutil"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

const nicID = 1

var _ stack.NetworkInterface = (*testInterface)(nil)

type testInterface struct {
	stack.NetworkLinkEndpoint
}

func (*testInterface) ID() tcpip.NICID {
	return nicID
}

func (*testInterface) IsLoopback() bool {
	return false
}

func (*testInterface) Name() string {
	return ""
}

func (*testInterface) Enabled() bool {
	return true
}

func (*testInterface) Promiscuous() bool {
	return false
}

func (*testInterface) WritePacketToRemote(tcpip.LinkAddress, *stack.GSO, tcpip.NetworkProtocolNumber, *stack.PacketBuffer) *tcpip.Error {
	return tcpip.ErrNotSupported
}

func TestClearEndpointFromProtocolOnClose(t *testing.T) {
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{NewProtocol},
	})
	proto := s.NetworkProtocolInstance(ProtocolNumber).(*protocol)
	nic := testInterface{}
	ep := proto.NewEndpoint(&nic, nil, nil, nil).(*endpoint)
	{
		proto.mu.Lock()
		_, hasEP := proto.mu.eps[nic.ID()]
		proto.mu.Unlock()
		if !hasEP {
			t.Fatalf("expected protocol to have ep = %p in set of endpoints", ep)
		}
	}

	ep.Close()

	{
		proto.mu.Lock()
		_, hasEP := proto.mu.eps[nic.ID()]
		proto.mu.Unlock()
		if hasEP {
			t.Fatalf("unexpectedly found ep = %p in set of protocol's endpoints", ep)
		}
	}
}

func TestMultiCounterStatsInitialization(t *testing.T) {
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{NewProtocol},
	})
	proto := s.NetworkProtocolInstance(ProtocolNumber).(*protocol)
	nic := testInterface{}
	ep := proto.NewEndpoint(&nic, nil, nil, nil).(*endpoint)
	// At that point, the Stack's stats and the NetworkEndpoint's stats are
	// supposed to be bound.
	refStack := s.Stats()
	refEP := ep.stats.localStats
	multi := ep.stats.multiCounterStats
	if err := testutil.ValidateMultiCounterStats(reflect.ValueOf(&refStack.IP).Elem(), reflect.ValueOf(&refEP.IP).Elem(), reflect.ValueOf(&multi.ip).Elem()); err != nil {
		t.Error(err)
	}
	if err := testutil.ValidateMultiCounterStats(reflect.ValueOf(&refStack.ICMP.V4).Elem(), reflect.ValueOf(&refEP.ICMP).Elem(), reflect.ValueOf(&multi.icmp).Elem()); err != nil {
		t.Error(err)
	}
	if err := testutil.ValidateMultiCounterStats(reflect.ValueOf(&refStack.IGMP).Elem(), reflect.ValueOf(&refEP.IGMP).Elem(), reflect.ValueOf(&multi.igmp).Elem()); err != nil {
		t.Error(err)
	}
}
