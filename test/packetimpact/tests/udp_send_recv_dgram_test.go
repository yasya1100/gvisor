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

package udp_send_recv_dgram_test

import (
	"context"
	"flag"
	"fmt"
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/test/packetimpact/testbench"
)

func init() {
	testbench.Initialize(flag.CommandLine)
}

type udpConn interface {
	Send(*testing.T, testbench.UDP, ...testbench.Layer)
	ExpectData(*testing.T, testbench.UDP, testbench.Payload, time.Duration) (testbench.Layers, error)
	Drain(*testing.T)
	Close(*testing.T)
}

func TestUDPSendUnicast(t *testing.T) {
	dut := testbench.NewDUT(t)
	subnetBcastAddr := broadcastAddr(dut.Net.RemoteIPv4, dut.Net.IPv4PrefixLength)

	for _, bound := range []net.IP{
		dut.Net.RemoteIPv4,
		net.IPv4zero.To4(),
		dut.Net.RemoteIPv6,
		net.IPv4bcast.To4(),
		subnetBcastAddr,
	} {
		t.Run(fmt.Sprintf("bound=%s", bound), func(t *testing.T) {
			for _, bindToDevice := range []bool{true, false} {
				t.Run(fmt.Sprintf("bindToDevice=%t", bound, bindToDevice), func(t *testing.T) {
					boundFD, remotePort := dut.CreateBoundSocket(t, unix.SOCK_DGRAM, unix.IPPROTO_UDP, bound)
					defer dut.Close(t, boundFD)
					if bindToDevice {
						dut.SetSockOpt(t, boundFD, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, []byte(dut.Net.RemoteDevName))
					}

					var conn udpConn
					var localAddr unix.Sockaddr
					if len(bound) == net.IPv4len {
						v4Conn := dut.Net.NewUDPIPv4(t, testbench.UDP{DstPort: &remotePort}, testbench.UDP{SrcPort: &remotePort})
						localAddr = v4Conn.LocalAddr(t)
						conn = &v4Conn
					} else {
						v6Conn := dut.Net.NewUDPIPv6(t, testbench.UDP{DstPort: &remotePort}, testbench.UDP{SrcPort: &remotePort})
						localAddr = v6Conn.LocalAddr(t, dut.Net.RemoteDevID)
						conn = &v6Conn
					}
					defer conn.Close(t)

					for _, v := range []struct {
						name    string
						payload []byte
					}{
						{"emptypayload", nil},
						{"small payload", []byte("hello world")},
						{"1kPayload", testbench.GenerateRandomPayload(t, 1<<10)},
						// Even though UDP allows larger dgrams we don't test it here as
						// they need to be fragmented and written out as individual
						// frames.
					} {
						t.Run(v.name, func(t *testing.T) {
							conn.Drain(t)
							if got, want := int(dut.SendTo(t, boundFD, v.payload, 0, localAddr)), len(v.payload); got != want {
								t.Fatalf("short write got: %d, want: %d", got, want)
							}
							if _, err := conn.ExpectData(t, testbench.UDP{SrcPort: &remotePort}, testbench.Payload{Bytes: v.payload}, time.Second); err != nil {
								t.Fatal(err)
							}
						})
					}
				})
			}
		})
	}
}

func TestUDPIPv4SendToBroadcast(t *testing.T) {
	dut := testbench.NewDUT(t)
	subnetBcastAddr := broadcastAddr(dut.Net.RemoteIPv4, dut.Net.IPv4PrefixLength)

	for _, bound := range []net.IP{
		dut.Net.RemoteIPv4,
		net.IPv4zero.To4(),
		net.IPv4bcast.To4(),
		subnetBcastAddr,
	} {
		t.Run(fmt.Sprintf("bound=%s", bound), func(t *testing.T) {
			for _, destAddr := range []net.IP{
				subnetBcastAddr,
				net.IPv4bcast.To4(),
			} {
				t.Run(fmt.Sprintf("destAddr=%s", destAddr), func(t *testing.T) {
					// When sending to limited broadcast bindToDevice must be true for the packet
					// to be sent on |conn|'s subnet.
					bindToDeviceRange := []bool{true}
					if cmp.Equal(destAddr, subnetBcastAddr) {
						bindToDeviceRange = append(bindToDeviceRange, false)
					}
					for _, bindToDevice := range bindToDeviceRange {
						t.Run(fmt.Sprintf("bindToDevice=%t", bindToDevice), func(t *testing.T) {
							boundFD, remotePort := dut.CreateBoundSocket(t, unix.SOCK_DGRAM, unix.IPPROTO_UDP, bound)
							defer dut.Close(t, boundFD)
							if bindToDevice {
								dut.SetSockOpt(t, boundFD, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, []byte(dut.Net.RemoteDevName))
							}
							dut.SetSockOptInt(t, boundFD, unix.SOL_SOCKET, unix.SO_BROADCAST, 1)

							conn := dut.Net.NewUDPIPv4(t, testbench.UDP{DstPort: &remotePort}, testbench.UDP{SrcPort: &remotePort})
							defer conn.Close(t)

							destSockaddr := unix.SockaddrInet4{Port: conn.LocalAddr(t).Port}
							copy(destSockaddr.Addr[:], destAddr)

							for _, v := range []struct {
								name    string
								payload []byte
							}{
								{"emptypayload", nil},
								{"small payload", []byte("hello world")},
								{"1kPayload", testbench.GenerateRandomPayload(t, 1<<10)},
								// Even though UDP allows larger dgrams we don't test it here as
								// they need to be fragmented and written out as individual
								// frames.
							} {
								t.Run(v.name, func(t *testing.T) {
									if got, want := int(dut.SendTo(t, boundFD, v.payload, 0, &destSockaddr)), len(v.payload); got != want {
										t.Fatalf("short write got: %d, want: %d", got, want)
									}
									broadcastMac := header.EthernetBroadcastAddress
									if _, err := conn.ExpectFrame(t, testbench.Layers{
										&testbench.Ether{DstAddr: &broadcastMac},
										&testbench.IPv4{DstAddr: testbench.Address(tcpip.Address(destAddr))},
										&testbench.UDP{SrcPort: &remotePort},
										&testbench.Payload{Bytes: v.payload}}, time.Second); err != nil {
										t.Fatal(err)
									}
								})
							}
						})
					}
				})
			}
		})
	}
}

func TestUDPIPv4UnboundSendToBroadcast(t *testing.T) {
	dut := testbench.NewDUT(t)

	// An unbound socket will auto-bind to INNADDR_ANY and a random port on sendto.
	unboundFD := dut.Socket(t, unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_UDP)
	defer dut.Close(t, unboundFD)
	dut.SetSockOpt(t, unboundFD, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, []byte(dut.Net.RemoteDevName))
	dut.SetSockOptInt(t, unboundFD, unix.SOL_SOCKET, unix.SO_BROADCAST, 1)

	conn := dut.Net.NewUDPIPv4(t, testbench.UDP{}, testbench.UDP{})
	defer conn.Close(t)

	bcastAddr := unix.SockaddrInet4{Port: conn.LocalAddr(t).Port}
	copy(bcastAddr.Addr[:], net.IPv4bcast.To4())

	for _, v := range []struct {
		name    string
		payload []byte
	}{
		{"emptypayload", nil},
		{"small payload", []byte("hello world")},
		{"1kPayload", testbench.GenerateRandomPayload(t, 1<<10)},
		// Even though UDP allows larger dgrams we don't test it here as
		// they need to be fragmented and written out as individual
		// frames.
	} {
		t.Run(v.name, func(t *testing.T) {
			if got, want := int(dut.SendTo(t, unboundFD, v.payload, 0, &bcastAddr)), len(v.payload); got != want {
				t.Fatalf("short write got: %d, want: %d", got, want)
			}
			broadcastMAC := header.EthernetBroadcastAddress
			if _, err := conn.ExpectFrame(t, testbench.Layers{
				&testbench.Ether{DstAddr: &broadcastMAC},
				&testbench.IPv4{DstAddr: testbench.Address(tcpip.Address(net.IPv4bcast.To4()))},
				&testbench.UDP{},
				&testbench.Payload{Bytes: v.payload}}, time.Second); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestUDPIPv4Recv(t *testing.T) {
	dut := testbench.NewDUT(t)
	subnetBcastAddr := broadcastAddr(dut.Net.RemoteIPv4, dut.Net.IPv4PrefixLength)

	for _, v := range []struct {
		bound, to net.IP
	}{
		{bound: net.IPv4zero, to: subnetBcastAddr},
		{bound: net.IPv4zero, to: net.IPv4bcast},
		{bound: net.IPv4zero, to: net.IPv4allsys},
		{bound: subnetBcastAddr, to: subnetBcastAddr},
		{bound: net.IPv4bcast, to: net.IPv4bcast},
		{bound: net.IPv4allsys, to: net.IPv4allsys},
		{bound: dut.Net.RemoteIPv4, to: dut.Net.RemoteIPv4},
	} {
		t.Run(fmt.Sprintf("bound=%s,to=%s", v.bound, v.to), func(t *testing.T) {
			for _, bindToDevice := range []bool{true, false} {
				t.Run(fmt.Sprintf("bindToDevice=%t", bindToDevice), func(t *testing.T) {
					boundFD, remotePort := dut.CreateBoundSocket(t, unix.SOCK_DGRAM, unix.IPPROTO_UDP, v.bound.To4())
					defer dut.Close(t, boundFD)
					if bindToDevice {
						dut.SetSockOpt(t, boundFD, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, []byte(dut.Net.RemoteDevName))
					}
					dut.SetSockOptInt(t, boundFD, unix.SOL_SOCKET, unix.SO_BROADCAST, 1)
					conn := dut.Net.NewUDPIPv4(t, testbench.UDP{DstPort: &remotePort}, testbench.UDP{SrcPort: &remotePort})
					defer conn.Close(t)
					for _, tc := range []struct {
						name    string
						payload []byte
					}{
						{"emptypayload", nil},
						{"small payload", []byte("hello world")},
						{"1kPayload", testbench.GenerateRandomPayload(t, 1<<10)},
						// Even though UDP allows larger dgrams we don't test it here as
						// they need to be fragmented and written out as individual
						// frames.
					} {
						t.Run(tc.name, func(t *testing.T) {
							conn.SendIP(
								t,
								testbench.IPv4{DstAddr: testbench.Address(tcpip.Address(v.to.To4()))},
								testbench.UDP{},
								&testbench.Payload{Bytes: tc.payload},
							)
							got, want := dut.Recv(t, boundFD, int32(len(tc.payload)), 0), tc.payload
							if diff := cmp.Diff(want, got); diff != "" {
								t.Errorf("received payload does not match sent payload, diff (-want, +got):\n%s", diff)
							}
						})
					}
				})
			}
		})
	}
}

func TestUDPIPv6Recv(t *testing.T) {
	dut := testbench.NewDUT(t)

	for _, bindToDevice := range []bool{true, false} {
		t.Run(fmt.Sprintf("bindToDevice=%t", bindToDevice), func(t *testing.T) {
			boundFD, remotePort := dut.CreateBoundSocket(t, unix.SOCK_DGRAM, unix.IPPROTO_UDP, dut.Net.RemoteIPv6)
			defer dut.Close(t, boundFD)
			if bindToDevice {
				dut.SetSockOpt(t, boundFD, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, []byte(dut.Net.RemoteDevName))
			}
			dut.SetSockOptInt(t, boundFD, unix.SOL_SOCKET, unix.SO_BROADCAST, 1)
			conn := dut.Net.NewUDPIPv6(t, testbench.UDP{DstPort: &remotePort}, testbench.UDP{SrcPort: &remotePort})
			defer conn.Close(t)
			for _, tc := range []struct {
				name    string
				payload []byte
			}{
				{"emptypayload", nil},
				{"small payload", []byte("hello world")},
				{"1kPayload", testbench.GenerateRandomPayload(t, 1<<10)},
				// Even though UDP allows larger dgrams we don't test it here as
				// they need to be fragmented and written out as individual
				// frames.
			} {
				t.Run(tc.name, func(t *testing.T) {
					conn.SendIPv6(
						t,
						testbench.IPv6{DstAddr: testbench.Address(tcpip.Address(dut.Net.RemoteIPv6))},
						testbench.UDP{},
						&testbench.Payload{Bytes: tc.payload},
					)
					got, want := dut.Recv(t, boundFD, int32(len(tc.payload)), 0), tc.payload
					if diff := cmp.Diff(want, got); diff != "" {
						t.Errorf("received payload does not match sent payload, diff (-want, +got):\n%s", diff)
					}
				})
			}
		})
	}
}

func TestUDPDoesntRecvMcastBcastOnUnicastAddr(t *testing.T) {
	dut := testbench.NewDUT(t)
	boundFD, remotePort := dut.CreateBoundSocket(t, unix.SOCK_DGRAM, unix.IPPROTO_UDP, dut.Net.RemoteIPv4)
	dut.SetSockOptTimeval(t, boundFD, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 1, Usec: 0})
	defer dut.Close(t, boundFD)
	conn := dut.Net.NewUDPIPv4(t, testbench.UDP{DstPort: &remotePort}, testbench.UDP{SrcPort: &remotePort})
	defer conn.Close(t)

	for _, to := range []net.IP{
		broadcastAddr(dut.Net.RemoteIPv4, dut.Net.IPv4PrefixLength),
		net.IPv4(255, 255, 255, 255),
		net.IPv4(224, 0, 0, 1),
	} {
		t.Run(fmt.Sprint("to=%s", to), func(t *testing.T) {
			payload := testbench.GenerateRandomPayload(t, 1<<10 /* 1 KiB */)
			conn.SendIP(
				t,
				testbench.IPv4{DstAddr: testbench.Address(tcpip.Address(to.To4()))},
				testbench.UDP{},
				&testbench.Payload{Bytes: payload},
			)
			ret, payload, errno := dut.RecvWithErrno(context.Background(), t, boundFD, 100, 0)
			if errno != syscall.EAGAIN || errno != syscall.EWOULDBLOCK {
				t.Errorf("Recv got unexpected result, ret=%d, payload=%q, errno=%s", ret, payload, errno)
			}
		})
	}
}

func broadcastAddr(ip net.IP, prefix int) net.IP {
	mask := net.CIDRMask(prefix, 32)
	result := make(net.IP, net.IPv4len)
	ip4 := ip.To4()
	for i := range ip4 {
		result[i] = ip4[i] | ^mask[i]
	}
	return result
}
