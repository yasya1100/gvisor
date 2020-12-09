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

package tcp_rack_test

import (
	"flag"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/seqnum"
	"gvisor.dev/gvisor/test/packetimpact/testbench"
)

func init() {
	testbench.Initialize(flag.CommandLine)
}

const (
	minMTU        = 1500
	mss           = minMTU - header.IPv4MinimumSize - header.TCPMinimumSize
	delayDuration = 30 * time.Millisecond
)

func createSACKConnection(t *testing.T) (testbench.DUT, testbench.TCPIPv4, int32, int32) {
	dut := testbench.NewDUT(t)
	listenFd, remotePort := dut.CreateListener(t, unix.SOCK_STREAM, unix.IPPROTO_TCP, 1)
	conn := dut.Net.NewTCPIPv4(t, testbench.TCP{DstPort: &remotePort}, testbench.TCP{SrcPort: &remotePort})

	// Enable SACK.
	opts := make([]byte, 40)
	optsOff := 0
	optsOff += header.EncodeNOP(opts[optsOff:])
	optsOff += header.EncodeNOP(opts[optsOff:])
	optsOff += header.EncodeSACKPermittedOption(opts[optsOff:])

	// Ethernet guarantees that the MTU is at least 1500 bytes.
	optsOff += header.EncodeMSSOption(mss, opts[optsOff:])

	conn.ConnectWithOptions(t, opts[:optsOff])
	acceptFd, _ := dut.Accept(t, listenFd)
	return dut, conn, acceptFd, listenFd
}

func closeSACKConnection(t *testing.T, dut testbench.DUT, conn testbench.TCPIPv4, acceptFd, listenFd int32) {
	dut.Close(t, acceptFd)
	dut.Close(t, listenFd)
	conn.Close(t)
}

func getPayloadSize(t *testing.T, dut testbench.DUT, acceptFd int32) int32 {
	pls := dut.GetSockOptInt(t, acceptFd, unix.IPPROTO_TCP, unix.TCP_MAXSEG)
	if !testbench.Native {
		// netstack does not impliment TCP_MAXSEG correctly. Fake it
		// here. Netstack uses the max SACK size which is 32. The MSS
		// option is 8 bytes, making the total 36 bytes.
		pls = mss - 36
	}
	return pls
}

func calculateRTT(t *testing.T, dut testbench.DUT, conn testbench.TCPIPv4, acceptFd int32, pls int32) time.Duration {
	payload := make([]byte, pls)
	seqNum1 := *conn.RemoteSeqNum(t)

	// Allow the connection to detect RTT by sending and replying to the
	// data packet. Add some delay to increase the RTT.
	dut.Send(t, acceptFd, payload, 0)
	time.Sleep(delayDuration)
	if _, err := conn.Expect(t, testbench.TCP{SeqNum: testbench.Uint32(uint32(seqNum1))}, time.Second); err != nil {
		t.Fatalf("expected a packet within a second but got error %s", err)
	}
	seqNum1.UpdateForward(seqnum.Size(pls))
	conn.Send(t, testbench.TCP{Flags: testbench.Uint8(header.TCPFlagAck), AckNum: testbench.Uint32(uint32(seqNum1))})
	// Add few milliseconds to account for the actual RTT without delay.
	rtt := delayDuration + 10*time.Millisecond
	return rtt
}

func sendAndReceive(t *testing.T, dut testbench.DUT, conn testbench.TCPIPv4, numPkts int, acceptFd, pls int32) {
	seqNum1 := *conn.RemoteSeqNum(t)
	payload := make([]byte, pls)
	for i, sn := 0, seqNum1; i < numPkts; i++ {
		dut.Send(t, acceptFd, payload, 0)
		time.Sleep(time.Millisecond)
		gotOne, err := conn.Expect(t, testbench.TCP{SeqNum: testbench.Uint32(uint32(sn))}, time.Second)
		if err != nil {
			t.Fatalf("Expect #%d: %s", i+1, err)
			continue
		}
		if gotOne == nil {
			t.Fatalf("#%d: expected a packet within a second but got none", i+1)
		}
		sn.UpdateForward(seqnum.Size(pls))
	}
}

// TestRACKTLPAllPacketsLost tests TLP when an entire flight of data is lost.
func TestRACKTLPAllPacketsLost(t *testing.T) {
	dut, conn, acceptFd, listenFd := createSACKConnection(t)
	pls := getPayloadSize(t, dut, acceptFd)
	seqNum1 := *conn.RemoteSeqNum(t)
	rtt := calculateRTT(t, dut, conn, acceptFd, pls)
	seqNum1.UpdateForward(seqnum.Size(pls))

	const numPkts = 5
	sendAndReceive(t, dut, conn, numPkts, acceptFd, pls)
	// Remove this check after TLP is implemented.
	if !testbench.Native {
		return
	}

	// Probe Timeout (PTO) should be two times RTT. Check that the last
	// packet is retransmitted after PTO.
	pto := rtt * 2
	tlpProbe := testbench.Uint32(uint32(seqNum1) + uint32((numPkts-1)*pls))
	if _, err := conn.Expect(t, testbench.TCP{SeqNum: tlpProbe}, pto); err != nil {
		t.Fatalf("expected payload was not received: %s", err)
	}
	closeSACKConnection(t, dut, conn, acceptFd, listenFd)
}

// TestRACKTLPLost tests TLP when there are tail losses.
// See: https://tools.ietf.org/html/draft-ietf-tcpm-rack-08#section-7.4
func TestRACKTLPLost(t *testing.T) {
	dut, conn, acceptFd, listenFd := createSACKConnection(t)
	pls := getPayloadSize(t, dut, acceptFd)
	seqNum1 := *conn.RemoteSeqNum(t)
	rtt := calculateRTT(t, dut, conn, acceptFd, pls)
	seqNum1.UpdateForward(seqnum.Size(pls))

	const numPkts = 10
	sendAndReceive(t, dut, conn, numPkts, acceptFd, pls)
	// Remove this check after TLP is implemented.
	if !testbench.Native {
		return
	}

	// Cumulative ACK for #[1-5] packets.
	ackNum := seqNum1.Add(seqnum.Size(6 * pls))
	conn.Send(t, testbench.TCP{Flags: testbench.Uint8(header.TCPFlagAck), AckNum: testbench.Uint32(uint32(ackNum))})

	// Probe Timeout (PTO) should be two times RTT. Check that the last
	// packet is retransmitted after PTO.
	pto := rtt * 2
	tlpProbe := testbench.Uint32(uint32(seqNum1) + uint32((numPkts-1)*pls))
	if _, err := conn.Expect(t, testbench.TCP{SeqNum: tlpProbe}, pto); err != nil {
		t.Fatalf("expected payload was not received: %s", err)
	}
	closeSACKConnection(t, dut, conn, acceptFd, listenFd)
}

// TestRACKTLPWithSACK tests TLP by acknowledging out of order packets.
// See: https://tools.ietf.org/html/draft-ietf-tcpm-rack-08#section-8.1
func TestRACKTLPWithSACK(t *testing.T) {
	dut, conn, acceptFd, listenFd := createSACKConnection(t)
	pls := getPayloadSize(t, dut, acceptFd)
	seqNum1 := *conn.RemoteSeqNum(t)
	rtt := calculateRTT(t, dut, conn, acceptFd, pls)
	seqNum1.UpdateForward(seqnum.Size(pls))

	const numPkts = 3
	sendAndReceive(t, dut, conn, numPkts, acceptFd, pls)
	// Remove this check after TLP is implemented.
	if !testbench.Native {
		return
	}

	// SACK for #2 packet.
	sackBlock := make([]byte, 40)
	start := seqNum1.Add(seqnum.Size(pls))
	end := start.Add(seqnum.Size(pls))
	sbOff := 0
	sbOff += header.EncodeNOP(sackBlock[sbOff:])
	sbOff += header.EncodeNOP(sackBlock[sbOff:])
	sbOff += header.EncodeSACKBlocks([]header.SACKBlock{{
		start, end,
	}}, sackBlock[sbOff:])
	conn.Send(t, testbench.TCP{Flags: testbench.Uint8(header.TCPFlagAck), AckNum: testbench.Uint32(uint32(seqNum1)), Options: sackBlock[:sbOff]})

	// RACK marks #1 packet as lost and retransmits it.
	if _, err := conn.Expect(t, testbench.TCP{SeqNum: testbench.Uint32(uint32(seqNum1))}, time.Second); err != nil {
		t.Fatalf("expected payload was not received: %s", err)
	}

	// ACK for #1 packet.
	conn.Send(t, testbench.TCP{Flags: testbench.Uint8(header.TCPFlagAck), AckNum: testbench.Uint32(uint32(end))})

	// Probe Timeout (PTO) should be two times RTT. TLP will trigger for #3
	// packet. RACK adds an additional timeout of 200ms if the number of
	// outstanding packets is equal to 1.
	pto := (rtt * 2) + (200 * time.Millisecond)
	tlpProbe := testbench.Uint32(uint32(end))
	if _, err := conn.Expect(t, testbench.TCP{SeqNum: tlpProbe}, pto); err != nil {
		t.Fatalf("expected payload was not received: %s", err)
	}
	closeSACKConnection(t, dut, conn, acceptFd, listenFd)
}
