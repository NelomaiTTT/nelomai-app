package main

import (
	"bufio"
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
)

// One complete scenario. Native OS effects are real on Windows; on the build
// host only nativeOwner is substituted. Crypto, dispatcher and RPC remain real.
func TestWorkerLifecycle(t *testing.T) {
	var feed io.WriteCloser
	var output io.ReadCloser
	var decoder *json.Decoder
	var child *exec.Cmd
	var entered chan struct{}
	var id uint64
	startChild := func(fault bool) {
		t.Helper()
		executable, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		child = exec.Command(executable, "-test.run=^$")
		child.Env = append(os.Environ(), "NELOMAI_WORKER_TEST_CHILD=1")
		if fault {
			child.Env = append(child.Env, "NELOMAI_WORKER_TEST_FAULT=1")
		}
		feed, err = child.StdinPipe()
		if err != nil {
			t.Fatal(err)
		}
		output, err = child.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		stderr, err := child.StderrPipe()
		if err != nil {
			t.Fatal(err)
		}
		entered = make(chan struct{}, 1)
		go func() {
			scanner := bufio.NewScanner(stderr)
			for scanner.Scan() {
				if scanner.Text() == "worker_test_write_entered" {
					entered <- struct{}{}
				}
			}
		}()
		if err := child.Start(); err != nil {
			t.Fatal(err)
		}
		// exec.Cmd retains the original Windows process HANDLE; never reopen by PID.
		decoder = json.NewDecoder(output)
		id = 0
	}
	defer func() {
		if child != nil && child.Process != nil {
			child.Process.Kill()
			child.Wait()
		}
	}()
	call := func(req request) response {
		t.Helper()
		id++
		req.ID = id
		req.Session = 1
		if err := json.NewEncoder(feed).Encode(req); err != nil {
			t.Fatal(err)
		}
		var frame json.RawMessage
		if err := decoder.Decode(&frame); err != nil {
			t.Fatal(err)
		}
		var reply response
		if err := json.Unmarshal(frame, &reply); err != nil {
			t.Fatal(err)
		}
		if req.Op == "stop" && req.AwaitAbsence != nil && !*req.AwaitAbsence {
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(frame, &fields); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(bytes.TrimSpace(fields["absent"]), []byte("false")) {
				t.Fatal("two-phase Stop omitted explicit absent:false ACK")
			}
		}
		if reply.ID != id {
			t.Fatalf("wrong ACK identity: %+v", reply)
		}
		return reply
	}
	startChild(false)
	if reply := call(request{Op: "start"}); reply.OK || reply.Error == "" {
		t.Fatalf("invalid Start not rejected: %+v", reply)
	}
	physical, endpoint := testPhysical(t)
	startRequest := func() request {
		var nonce [16]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			t.Fatal(err)
		}
		guid := fmt.Sprintf("{%x-%x-%x-%x-%x}", nonce[:4], nonce[4:6], nonce[6:8], nonce[8:10], nonce[10:])
		return request{Op: "start", Name: "NeloWorker-" + fmt.Sprint(time.Now().UnixNano()), GUID: guid, DLLSHA256: testDLLSHA(t), MTU: 1280}
	}
	start := call(startRequest())
	if !start.OK || start.Identity.Index == 0 || start.Identity.LUID == 0 || start.MTU != 1280 {
		t.Fatalf("Start: %+v", start)
	}
	send, receiveUDP, closeUDP := testTransport(t, start.Identity)
	defer func() { closeUDP() }()
	var configurations [2]string
	var peers [2]*device.Device
	var memory [2]*testPeerTUN
	for slot := range peers {
		private, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		remote, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		memory[slot] = newTestPeer(fmt.Sprint(slot))
		peers[slot] = device.NewDevice(memory[slot], conn.NewStdNetBind(), device.NewLogger(device.LogLevelSilent, ""))
		defer peers[slot].Close()
		awg := ""
		if slot == 1 {
			awg = "jc=2\njmin=40\njmax=80\nh1=111111\nh2=222222\nh3=333333\nh4=444444\n"
		}
		configuration := fmt.Sprintf("private_key=%s\nlisten_port=0\n%spublic_key=%s\nallowed_ip=198.18.240.1/32\n\n", hex.EncodeToString(remote.Bytes()), awg, hex.EncodeToString(private.PublicKey().Bytes()))
		if err := peers[slot].IpcSet(configuration); err != nil {
			t.Fatal(err)
		}
		if err := peers[slot].Up(); err != nil {
			t.Fatal(err)
		}
		state, err := peers[slot].IpcGet()
		if err != nil {
			t.Fatal(err)
		}
		port := ""
		for _, line := range strings.Split(state, "\n") {
			if value, ok := strings.CutPrefix(line, "listen_port="); ok {
				port = value
			}
		}
		if port == "" || port == "0" {
			t.Fatal("local peer is not bound")
		}
		config := fmt.Sprintf("private_key=%s\nlisten_port=0\n%spublic_key=%s\nallowed_ip=198.18.240.2/32\nendpoint=%s:%s\npersistent_keepalive_interval=1\n\n", hex.EncodeToString(private.Bytes()), awg, hex.EncodeToString(remote.PublicKey().Bytes()), endpoint, port)
		configurations[slot] = config
		attached := call(request{Op: "attach", Slot: uint32(slot), Configuration: config, Physical: physical})
		if !attached.OK {
			t.Fatalf("Attach %d: %+v", slot, attached)
		}
	}
	deadline := time.Now().Add(15 * time.Second)
	for {
		sampled := call(request{Op: "sample"})
		if sampled.Handshakes[0] > 0 && sampled.Handshakes[1] > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("both authenticated handshakes missing")
		}
		time.Sleep(10 * time.Millisecond)
	}
	// Feed one bounded burst through A, then the SAME destination through B.
	var previousStats [2]RedundantSlotStats
	for slot := 0; slot < 2; slot++ {
		if slot == 1 {
			reply := call(request{Op: "switch", Slot: 1})
			if !reply.OK {
				t.Fatal(reply)
			}
			before := reply.Counters.InactiveInboundDrops
			memory[0].packetMu.Lock()
			old := append([]byte(nil), memory[0].lastPacket...)
			memory[0].packetMu.Unlock()
			memory[0].outbound <- testPacket(old[16:20], old[12:16], binary.BigEndian.Uint16(old[22:24]), binary.BigEndian.Uint16(old[20:22]), []byte("late-A"))
			until := time.Now().Add(5 * time.Second)
			for {
				sample := call(request{Op: "sample"})
				if sample.Counters.InactiveInboundDrops > before {
					break
				}
				if time.Now().After(until) {
					t.Fatal("late authenticated A reply was not fenced")
				}
				time.Sleep(time.Millisecond)
			}
		}
		for packet := 0; packet < 24; packet++ {
			send([]byte(fmt.Sprintf("load-%d-%d", slot, packet)))
		}
		seen := map[string]bool{}
		for packet := 0; packet < 24; packet++ {
			payload := string(receiveUDP())
			expectedPrefix := fmt.Sprintf("peer-%d:load-%d-", slot, slot)
			if !strings.HasPrefix(payload, expectedPrefix) || seen[payload] {
				t.Fatalf("wrong/duplicate routed payload %q", payload)
			}
			seen[payload] = true
		}
		until := time.Now().Add(time.Second)
		for {
			stats := call(request{Op: "sample"}).SlotStats
			if stats[slot].TxPackets >= 24 && stats[slot].RxDataPackets >= 24 {
				other := 1 - slot
				if stats[other].TxPackets != previousStats[other].TxPackets || stats[other].RxDataPackets != previousStats[other].RxDataPackets {
					t.Fatal("slot traffic/late drop leaked into reserve packet counters")
				}
				previousStats = stats
				break
			}
			if time.Now().After(until) {
				t.Fatal("real per-slot IP packet counters missing")
			}
			time.Sleep(time.Millisecond)
		}
	}
	// The worker must preserve the exact query ID/question, and return both real
	// invalid and valid DNS replies. Only the caller may validate the answer.
	query := []byte{0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1}
	sent := call(request{Op: "probe_send", Slot: 0, Source: "198.18.240.1", Target: "198.18.240.2", DNS: query})
	if !sent.OK || sent.Probe == 0 {
		t.Fatalf("standby probe: %+v", sent)
	}
	var replies [][]byte
	deadline = time.Now().Add(5 * time.Second)
	for len(replies) < 2 {
		polled := call(request{Op: "probe_poll", Probe: sent.Probe})
		if !polled.OK {
			t.Fatal(polled)
		}
		if len(polled.DNS) > 0 {
			replies = append(replies, polled.DNS)
		}
		if time.Now().After(deadline) {
			t.Fatal("genuine standby DNS replies missing")
		}
		time.Sleep(time.Millisecond)
	}
	valid := append([]byte(nil), query...)
	valid[2] = 0x81
	valid[3] = 0x80
	valid[7] = 1
	valid = append(valid, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 203, 0, 113, 1)
	if replies[0][3] != 0x83 || !bytes.Equal(replies[1], valid) {
		t.Fatal("worker synthesized or rewrote DNS answer")
	}
	stats := call(request{Op: "sample"}).SlotStats
	if stats[0].TxPackets != previousStats[0].TxPackets+1 || stats[0].RxDataPackets != previousStats[0].RxDataPackets+2 || stats[1].TxPackets != previousStats[1].TxPackets || stats[1].RxDataPackets != previousStats[1].RxDataPackets {
		t.Fatal("genuine injected DNS IP packets were not counted only on their slot")
	}
	if cancelled := call(request{Op: "probe_cancel", Probe: sent.Probe}); !cancelled.OK {
		t.Fatal(cancelled)
	}
	if stale := call(request{Op: "probe_poll", Probe: sent.Probe}); stale.OK {
		t.Fatal("cancelled probe remained live")
	}
	// Retire only inactive A and replace its crypto device behind the SAME TUN.
	oldGeneration := stats[0].Generation
	if detached := call(request{Op: "detach", Slot: 0, Generation: oldGeneration}); !detached.OK || !detached.SlotStats[0].Closed || detached.SlotStats[1].Closed || detached.Identity != start.Identity {
		t.Fatalf("inactive retirement: %+v", detached)
	}
	send([]byte("reserve-continuity"))
	if string(receiveUDP()) != "peer-1:reserve-continuity" {
		t.Fatal("retirement interrupted active B")
	}
	if attached := call(request{Op: "attach", Slot: 0, Configuration: configurations[0], Physical: physical}); !attached.OK || attached.SlotStats[0].Generation <= oldGeneration {
		t.Fatalf("fresh crypto replacement: %+v", attached)
	}
	if stale := call(request{Op: "detach", Slot: 0, Generation: oldGeneration}); stale.OK {
		t.Fatal("old generation detached replacement")
	}
	if active := call(request{Op: "detach", Slot: 1, Generation: stats[1].Generation}); active.OK {
		t.Fatal("active device retirement accepted")
	}
	if switched := call(request{Op: "switch", Slot: 0}); !switched.OK {
		t.Fatal(switched)
	}
	send([]byte("replacement"))
	if string(receiveUDP()) != "peer-0:replacement" {
		t.Fatal("replacement crypto dataplane failed")
	}
	// Two-phase Stop proves native close, then the parent independently proves
	// exact absence and original process exit before the fresh-child repeat.
	awaitAbsence := false
	stopAt := time.Now()
	clean := call(request{Op: "stop", AwaitAbsence: &awaitAbsence})
	if !clean.OK || !clean.Closed || clean.Absent || clean.ElapsedMS > 7000 {
		t.Fatalf("clean Stop: %+v", clean)
	}
	if err := child.Wait(); err != nil {
		t.Fatalf("original process did not exit cleanly: %v", err)
	}
	observer := newNativeOwner()
	for {
		absent, err := observer.absent(start.Identity)
		if err != nil {
			t.Fatal(err)
		}
		if absent {
			break
		}
		if time.Since(stopAt) >= 7*time.Second {
			t.Fatal("original exact interface remained after Close/exit")
		}
		time.Sleep(time.Millisecond)
	}
	if time.Since(stopAt) > 7*time.Second {
		t.Fatal("normal two-phase Stop exceeded 7s")
	}
	closeUDP()
	feed.Close()
	output.Close()
	startChild(true)
	repeated := call(startRequest())
	if !repeated.OK || repeated.Identity.GUID == start.Identity.GUID {
		t.Fatalf("fresh repeat Start: %+v", repeated)
	}
	send, receiveUDP, closeUDP = testTransport(t, repeated.Identity)
	for slot := range configurations {
		ack := call(request{Op: "attach", Slot: uint32(slot), Configuration: configurations[slot], Physical: physical})
		if !ack.OK {
			t.Fatal(ack)
		}
	}
	if ack := call(request{Op: "switch", Slot: 1}); !ack.OK {
		t.Fatal(ack)
	}
	// Test-only wrapper delays this actual Write; a Switch ACK may not overtake it.
	send([]byte("switch-barrier"))
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("writer barrier not reached")
	}
	id++
	switchID := id
	if err := json.NewEncoder(feed).Encode(request{ID: id, Session: 1, Op: "switch", Slot: 0}); err != nil {
		t.Fatal(err)
	}
	switched := make(chan response, 1)
	go func() { var ack response; decoder.Decode(&ack); switched <- ack }()
	select {
	case <-switched:
		t.Fatal("Switch ACK overtook active Write")
	case <-time.After(20 * time.Millisecond):
	}
	ack := <-switched
	if !ack.OK || ack.ID != switchID {
		t.Fatalf("Switch after Write: %+v", ack)
	}
	if string(receiveUDP()) != "peer-1:switch-barrier" {
		t.Fatal("admitted old Write was lost")
	}
	send([]byte("writer-error"))
	deadline = time.Now().Add(5 * time.Second)
	for {
		sample := call(request{Op: "sample"})
		if sample.Closed {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("post-switch peer did not establish")
		}
		time.Sleep(time.Millisecond)
	}
	// The write error closes the actual dispatcher outside routeMu.RLock.
	stop := call(request{Op: "stop"})
	if !stop.Absent || stop.OK || stop.Error == "" || stop.ElapsedMS > 8000 {
		t.Fatalf("error Stop: %+v", stop)
	}
	if err := child.Wait(); err != nil {
		t.Fatalf("terminal error ACK was not followed by process exit: %v", err)
	}
}

func TestMain(m *testing.M) {
	// Disposable external network double: only memory TUNs and real AWG UDP.
	// No worker/native interface effects; original devices die on stdin EOF.
	if address := os.Getenv("NELOMAI_WORKER_TEST_PEERS"); address != "" {
		ip := net.ParseIP(address)
		if ip == nil || ip.To4() == nil || ip.IsLoopback() || ip.IsUnspecified() {
			os.Exit(1)
		}
		var peers [3]*device.Device
		ready := make([]map[string]string, len(peers))
		for slot := range peers {
			clientBytes, remoteBytes := bytes.Repeat([]byte{byte(1 + slot*2)}, 32), bytes.Repeat([]byte{byte(2 + slot*2)}, 32)
			client, err := ecdh.X25519().NewPrivateKey(clientBytes)
			if err != nil {
				os.Exit(1)
			}
			remote, err := ecdh.X25519().NewPrivateKey(remoteBytes)
			if err != nil {
				os.Exit(1)
			}
			peers[slot] = device.NewDevice(newTestPeer(fmt.Sprint(slot)), conn.NewStdNetBind(), device.NewLogger(device.LogLevelSilent, ""))
			configuration := fmt.Sprintf("private_key=%s\nlisten_port=0\njc=2\njmin=40\njmax=80\ns1=12\ns2=12\ns3=12\ns4=12\nh1=111111\nh2=222222\nh3=333333\nh4=444444\nheader_protection_key=%s\ncontent_padding_addition=0-32\npublic_key=%s\nallowed_ip=10.7.0.2/32\n\n", hex.EncodeToString(remote.Bytes()), hex.EncodeToString(bytes.Repeat([]byte{2}, 32)), hex.EncodeToString(client.PublicKey().Bytes()))
			if peers[slot].IpcSet(configuration) != nil || peers[slot].Up() != nil {
				os.Exit(1)
			}
			state, err := peers[slot].IpcGet()
			if err != nil {
				os.Exit(1)
			}
			port := ""
			for _, line := range strings.Split(state, "\n") {
				if value, ok := strings.CutPrefix(line, "listen_port="); ok {
					port = value
				}
			}
			if port == "" || port == "0" {
				os.Exit(1)
			}
			ready[slot] = map[string]string{"endpoint": net.JoinHostPort(ip.String(), port), "public_key": base64.StdEncoding.EncodeToString(remote.PublicKey().Bytes())}
		}
		// An authenticated test-only UDP request closes the REAL external A
		// peer. Failure then traverses product DNS/metrics and actor promotion.
		control, err := net.ListenUDP("udp4", &net.UDPAddr{})
		if err != nil {
			os.Exit(1)
		}
		var nonce [16]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			os.Exit(1)
		}
		token := hex.EncodeToString(nonce[:])
		ready[0]["control"] = net.JoinHostPort(ip.String(), fmt.Sprint(control.LocalAddr().(*net.UDPAddr).Port))
		ready[0]["token"] = token
		done := make(chan struct{})
		go func() {
			defer close(done)
			var packet [128]byte
			for {
				n, address, err := control.ReadFromUDP(packet[:])
				if err != nil {
					return
				}
				if string(packet[:n]) != "close-a:"+token {
					continue
				}
				peers[0].Close()
				<-peers[0].Wait()
				_, _ = control.WriteToUDP([]byte("closed-a:"+token), address)
			}
		}()
		if json.NewEncoder(os.Stdout).Encode(ready) != nil {
			os.Exit(1)
		}
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
		} // bounded by the original parent pipe lifetime
		control.Close()
		<-done
		for _, peer := range peers {
			peer.Close()
			<-peer.Wait()
		}
		if scanner.Err() != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}
	if os.Getenv("NELOMAI_WORKER_TEST_CHILD") == "1" {
		log.SetOutput(io.Discard)
		installTestNativeFault()
		if runWorker(os.Stdin, os.Stdout) != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// This fault adapter is linked only into the test executable, never the worker.
type testWriteFault struct{ tun.Device }

func (f *testWriteFault) LUID() uint64 { return f.Device.(interface{ LUID() uint64 }).LUID() }
func (f *testWriteFault) Write(bufs [][]byte, offset int) (int, error) {
	if os.Getenv("NELOMAI_WORKER_TEST_FAULT") == "1" {
		for _, packet := range bufs {
			if bytes.Contains(packet[offset:], []byte("writer-error")) {
				return 0, fmt.Errorf("injected native writer failure")
			}
			if bytes.Contains(packet[offset:], []byte("switch-barrier")) {
				fmt.Fprintln(os.Stderr, "worker_test_write_entered")
				time.Sleep(300 * time.Millisecond)
			}
		}
	}
	return f.Device.Write(bufs, offset)
}

type testPeerTUN struct {
	packetMu   sync.Mutex
	lastPacket []byte
	label      string
	outbound   chan []byte
	events     chan tun.Event
	done       chan struct{}
	once       sync.Once
}

func newTestPeer(label string) *testPeerTUN {
	return &testPeerTUN{label: label, outbound: make(chan []byte, 128), events: make(chan tun.Event), done: make(chan struct{})}
}
func (p *testPeerTUN) File() *os.File           { return nil }
func (p *testPeerTUN) MTU() (int, error)        { return 1420, nil }
func (p *testPeerTUN) Name() (string, error)    { return "memory-peer", nil }
func (p *testPeerTUN) Events() <-chan tun.Event { return p.events }
func (p *testPeerTUN) BatchSize() int           { return 1 }
func (p *testPeerTUN) Close() error             { p.once.Do(func() { close(p.done); close(p.events) }); return nil }
func (p *testPeerTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	select {
	case <-p.done:
		return 0, os.ErrClosed
	case packet := <-p.outbound:
		copy(bufs[0][offset:], packet)
		sizes[0] = len(packet)
		return 1, nil
	}
}
func (p *testPeerTUN) Write(bufs [][]byte, offset int) (int, error) {
	for _, buf := range bufs {
		packet := buf[offset:]
		if len(packet) < 28 || packet[0] != 0x45 || packet[9] != 17 {
			continue
		}
		var payloads [][]byte
		if binary.BigEndian.Uint16(packet[22:24]) == 53 {
			invalid := append([]byte(nil), packet[28:]...)
			invalid[2] = 0x81
			invalid[3] = 0x83
			valid := append([]byte(nil), packet[28:]...)
			valid[2] = 0x81
			valid[3] = 0x80
			valid[7] = 1
			valid = append(valid, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 203, 0, 113, 1)
			payloads = [][]byte{invalid, valid}
		} else {
			p.packetMu.Lock()
			p.lastPacket = append([]byte(nil), packet...)
			p.packetMu.Unlock()
			payloads = [][]byte{[]byte("peer-" + p.label + ":" + string(packet[28:]))}
		}
		for _, payload := range payloads {
			reply := testPacket(packet[16:20], packet[12:16], binary.BigEndian.Uint16(packet[22:24]), binary.BigEndian.Uint16(packet[20:22]), payload)
			select {
			case <-p.done:
				return 0, os.ErrClosed
			case p.outbound <- reply:
			}
		}
	}
	return len(bufs), nil
}
func testPacket(source, target []byte, sourcePort, targetPort uint16, payload []byte) []byte {
	packet := make([]byte, 28+len(payload))
	packet[0] = 0x45
	packet[8] = 64
	packet[9] = 17
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	copy(packet[12:16], source)
	copy(packet[16:20], target)
	var sum uint32
	for at := 0; at < 20; at += 2 {
		sum += uint32(binary.BigEndian.Uint16(packet[at : at+2]))
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	binary.BigEndian.PutUint16(packet[10:12], ^uint16(sum))
	binary.BigEndian.PutUint16(packet[20:22], sourcePort)
	binary.BigEndian.PutUint16(packet[22:24], targetPort)
	binary.BigEndian.PutUint16(packet[24:26], uint16(len(payload)+8))
	copy(packet[28:], payload)
	return packet
}
