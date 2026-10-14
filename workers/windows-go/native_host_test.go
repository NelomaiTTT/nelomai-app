//go:build !windows

package main

import (
	"encoding/binary"
	"errors"
	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// Substitute only Wintun/MIB/DLL/socket pin effects on the build host. The child
// process still exercises the genuine worker IPC, crypto, dispatcher and probes.
type nativeOwner struct {
	real    *hostTestTUN
	pending identity
}

func newNativeOwner() nativeOwner { return nativeOwner{} }
func (o *nativeOwner) start(req request) (tun.Device, identity, error) {
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return nil, identity{}, err
	}
	o.real = &hostTestTUN{socket: socket, events: make(chan tun.Event), mtu: int(req.MTU)}
	o.pending = identity{GUID: req.GUID, LUID: 1, Index: uint32(socket.LocalAddr().(*net.UDPAddr).Port)}
	return &testWriteFault{Device: o.real}, o.pending, nil
}
func (o *nativeOwner) newBind(identity) (conn.Bind, error) { return conn.NewStdNetBind(), nil }
func (o *nativeOwner) closeTun() error {
	if o.real != nil {
		return o.real.Close()
	}
	return nil
}
func (o *nativeOwner) absent(identity) (bool, error) {
	if o.real == nil {
		return true, nil
	}
	o.real.mu.Lock()
	defer o.real.mu.Unlock()
	return o.real.closed, nil
}
func installTestNativeFault() {}
func testPhysical(*testing.T) (identity, string) {
	return identity{GUID: "host-only-native-substitution", LUID: 2, Index: 2}, "127.0.0.1"
}
func testDLLSHA(*testing.T) string { return strings.Repeat("0", 64) }
func testTransport(t *testing.T, ident identity) (func([]byte), func() []byte, func()) {
	t.Helper()
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	localPort := uint16(socket.LocalAddr().(*net.UDPAddr).Port)
	send := func(payload []byte) {
		t.Helper()
		packet := testPacket([]byte{198, 18, 240, 1}, []byte{198, 18, 240, 2}, localPort, 45123, payload)
		if _, err := socket.WriteToUDP(packet, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(ident.Index)}); err != nil {
			t.Fatal(err)
		}
	}
	receive := func() []byte {
		t.Helper()
		socket.SetReadDeadline(time.Now().Add(10 * time.Second))
		buffer := make([]byte, 2048)
		n, _, err := socket.ReadFromUDP(buffer)
		if err != nil {
			t.Fatal(err)
		}
		if n < 28 {
			t.Fatal("invalid raw TUN reply")
		}
		return append([]byte(nil), buffer[28:n]...)
	}
	return send, receive, func() { socket.Close() }
}

type hostTestTUN struct {
	mtu    int
	socket *net.UDPConn
	events chan tun.Event
	mu     sync.Mutex
	closed bool
}

func (t *hostTestTUN) File() *os.File           { return nil }
func (t *hostTestTUN) Name() (string, error)    { return "host-test-native-effect", nil }
func (t *hostTestTUN) MTU() (int, error)        { return t.mtu, nil }
func (t *hostTestTUN) BatchSize() int           { return 1 }
func (t *hostTestTUN) Events() <-chan tun.Event { return t.events }
func (t *hostTestTUN) LUID() uint64             { return 1 }
func (t *hostTestTUN) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return errors.New("double native close")
	}
	t.closed = true
	close(t.events)
	return t.socket.Close()
}
func (t *hostTestTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	n, _, err := t.socket.ReadFromUDP(bufs[0][offset:])
	if err != nil {
		return 0, os.ErrClosed
	}
	sizes[0] = n
	return 1, nil
}
func (t *hostTestTUN) Write(bufs [][]byte, offset int) (int, error) {
	for i, buf := range bufs {
		packet := buf[offset:]
		if len(packet) < 28 {
			return i, io.ErrShortWrite
		}
		target := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(binary.BigEndian.Uint16(packet[22:24]))}
		if _, err := t.socket.WriteToUDP(packet, target); err != nil {
			return i, err
		}
	}
	return len(bufs), nil
}
