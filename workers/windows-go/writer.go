package main

import (
	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"io"
	"os"
	"sync"
)

// The staged Windows dispatcher holds routeMu.RLock through one synchronous
// call. This gate also fences Close and guarantees NativeTun's one-Write-caller
// contract, without dropping a packet simply because another caller is writing.
type serializedWriter struct {
	mu     sync.Mutex
	closed bool
	device tun.Device
}

func newRedundantRealWriter(real tun.Device) (redundantRealWriter, error) {
	return &serializedWriter{device: real}, nil
}
func (w *serializedWriter) WritePacket(packet []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return os.ErrClosed
	}
	count, err := w.device.Write([][]byte{packet}, 0)
	if err != nil {
		return err
	}
	if count != 1 {
		return io.ErrShortWrite
	}
	return nil
}
func (w *serializedWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.closed = true
	return nil
}
