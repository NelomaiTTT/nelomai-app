package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"golang.org/x/sys/windows"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func installTestNativeFault() {
	original := createNativeTUN
	createNativeTUN = func(name string, guid *windows.GUID, mtu int) (tun.Device, error) {
		real, err := original(name, guid, mtu)
		if err != nil {
			return real, err
		}
		return &testWriteFault{Device: real}, nil
	}
}
func testDLLSHA(t *testing.T) string {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(filepath.Dir(executable), "wintun.dll"))
	if err != nil {
		t.Fatal("trusted x64 wintun.dll must be beside test executable: ", err)
	}
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}
func testPhysical(t *testing.T) (identity, string) {
	t.Helper()
	rows, err := interfaceRows()
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		if row.OperStatus != 1 || row.Type == 24 || row.Type == 131 {
			continue
		}
		network, err := net.InterfaceByIndex(int(row.InterfaceIndex))
		if err != nil {
			continue
		}
		addresses, err := network.Addrs()
		if err != nil {
			continue
		}
		for _, address := range addresses {
			ip, _, err := net.ParseCIDR(address.String())
			if err == nil && ip.To4() != nil && !ip.IsLoopback() {
				return identity{GUID: row.InterfaceGuid.String(), LUID: row.InterfaceLuid, Index: row.InterfaceIndex}, ip.String()
			}
		}
	}
	t.Fatal("no up physical IPv4 interface for local pinned crypto peers")
	return identity{}, ""
}
func testTransport(t *testing.T, ident identity) (func([]byte), func() []byte, func()) {
	t.Helper()
	script := fmt.Sprintf(`$ErrorActionPreference='Stop';
 if (Get-NetIPAddress -AddressFamily IPv4 | Where-Object IPAddress -eq '198.18.240.1') { throw 'proof address already exists' };
 if (Get-NetRoute -AddressFamily IPv4 | Where-Object DestinationPrefix -eq '198.18.240.0/30') { throw 'proof route already exists' };
 Set-NetIPInterface -InterfaceIndex %d -AddressFamily IPv4 -Dhcp Disabled -DadTransmits 0;
 New-NetIPAddress -InterfaceIndex %d -AddressFamily IPv4 -IPAddress '198.18.240.1' -PrefixLength 30 -PolicyStore ActiveStore | Out-Null`, ident.Index, ident.Index)
	if output, err := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script).CombinedOutput(); err != nil {
		t.Fatalf("configure own test interface: %v %s", err, output)
	}
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("198.18.240.1")})
	if err != nil {
		t.Fatal(err)
	}
	send := func(payload []byte) {
		t.Helper()
		if _, err := socket.WriteToUDP(payload, &net.UDPAddr{IP: net.ParseIP("198.18.240.2"), Port: 45123}); err != nil {
			t.Fatal(err)
		}
	}
	receive := func() []byte {
		t.Helper()
		socket.SetReadDeadline(time.Now().Add(10 * time.Second))
		buffer := make([]byte, 2048)
		n, source, err := socket.ReadFromUDP(buffer)
		if err != nil {
			t.Fatal(err)
		}
		if source.IP.String() != "198.18.240.2" || source.Port != 45123 {
			t.Fatal("unexpected peer UDP tuple")
		}
		return append([]byte(nil), buffer[:n]...)
	}
	return send, receive, func() { socket.Close() }
}
