package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"golang.org/x/sys/windows"
)

// All these original objects remain owned through partial Start errors and until
// process exit. No adapter is ever reacquired by name or by returned JSON data.
type nativeOwner struct {
	file    *os.File
	module  windows.Handle
	dllPath string
	real    tun.Device
	pending identity
}

func newNativeOwner() nativeOwner { return nativeOwner{} }

var createNativeTUN = tun.CreateTUNWithRequestedGUID

func (o *nativeOwner) start(req request) (real tun.Device, ident identity, err error) {
	defer func() { ident = o.pending }()
	guid, err := windows.GUIDFromString(req.GUID)
	if err != nil {
		return nil, identity{}, err
	}
	rows, err := interfaceRows()
	if err != nil {
		return nil, identity{}, err
	}
	for _, row := range rows {
		if row.InterfaceGuid == guid || strings.EqualFold(windows.UTF16ToString(row.Alias[:]), req.Name) {
			return nil, identity{}, errors.New("adapter_conflict")
		}
	}
	// The GUID was absent before any SDK effect; retain this unresolved original
	// obligation even if CreateTUN or postflight validation returns an error.
	o.pending.GUID = guid.String()
	if err = o.pinDLL(req.DLLSHA256); err != nil {
		return nil, o.pending, err
	}
	o.real, err = createNativeTUN(req.Name, &guid, int(req.MTU))
	if o.real != nil {
		luidOwner, ok := o.real.(interface{ LUID() uint64 })
		if !ok {
			return nil, o.pending, errors.New("missing_native_luid")
		}
		o.pending.LUID = luidOwner.LUID()
	}
	if err != nil {
		return nil, o.pending, err
	}
	if err = o.verifyDLL(); err != nil {
		return nil, o.pending, err
	}
	row := windows.MibIfRow2{InterfaceLuid: o.pending.LUID}
	if err = windows.GetIfEntry2Ex(0, &row); err != nil {
		return nil, o.pending, err
	}
	o.pending.Index = row.InterfaceIndex
	if row.InterfaceGuid != guid || row.InterfaceIndex == 0 || row.InterfaceLuid == 0 {
		return nil, o.pending, errors.New("created_identity_mismatch")
	}
	byIndex := windows.MibIfRow2{InterfaceIndex: row.InterfaceIndex}
	if err = windows.GetIfEntry2Ex(0, &byIndex); err != nil {
		return nil, o.pending, err
	}
	if byIndex.InterfaceGuid != guid || byIndex.InterfaceLuid != row.InterfaceLuid {
		return nil, o.pending, errors.New("identity_lookup_disagrees")
	}
	return o.real, o.pending, nil
}
func (o *nativeOwner) pinDLL(expected string) error {
	name, _ := windows.UTF16PtrFromString("wintun.dll")
	var existing windows.Handle
	err := windows.GetModuleHandleEx(windows.GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, name, &existing)
	if err == nil || o.module != 0 {
		return errors.New("preexisting_wintun_module")
	}
	if !errors.Is(err, windows.ERROR_MOD_NOT_FOUND) {
		return err
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	path, err := filepath.Abs(filepath.Join(filepath.Dir(executable), "wintun.dll"))
	if err != nil {
		return err
	}
	path16, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	handle, err := windows.CreateFile(path16, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return err
	}
	o.file = os.NewFile(uintptr(handle), path)
	digest := sha256.New()
	if _, err = io.Copy(digest, o.file); err != nil {
		return err
	}
	if !strings.EqualFold(hex.EncodeToString(digest.Sum(nil)), expected) {
		return errors.New("wintun_digest_mismatch")
	}
	o.dllPath = path
	o.module, err = windows.LoadLibraryEx(path, 0, windows.LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR|windows.LOAD_LIBRARY_SEARCH_SYSTEM32)
	if err != nil {
		return err
	}
	return o.verifyDLL()
}
func (o *nativeOwner) verifyDLL() error {
	if o.module == 0 || o.file == nil {
		return errors.New("wintun_not_pinned")
	}
	name, _ := windows.UTF16PtrFromString("wintun.dll")
	var observed windows.Handle
	if err := windows.GetModuleHandleEx(windows.GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, name, &observed); err != nil {
		return err
	}
	if observed != o.module {
		return errors.New("wintun_handle_changed")
	}
	var path [32768]uint16
	n, err := windows.GetModuleFileName(o.module, &path[0], uint32(len(path)))
	if err != nil {
		return err
	}
	if n == 0 || n >= uint32(len(path)) || !strings.EqualFold(filepath.Clean(windows.UTF16ToString(path[:n])), filepath.Clean(o.dllPath)) {
		return errors.New("wintun_module_path_mismatch")
	}
	return nil
}
func (o *nativeOwner) closeTun() error {
	if o.real != nil {
		return o.real.Close()
	}
	return nil
}
func (o *nativeOwner) absent(expected identity) (bool, error) {
	if expected.GUID == "" && expected.LUID == 0 {
		return true, nil
	}
	rows, err := interfaceRows()
	if err != nil {
		return false, err
	}
	for _, row := range rows {
		if (expected.LUID != 0 && row.InterfaceLuid == expected.LUID) || (expected.GUID != "" && strings.EqualFold(row.InterfaceGuid.String(), expected.GUID)) {
			return false, nil
		}
	}
	return true, nil
}
func (o *nativeOwner) newBind(physical identity) (conn.Bind, error) {
	if err := verifyPhysical(physical); err != nil {
		return nil, err
	}
	return &physicalBind{StdNetBind: conn.NewStdNetBind().(*conn.StdNetBind), physical: physical}, nil
}
func verifyPhysical(expected identity) error {
	if expected.GUID == "" || expected.LUID == 0 || expected.Index == 0 {
		return errors.New("missing_physical_identity")
	}
	row := windows.MibIfRow2{InterfaceLuid: expected.LUID}
	if err := windows.GetIfEntry2Ex(0, &row); err != nil {
		return err
	}
	if row.InterfaceIndex != expected.Index || !strings.EqualFold(row.InterfaceGuid.String(), expected.GUID) || row.OperStatus != 1 || row.Type == 24 || row.Type == 131 {
		return errors.New("physical_identity_changed")
	}
	byIndex := windows.MibIfRow2{InterfaceIndex: expected.Index}
	if err := windows.GetIfEntry2Ex(0, &byIndex); err != nil {
		return err
	}
	if byIndex.InterfaceLuid != expected.LUID || byIndex.InterfaceGuid != row.InterfaceGuid {
		return errors.New("physical_lookup_disagrees")
	}
	return nil
}

type physicalBind struct {
	*conn.StdNetBind
	physical identity
}

func (b *physicalBind) Open(port uint16) (receive []conn.ReceiveFunc, actual uint16, err error) {
	if err = verifyPhysical(b.physical); err != nil {
		return nil, 0, err
	}
	receive, actual, err = b.StdNetBind.Open(port)
	if err != nil {
		return nil, 0, err
	}
	pinned := 0
	for _, pin := range []func(uint32, bool) error{b.BindSocketToInterface4, b.BindSocketToInterface6} {
		if err = pin(b.physical.Index, false); err == nil {
			pinned++
		} else if !errors.Is(err, windows.WSAEAFNOSUPPORT) {
			b.StdNetBind.Close()
			return nil, 0, err
		}
	}
	if pinned != len(receive) {
		b.StdNetBind.Close()
		return nil, 0, errors.New("not_all_open_sockets_pinned")
	}
	if err = verifyPhysical(b.physical); err != nil {
		b.StdNetBind.Close()
		return nil, 0, err
	}
	return receive, actual, nil
}

var iphlpapi = windows.NewLazySystemDLL("iphlpapi.dll")
var getIfTable2 = iphlpapi.NewProc("GetIfTable2")
var freeMibTable = iphlpapi.NewProc("FreeMibTable")

func interfaceRows() ([]windows.MibIfRow2, error) {
	type table struct {
		count uint32
		rows  [1]windows.MibIfRow2
	}
	var pointer *table
	code, _, _ := getIfTable2.Call(uintptr(unsafe.Pointer(&pointer)))
	if code != 0 {
		return nil, windows.Errno(code)
	}
	if pointer == nil {
		return nil, errors.New("nil_interface_table")
	}
	defer freeMibTable.Call(uintptr(unsafe.Pointer(pointer)))
	if pointer.count > 65536 {
		return nil, errors.New("interface_table_too_large")
	}
	return append([]windows.MibIfRow2(nil), unsafe.Slice(&pointer.rows[0], int(pointer.count))...), nil
}
