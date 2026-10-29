//go:build linux

package portforward

import (
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cedar2025/xboard-node/internal/nftsnapshot"
	"golang.org/x/sys/unix"
)

func TestNftCommandCaptureCannotBypassInventoryLimit(t *testing.T) {
	var output nftOutput
	_, err := io.Copy(&output, io.LimitReader(strings.NewReader(strings.Repeat("x", nftsnapshot.MaxOutput+1)), nftsnapshot.MaxOutput+1))
	if err != nftsnapshot.ErrTooLarge || !output.exceeded || output.buffer.Len() > nftsnapshot.MaxOutput {
		t.Fatal("nft stdout exceeded bounded inventory")
	}
}

func TestRootLockRejectsSymlinksAndPublicPermissions(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("preserved"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "symlink")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if fd, err := openLock(link); err == nil {
		unix.Close(fd)
		t.Fatal("followed a symlink lock")
	}
	public := filepath.Join(dir, "public")
	if err := os.WriteFile(public, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(public, 0644); err != nil {
		t.Fatal(err)
	}
	if fd, err := openLock(public); err == nil {
		unix.Close(fd)
		t.Fatal("accepted a public lock")
	}
	data, _ := os.ReadFile(target)
	if string(data) != "preserved" {
		t.Fatal("symlink target changed")
	}
}

func TestRootLockRejectsHardlinksAndSerializesDescriptors(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root ownership contract")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "lock")
	first, err := openLock(path)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(first)
	if err := unix.Flock(first, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	second, err := openLock(path)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(second)
	if err := unix.Flock(second, unix.LOCK_EX|unix.LOCK_NB); err != unix.EWOULDBLOCK && err != unix.EAGAIN {
		t.Fatal("distinct descriptors did not conflict", err)
	}
	if err := unix.Flock(first, unix.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	if err := unix.Flock(second, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal("released lease not reusable", err)
	}
	if err := os.Link(path, filepath.Join(dir, "hardlink")); err != nil {
		t.Fatal(err)
	}
	if fd, err := openLock(path); err == nil {
		unix.Close(fd)
		t.Fatal("accepted multiply-linked lock")
	}
}

func TestMissingNftReturnsActionableErrorWithoutRunningShell(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	_, err := nft("table inet harmless {}", "-f", "-")
	if err == nil || !strings.Contains(err.Error(), "install nftables") {
		t.Fatal(err)
	}
}

func TestUDPMetadataAndOwnedSocketExceptions(t *testing.T) {
	v4 := []byte("  sl  local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n 1: 0100007F:A5D2 00000000:0000 07 00000000:00000000 00:00000000 00000000 0 0 42 2\n")
	sockets, err := parseUDPSockets(v4, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(sockets) != 1 || sockets[0].address.String() != "127.0.0.1" || sockets[0].port != 42450 || sockets[0].inode != "42" {
		t.Fatal(sockets)
	}
	n := node()
	n.ListenIP = "127.0.0.1"
	r, _ := validate(n)
	if checkSockets(sockets, r, nil, nil) == nil {
		t.Fatal("other UDP service intercepted")
	}
	r.target = 42450
	if checkSockets(sockets, r, nil, map[string]bool{"42": true}) != nil {
		t.Fatal("own listener rejected")
	}
	if checkSockets(sockets, r, nil, map[string]bool{"41": true}) == nil {
		t.Fatal("foreign process on same target port exempted")
	}
	r.target = 42443
	if checkSockets(sockets, r, []int{42450}, map[string]bool{"42": true}) != nil {
		t.Fatal("owned old listener rejected")
	}
	if checkSockets(sockets, r, []int{42450}, nil) == nil {
		t.Fatal("foreign process reusing stale target port exempted")
	}
	v6 := []byte("sl local_address\n 1: 00000000000000000000000001000000:A5D2 00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 00000000 0 0 88 2\n")
	sockets, err = parseUDPSockets(v6, true)
	if err != nil {
		t.Fatal(err)
	}
	if sockets[0].address.String() != "::1" {
		t.Fatal(sockets)
	}
	if socketOverlaps(sockets[0], r) {
		t.Fatal("separate address families overlap")
	}
	dual := udpSocket{address: netip.IPv6Unspecified(), port: 42450, dual: true}
	if !socketOverlaps(dual, r) {
		t.Fatal("IPv6 wildcard may receive mapped IPv4")
	}
}

func TestLegacyNATRejectsUDPAndUnknownWhilePreservingTCP(t *testing.T) {
	for _, tc := range []struct {
		line   string
		reject bool
	}{
		{"-A PREROUTING -p udp --dport 53 -j DNAT --to-destination 192.0.2.1", true},
		{"-A PREROUTING -j REDIRECT --to-port 9999", true},
		{"-A PREROUTING -p tcp --dport 443 -j DNAT --to-destination 192.0.2.1", false},
		{"-A PREROUTING ! -p tcp -j REDIRECT --to-port 9999", true},
		{"-A PREROUTING -m comment --comment \"looks -p tcp inside comment\" -j DNAT --to-destination 192.0.2.1", true},
		{"-A PREROUTING -p udp -m comment --comment \"--protocol=tcp\" -j DNAT --to-destination 192.0.2.1", true},
		{"-A PREROUTING -m comment --comment \"-j\" DNAT", false},
		{"-A PREROUTING -m string --string \"--protocol=tcp\" --algo kmp -j DNAT --to-destination 192.0.2.1", true},
		{"-A PREROUTING -p udp -j ACCEPT", false},
		{"*nat\n:PREROUTING ACCEPT [0:0]\nCOMMIT", false},
	} {
		if got := checkLegacy([]byte(tc.line)) != nil; got != tc.reject {
			t.Fatalf("reject=%v for %s", got, tc.line)
		}
	}
}
