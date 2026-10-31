//go:build linux

package firewall

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// Socket integration uses the same explicit private namespace contract as the
// packet tests. It never writes a host /run endpoint or changes firewall rules.
func privateSocketTestDirectory(t *testing.T) string {
	t.Helper()
	host := os.Getenv("XB_NETNS_HOST_ID")
	current, err := os.Readlink("/proc/self/ns/net")
	if os.Geteuid() != 0 || os.Getenv("XB_NETNS_PRIVATE_RUN") != "1" || host == "" || err != nil || host == current {
		t.Skip("private root network and mount namespaces are required for socket integration")
	}
	var stat unix.Statfs_t
	if unix.Statfs("/run", &stat) != nil || stat.Type != unix.TMPFS_MAGIC {
		t.Fatal("private /run tmpfs required")
	}
	dir, err := os.MkdirTemp("/run", "xb-firewall-control-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func TestControlPrivateSocketLifecycle(t *testing.T) {
	dir := privateSocketTestDirectory(t)
	path := filepath.Join(dir, "private", "control.sock")
	provider := new(controlFixture)
	server, err := startControlAt(path, provider)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	info, err := os.Lstat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("socket is not private")
	}
	response, err := QueryControl(path, "ports")
	if err != nil || len(response.Report.Ports) != 1 || response.Report.Ports[0].ListenPort != 8443 {
		t.Fatalf("live report: %+v %v", response, err)
	}
	if other, err := startControlAt(path, new(controlFixture)); err == nil {
		other.Close()
		t.Fatal("stole live socket lease")
	}
	if _, err := QueryControl(path, "ports"); err != nil {
		t.Fatal("failed duplicate startup damaged active socket")
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("owned endpoint survived close")
	}
	if _, err := QueryControl(path, "status"); err == nil {
		t.Fatal("stopped server reported runtime data")
	}
}

func TestControlUnknownObjectsAndUnsafeDirectoriesArePreserved(t *testing.T) {
	dir := privateSocketTestDirectory(t)
	for _, kind := range []string{"regular", "symlink", "public-directory", "unknown-lock"} {
		t.Run(kind, func(t *testing.T) {
			parent := filepath.Join(dir, kind)
			if err := os.Mkdir(parent, 0700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(parent, "control.sock")
			switch kind {
			case "regular":
				if err := os.WriteFile(path, []byte("foreign object"), 0600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Symlink("foreign-target", path); err != nil {
					t.Fatal(err)
				}
			case "public-directory":
				if err := os.Chmod(parent, 0755); err != nil {
					t.Fatal(err)
				}
			case "unknown-lock":
				if err := os.WriteFile(filepath.Join(parent, "control.lock"), []byte("foreign lock"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if server, err := startControlAt(path, new(controlFixture)); err == nil {
				server.Close()
				t.Fatal("unsafe endpoint accepted")
			}
			if kind == "regular" {
				data, _ := os.ReadFile(path)
				if string(data) != "foreign object" {
					t.Fatal("unknown object overwritten")
				}
			}
			if kind == "symlink" {
				target, _ := os.Readlink(path)
				if target != "foreign-target" {
					t.Fatal("symlink replaced")
				}
			}
			if kind == "unknown-lock" {
				data, _ := os.ReadFile(filepath.Join(parent, "control.lock"))
				if string(data) != "foreign lock" {
					t.Fatal("unknown lock overwritten")
				}
			}
		})
	}
}

func TestControlKnownStaleSocketRecoversAndClosePreservesReplacement(t *testing.T) {
	dir := privateSocketTestDirectory(t)
	path := filepath.Join(dir, "private", "control.sock")
	server, err := startControlAt(path, new(controlFixture))
	if err != nil {
		t.Fatal(err)
	}
	// Simulate process exit: the listener and lock close without endpoint cleanup.
	_ = server.listener.Close()
	_ = server.lock.Close()
	recovered, err := startControlAt(path, new(controlFixture))
	if err != nil {
		t.Fatal("known stale endpoint was not reclaimed:", err)
	}
	defer recovered.Close()
	if _, err := QueryControl(path, "status"); err != nil {
		t.Fatal(err)
	}
	// An endpoint replaced by another root actor is no longer ours to unlink.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	_ = recovered.Close()
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "replacement" {
		t.Fatal("close removed an unknown replacement")
	}
}

func TestControlDoesNotReclaimActiveSocketWithoutLease(t *testing.T) {
	dir := privateSocketTestDirectory(t)
	path := filepath.Join(dir, "control.sock")
	if err := os.WriteFile(filepath.Join(dir, "control.lock"), []byte(controlMarker), 0600); err != nil {
		t.Fatal(err)
	}
	foreign, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer foreign.Close()
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if server, err := startControlAt(path, new(controlFixture)); err == nil {
		server.Close()
		t.Fatal("active endpoint was reclaimed")
	} else if !strings.Contains(err.Error(), "already active") {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); err != nil {
		t.Fatal("foreign endpoint removed")
	}
}
