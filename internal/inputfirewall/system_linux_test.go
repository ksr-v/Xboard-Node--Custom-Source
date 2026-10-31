//go:build linux

package inputfirewall

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestLeaseRejectsSymlinkPublicAndHardlinkedFiles(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("preserved"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "symlink")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if fd, err := openLease(link); err == nil {
		unix.Close(fd)
		t.Fatal("followed symlink")
	}
	public := filepath.Join(dir, "public")
	if err := os.WriteFile(public, nil, 0644); err != nil {
		t.Fatal(err)
	}
	if fd, err := openLease(public); err == nil {
		unix.Close(fd)
		t.Fatal("accepted public lock")
	}
	if err := os.Link(target, filepath.Join(dir, "hardlink")); err != nil {
		t.Fatal(err)
	}
	if fd, err := openLease(target); err == nil {
		unix.Close(fd)
		t.Fatal("accepted hardlink")
	}
	data, _ := os.ReadFile(target)
	if string(data) != "preserved" {
		t.Fatal("lock target altered")
	}
}

func TestProcessLeaseExcludesOtherControllerAndIsRetained(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root-owned fixture lock")
	}
	path := filepath.Join(t.TempDir(), "lease")
	a := &linuxSystem{fd: -1, lockPath: path}
	b := &linuxSystem{fd: -1, lockPath: path}
	if err := a.acquire(); err != nil {
		t.Fatal(err)
	}
	defer unix.Close(a.fd)
	if err := a.acquire(); err != nil {
		t.Fatal("same controller lost its lease", err)
	}
	if b.acquire() != errLease {
		t.Fatal("second controller acquired process lease")
	}
	if unix.Flock(a.fd, unix.LOCK_UN) != nil {
		t.Fatal("fixture unlock failed")
	}
	if err := b.acquire(); err != nil {
		t.Fatal(err)
	}
	defer unix.Close(b.fd)
}

func TestTrustedToolPreservesMulticallAliasAndRejectsWritablePath(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("production binaries must be root owned")
	}
	path, err := trustedTool("sh")
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(path) != "sh" {
		t.Fatal("multi-call alias resolved away", path)
	}
	dir := t.TempDir()
	name := "input-firewall-untrusted-fixture"
	file := filepath.Join(dir, name)
	if err := os.WriteFile(file, []byte("fixture"), 0777); err != nil {
		t.Fatal(err)
	}
	// WriteFile's creation mode is filtered by the caller's umask. Set the
	// intended unsafe permissions explicitly on hosts using the normal 022.
	if err := os.Chmod(file, 0777); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	if _, err := trustedTool(name); err != errUnavailable {
		t.Fatal("writable executable accepted", err)
	}
}

func fakeLinuxTools() (*linuxSystem, map[string]string) {
	tools := make(map[string]string)
	for _, base := range []string{"iptables", "ip6tables"} {
		for _, suffix := range []string{"-nft", "-legacy", ""} {
			for _, helper := range []string{"", "-save", "-restore"} {
				kind := "nf_tables"
				if suffix == "-legacy" {
					kind = "legacy"
				}
				tools[base+suffix+helper] = kind
			}
		}
	}
	s := &linuxSystem{fd: -1, nftFamilies: map[int]bool{4: true, 6: true}, legacy: func(int) bool { return true }, ipv6: func() bool { return true }}
	s.lookup = func(name string) (string, error) {
		if _, ok := tools[name]; !ok {
			return "", errUnavailable
		}
		return "/trusted/" + name, nil
	}
	s.run = func(path string, args []string, input string) ([]byte, error) {
		kind, ok := tools[filepath.Base(path)]
		if !ok {
			return nil, errOperation
		}
		if len(args) != 1 || args[0] != "--version" || input != "" {
			return nil, errOperation
		}
		return []byte(filepath.Base(path) + " v1.8.9 (" + kind + ")\n"), nil
	}
	return s, tools
}

func TestDiscoverBothFamiliesAndBackendsDeduplicatesAliases(t *testing.T) {
	s, _ := fakeLinuxTools()
	found, err := s.discover()
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 4 {
		t.Fatal("not four unique backend/families", found)
	}
	seen := make(map[string]bool)
	for _, b := range found {
		if seen[b.key()] {
			t.Fatal("duplicate alias", b)
		}
		seen[b.key()] = true
	}
}

func TestDiscoverMissingActiveBackendAndMismatchedHelpersRefuses(t *testing.T) {
	for _, name := range []string{"missing-legacy", "helper-mismatch", "missing-restore", "unknown-version"} {
		t.Run(name, func(t *testing.T) {
			s, tools := fakeLinuxTools()
			switch name {
			case "missing-legacy":
				for tool := range tools {
					if strings.Contains(tool, "legacy") {
						delete(tools, tool)
					}
				}
			case "helper-mismatch":
				tools["iptables-nft-save"] = "legacy"
			case "missing-restore":
				delete(tools, "iptables-nft-restore")
			case "unknown-version":
				tools["iptables-nft"] = "unknown"
			}
			if _, err := s.discover(); err != errUnavailable {
				t.Fatal("unsafe backend accepted", err)
			}
		})
	}
}

func TestDiscoverInactiveLegacyAndDisabledIPv6AreNotActivated(t *testing.T) {
	s, _ := fakeLinuxTools()
	s.legacy = func(int) bool { return false }
	s.ipv6 = func() bool { return false }
	s.nftFamilies = map[int]bool{4: true}
	found, err := s.discover()
	if err != nil || len(found) != 1 || found[0].key() != "4/nft" {
		t.Fatal(found, err)
	}
}

func TestDiscoverLegacyOnlyDoesNotActivateInstalledNFTHook(t *testing.T) {
	s, _ := fakeLinuxTools()
	s.nftFamilies = map[int]bool{}
	found, err := s.discover()
	if err != nil || len(found) != 2 {
		t.Fatal(found, err)
	}
	for _, b := range found {
		if b.kind != "legacy" {
			t.Fatal("installed but inactive nft backend was selected", b)
		}
	}
}

func TestDiscoverEmptyHostBootstrapsOnlyOneHookPerFamily(t *testing.T) {
	s, _ := fakeLinuxTools()
	s.nftFamilies = map[int]bool{}
	s.legacy = func(int) bool { return false }
	found, err := s.discover()
	if err != nil || len(found) != 2 {
		t.Fatal(found, err)
	}
	for _, b := range found {
		if b.kind != "nft" {
			t.Fatal("empty host activated multiple filter implementations", b)
		}
	}
}

func TestNativeInspectionAndRestoreCommandsAreBoundedAndShellFree(t *testing.T) {
	s, _ := fakeLinuxTools()
	calls := 0
	s.lookup = func(name string) (string, error) {
		if name != "nft" {
			t.Fatal(name)
		}
		return "/trusted/nft", nil
	}
	s.run = func(path string, args []string, input string) ([]byte, error) {
		calls++
		if path == "/trusted/nft" && strings.Join(args, " ") == "--version" {
			return []byte("nftables v1.0.9 (Old Doc Yak #3)"), nil
		}
		if path != "/trusted/nft" || strings.Join(args, " ") != "-j -nn list ruleset" || input != "" {
			t.Fatal("unexpected nft operation", path, args)
		}
		return []byte(`{"nftables":[{"chain":{"family":"ip","table":"filter","name":"INPUT","type":"filter","hook":"input","prio":0}}]}`), nil
	}
	if err := s.checkNative(); err != nil || !s.nftFamilies[4] || calls != 2 {
		t.Fatal(err)
	}
	s.run = func(path string, args []string, input string) ([]byte, error) {
		if path != "/trusted/iptables-nft-restore" || strings.Join(args, " ") != "--noflush --wait 2" || input != "*filter\nCOMMIT\n" {
			t.Fatal("restore changed scope", path, args, input)
		}
		return nil, nil
	}
	if err := s.apply(backend{restore: "/trusted/iptables-nft-restore"}, "*filter\nCOMMIT\n"); err != nil {
		t.Fatal(err)
	}
}

func TestEmptyNftJSONGuardBeforeInputManagement(t *testing.T) {
	for name, response := range map[string]struct {
		json, tables string
		failTables   bool
		want         error
		calls        int
	}{
		"confirmed-empty":          {"", "", false, nil, 2},
		"confirmed-whitespace":     {" \n", "\t\n", false, nil, 2},
		"populated-tables":         {"", "table ip existing\n", false, errRules, 2},
		"failed-table-query":       {"", "", true, errRules, 2},
		"bare-null-is-not-empty":   {"null", "", false, errRules, 1},
		"legacy-null-confirmed":    {`{"nftables":null}`, "", false, nil, 2},
		"legacy-null-populated":    {`{"nftables":null}`, "table ip existing\n", false, errRules, 2},
		"missing-key-is-not-empty": {"{}", "", false, errRules, 1},
		"malformed-is-not-empty":   {"not JSON", "", false, errRules, 1},
	} {
		t.Run(name, func(t *testing.T) {
			s, _ := fakeLinuxTools()
			calls := 0
			s.lookup = func(string) (string, error) { return "/trusted/nft", nil }
			s.run = func(path string, args []string, input string) ([]byte, error) {
				calls++
				if input != "" {
					t.Fatal("inventory supplied mutation input")
				}
				switch strings.Join(args, " ") {
				case "--version":
					return []byte("nftables v1.0.9"), nil
				case "-j -nn list ruleset":
					return []byte(response.json), nil
				case "list tables":
					if response.failTables {
						return nil, errors.New("private diagnostic")
					}
					return []byte(response.tables), nil
				default:
					t.Fatal("unexpected inventory command", args)
					return nil, errOperation
				}
			}
			if err := s.checkNative(); err != response.want || calls != response.calls+1 {
				t.Fatal("guard result", err, calls)
			}
		})
	}
}

func TestExactOldNFTSelectsLegacyWithoutChangingDefaultNFTAlias(t *testing.T) {
	s, _ := fakeLinuxTools()
	s.legacyNFT = true
	s.nftFamilies = map[int]bool{}
	s.legacy = func(int) bool { return false }
	found, err := s.discover()
	if err != nil || len(found) != 2 {
		t.Fatal(found, err)
	}
	for _, b := range found {
		if b.kind != "legacy" || !strings.HasSuffix(b.command, "-legacy") {
			t.Fatal("old nft activated unused NFT filter", b)
		}
	}
}

func TestOldNFTMissingLegacyToolsRefusesBeforeMutation(t *testing.T) {
	s, tools := fakeLinuxTools()
	s.legacyNFT = true
	s.nftFamilies = map[int]bool{}
	for name := range tools {
		if strings.Contains(name, "legacy") {
			delete(tools, name)
		}
	}
	if _, err := s.discover(); err != errUnavailable {
		t.Fatal("missing explicit legacy silently used default NFT", err)
	}
}

func TestKnownOldActiveNFTInputIsRejectedBeforeMutation(t *testing.T) {
	s, _ := fakeLinuxTools()
	s.lookup = func(string) (string, error) { return "/trusted/nft", nil }
	s.run = func(_ string, args []string, input string) ([]byte, error) {
		if input != "" {
			t.Fatal("native inventory attempted write")
		}
		switch strings.Join(args, " ") {
		case "--version":
			return []byte("nftables v0.9.0 (Fearless Fosdick)"), nil
		case "-j -nn list ruleset":
			return []byte(`{"nftables":[{"chain":{"family":"ip","table":"filter","name":"INPUT","type":"filter","hook":"input","prio":0}}]}`), nil
		default:
			t.Fatal(args)
			return nil, errOperation
		}
	}
	if err := s.checkNative(); err != errLegacyNFT {
		t.Fatal("old NFT compatibility hook silently managed", err)
	}
}

func TestLegacyNFTFeaturePolicyRecognizesOnlyConfirmedVersion(t *testing.T) {
	for text, want := range map[string]bool{"nftables v0.9.0 (Fearless Fosdick)": true, "nftables v1.0.9": false, "nftables v0.9.01": false, "nftables v0.9.0-custom": false, "unknown v0.9.0": false, "": false} {
		if isLegacyNFT([]byte(text)) != want {
			t.Fatal("version policy guessed", text)
		}
	}
}

func TestCommandOutputLimit(t *testing.T) {
	var b limitedOutput
	if _, err := b.Write(bytes.Repeat([]byte("x"), maxOutput)); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Write([]byte("x")); err != errOperation || !b.exceeded || b.Len() != maxOutput {
		t.Fatal("output not bounded")
	}
	var streamed limitedOutput
	_, err := io.Copy(&streamed, io.LimitReader(strings.NewReader(strings.Repeat("x", maxOutput+1)), maxOutput+1))
	if err != errOperation || !streamed.exceeded || streamed.Len() > maxOutput {
		t.Fatal("io.Copy bypassed output limit")
	}
}

// This fixture executes only this test binary, never a host firewall command.
func TestCommandFixtureProcess(t *testing.T) {
	if os.Getenv("INPUT_FIREWALL_COMMAND_FIXTURE") != "1" {
		return
	}
	mode := os.Args[len(os.Args)-1]
	switch mode {
	case "failure":
		fmt.Fprintln(os.Stderr, "private firewall rule password=secret")
		os.Exit(3)
	case "overflow":
		_, _ = os.Stdout.Write(bytes.Repeat([]byte("x"), maxOutput+1))
		os.Exit(0)
	case "timeout":
		time.Sleep(30 * time.Second)
		os.Exit(0)
	default:
		os.Exit(4)
	}
}

func TestCommandFailureOverflowTimeoutNeverExposeDiagnostics(t *testing.T) {
	t.Setenv("INPUT_FIREWALL_COMMAND_FIXTURE", "1")
	path, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"failure", "overflow", "timeout"} {
		t.Run(mode, func(t *testing.T) {
			start := time.Now()
			data, err := runCommand(path, []string{"-test.run=^TestCommandFixtureProcess$", "--", mode}, "")
			if !errors.Is(err, errOperation) || len(data) != 0 || strings.Contains(err.Error(), "secret") {
				t.Fatalf("command fixture: safe_error=%t data_bytes=%d elapsed_ms=%d", errors.Is(err, errOperation), len(data), time.Since(start).Milliseconds())
			}
			want := map[string]string{"failure": "command exited with code 3", "overflow": "command output limit exceeded", "timeout": "command timed out"}[mode]
			if !strings.Contains(err.Error(), want) || strings.Contains(err.Error(), path) {
				t.Fatal("command failure classification missing or private path exposed", err)
			}
			if time.Since(start) > 8*time.Second {
				t.Fatal("command deadline not enforced")
			}
		})
	}
}

func TestCommandStartFailuresUseFixedPrivateClassifications(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct {
		name, classification string
		create               bool
	}{
		{"private-password-secret-missing", "command executable not found", false},
		{"private-password-secret-denied", "command execution permission denied", true},
	} {
		path := filepath.Join(dir, tc.name)
		if tc.create {
			if err := os.WriteFile(path, []byte("private-content-secret"), 0600); err != nil {
				t.Fatal(err)
			}
		}
		data, err := runCommand(path, nil, "")
		if !errors.Is(err, errOperation) || len(data) != 0 || !strings.Contains(err.Error(), tc.classification) || strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), dir) {
			t.Fatal("unsafe command start diagnostics", err)
		}
	}
}
