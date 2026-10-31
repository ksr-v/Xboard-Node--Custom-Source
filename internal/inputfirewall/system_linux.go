//go:build linux

package inputfirewall

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cedar2025/xboard-node/internal/nftsnapshot"
	"golang.org/x/sys/unix"
)

type linuxSystem struct {
	fd              int
	lockPath        string
	nft             string
	nftFamilies     map[int]bool
	legacyNFT       bool
	inventoryNative string
	lookup          func(string) (string, error)
	run             func(string, []string, string) ([]byte, error)
	legacy          func(int) bool
	ipv6            func() bool
}

func newSystem() system {
	return &linuxSystem{fd: -1, lockPath: "/run/xboard-node-managed-input.lock", lookup: trustedTool, run: runCommand}
}

func (s *linuxSystem) acquire() error {
	if s.fd >= 0 {
		return nil
	}
	if os.Geteuid() != 0 {
		return errUnavailable
	}
	// The fixed production parent is root-owned and cannot be renamed by an
	// unprivileged process. Tests use a private directory in a mount namespace.
	info, err := os.Lstat(filepath.Dir(s.lockPath))
	if err != nil || !info.IsDir() || info.Mode().Perm()&0022 != 0 {
		return errUnavailable
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != 0 {
		return errUnavailable
	}
	fd, err := openLease(s.lockPath)
	if err != nil {
		return errUnavailable
	}
	if unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB) != nil {
		unix.Close(fd)
		return errLease
	}
	s.fd = fd
	return nil
}

func openLease(path string) (int, error) {
	fd, err := unix.Open(path, unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return -1, errUnavailable
	}
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Uid != 0 || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&07777 != 0600 || st.Nlink != 1 {
		unix.Close(fd)
		return -1, errUnavailable
	}
	return fd, nil
}

func trustedTool(name string) (string, error) {
	path, err := exec.LookPath(name)
	if err != nil || !filepath.IsAbs(path) {
		return "", errUnavailable
	}
	if err := trustedExecutable(path); err != nil {
		return "", err
	}
	// xtables tools commonly share a multi-call binary. Preserve argv[0]'s
	// alias after verifying the resolved executable and its immutable parents.
	return path, nil
}

// Resolve one component at a time so writable ancestors of intermediate
// symlinks cannot disappear from the check. Merely checking the initial and
// fully resolved paths would miss a multi-hop alternative through /tmp.
func trustedExecutable(path string) error {
	if !filepath.IsAbs(path) {
		return errUnavailable
	}
	root, err := os.Lstat("/")
	if err != nil || !root.IsDir() || root.Mode().Perm()&0022 != 0 {
		return errUnavailable
	}
	rootStat, ok := root.Sys().(*syscall.Stat_t)
	if !ok || rootStat.Uid != 0 {
		return errUnavailable
	}
	pending := strings.Split(path, "/")
	current := "/"
	links := 0
	for len(pending) > 0 {
		part := pending[0]
		pending = pending[1:]
		if part == "" || part == "." {
			continue
		}
		if part == ".." {
			current = filepath.Dir(current)
			continue
		}
		next := filepath.Join(current, part)
		info, err := os.Lstat(next)
		if err != nil {
			return errUnavailable
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 0 {
			return errUnavailable
		}
		if info.Mode()&os.ModeSymlink != 0 {
			links++
			if links > 40 {
				return errUnavailable
			}
			target, err := os.Readlink(next)
			if err != nil {
				return errUnavailable
			}
			if filepath.IsAbs(target) {
				current = "/"
			}
			pending = append(strings.Split(target, "/"), pending...)
			continue
		}
		if info.Mode().Perm()&0022 != 0 {
			return errUnavailable
		}
		if info.IsDir() {
			current = next
			continue
		}
		if len(pending) != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
			return errUnavailable
		}
		return nil
	}
	return errUnavailable
}

// Inspect all nft INPUT filter base chains before installing any permission.
// An ACCEPT in a separate compatibility chain cannot override their DROP.
func (s *linuxSystem) checkNative() error {
	s.inventoryNative = "unknown"
	s.nftFamilies = make(map[int]bool)
	s.legacyNFT = false
	path, err := s.lookup("nft")
	if err != nil {
		return errUnavailable
	}
	version, err := s.run(path, []string{"--version"}, "")
	if err != nil {
		return safeError(err)
	}
	s.legacyNFT = isLegacyNFT(version)
	data, err := nftsnapshot.Read(func(args ...string) ([]byte, error) { return s.run(path, args, "") })
	if err != nil {
		if errors.Is(err, nftsnapshot.ErrUnconfirmedEmpty) || errors.Is(err, nftsnapshot.ErrTooLarge) {
			return errRules
		}
		return safeError(err)
	}
	if err = inspectNft(data); err != nil {
		if errors.Is(err, errUnsupported) {
			s.inventoryNative = "present"
		}
		return err
	}
	s.inventoryNative = "absent"
	s.nft = path
	s.nftFamilies = make(map[int]bool)
	var top struct {
		Nftables []struct {
			Chain *struct{ Family, Table, Name, Hook string }
		}
	}
	if json.Unmarshal(data, &top) != nil {
		return errRules
	}
	for _, row := range top.Nftables {
		if row.Chain == nil {
			continue
		}
		c := row.Chain
		if c.Table == "filter" && c.Name == "INPUT" && c.Hook == "input" {
			if c.Family == "ip" {
				s.nftFamilies[4] = true
			}
			if c.Family == "ip6" {
				s.nftFamilies[6] = true
			}
		}
	}
	if s.legacyNFT && len(s.nftFamilies) > 0 {
		return errLegacyNFT
	}
	return nil
}

func platformInventory() InventoryStatus {
	result := InventoryStatus{NativeNFT: "unknown", Issues: []string{}}
	s := newSystem().(*linuxSystem)
	_, nftErr := s.lookup("nft")
	result.NFTToolPresent = nftErr == nil
	for _, name := range []string{"iptables-nft", "ip6tables-nft"} {
		if _, err := s.lookup(name); err == nil {
			result.IPTablesNFTPresent = true
		}
	}
	for _, name := range []string{"iptables-legacy", "ip6tables-legacy"} {
		if _, err := s.lookup(name); err == nil {
			result.IPTablesLegacyPresent = true
		}
	}
	if err := s.checkNative(); err != nil {
		result.Issues = append(result.Issues, safeError(err).Error())
	}
	result.NativeNFT = s.inventoryNative
	return result
}

func isLegacyNFT(version []byte) bool {
	if len(version) > 4096 {
		return false
	}
	parts := strings.Fields(string(version))
	return len(parts) >= 2 && parts[0] == "nftables" && parts[1] == "v0.9.0"
}

func (s *linuxSystem) discover() ([]backend, error) {
	var result []backend
	seen := make(map[string]bool)
	legacy := s.legacy
	if legacy == nil {
		v4, err4 := legacyFilter("/proc/net/ip_tables_names")
		v6, err6 := legacyFilter("/proc/net/ip6_tables_names")
		if err4 != nil || err6 != nil {
			return nil, errUnavailable
		}
		legacy = func(family int) bool {
			if family == 6 {
				return v6
			}
			return v4
		}
	}
	legacyActive := map[int]bool{4: legacy(4), 6: legacy(6)}
	ipv6Enabled := true
	if s.ipv6 != nil {
		ipv6Enabled = s.ipv6()
	} else {
		_, err := os.Stat("/proc/net/if_inet6")
		ipv6Enabled = err == nil
	}
	for _, family := range []int{4, 6} {
		if family == 6 && !ipv6Enabled && !legacyActive[6] && !s.nftFamilies[6] {
			continue
		}
		base := "iptables"
		if family == 6 {
			base = "ip6tables"
		}
		candidates := []string{base + "-nft", base, base + "-legacy"}
		// nft 0.9.0 cannot serialize xt compatibility expressions reliably.
		// Do not create an unused NFT filter hook that would poison the next
		// inventory; explicit legacy tools leave global alternatives unchanged.
		forceLegacy := s.legacyNFT && !s.nftFamilies[family]
		if forceLegacy {
			candidates = []string{base + "-legacy"}
		}
		for _, name := range candidates {
			command, err := s.lookup(name)
			if err != nil {
				continue
			}
			data, err := s.run(command, []string{"--version"}, "")
			if err != nil {
				return nil, safeError(err)
			}
			kind := versionKind(data)
			if kind == "" {
				return nil, errUnavailable
			}
			if forceLegacy && kind != "legacy" {
				return nil, errUnavailable
			}
			// Existing hooks decide the write scope. An installed nft tool is
			// not evidence that the nft hook participates in a legacy-only host.
			if (legacyActive[family] || s.nftFamilies[family]) && ((kind == "nft" && !s.nftFamilies[family]) || (kind == "legacy" && !legacyActive[family])) {
				continue
			}
			key := backend{family: family, kind: kind}.key()
			if seen[key] {
				continue
			}
			// Do not activate a previously unused legacy filter hook merely
			// because its tools happen to be installed alongside nftables.
			if kind == "legacy" && !legacyActive[family] && (s.nftFamilies[family] || seen[backend{family: family, kind: "nft"}.key()]) {
				continue
			}
			save, err := s.lookup(name + "-save")
			if err != nil {
				return nil, errUnavailable
			}
			restore, err := s.lookup(name + "-restore")
			if err != nil {
				return nil, errUnavailable
			}
			for _, tool := range []string{save, restore} {
				version, err := s.run(tool, []string{"--version"}, "")
				if err != nil || versionKind(version) != kind {
					return nil, errUnavailable
				}
			}
			seen[key] = true
			result = append(result, backend{family: family, kind: kind, command: command, save: save, restore: restore})
			// With no filter hook yet, bootstrap one available backend, without
			// changing system alternatives or activating a second empty hook.
			if !legacyActive[family] && !s.nftFamilies[family] {
				break
			}
		}
		if legacyActive[family] && !seen[backend{family: family, kind: "legacy"}.key()] {
			return nil, errUnavailable
		}
		if s.nftFamilies[family] && !seen[backend{family: family, kind: "nft"}.key()] {
			return nil, errUnavailable
		}
		if forceLegacy && !seen[backend{family: family, kind: "legacy"}.key()] {
			return nil, errUnavailable
		}
	}
	return result, nil
}

func legacyFilter(path string) (bool, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil || len(data) > 1<<16 {
		return false, errUnavailable
	}
	for _, line := range strings.Fields(string(data)) {
		if line == "filter" {
			return true, nil
		}
	}
	return false, nil
}

func versionKind(data []byte) string {
	if len(data) > 4096 {
		return ""
	}
	v := strings.ToLower(strings.TrimSpace(string(data)))
	if !strings.Contains(v, "tables") || !strings.Contains(v, " v1.") {
		return ""
	}
	if strings.Contains(v, "(nf_tables)") {
		return "nft"
	}
	if strings.Contains(v, "(legacy)") || !strings.Contains(v, "(") {
		return "legacy"
	}
	return ""
}

func (s *linuxSystem) read(b backend) ([]byte, error) {
	return s.run(b.save, []string{"-t", "filter"}, "")
}
func (s *linuxSystem) apply(b backend, input string) error {
	if len(input) > maxOutput {
		return errRules
	}
	_, err := s.run(b.restore, []string{"--noflush", "--wait", "2"}, input)
	return err
}

type limitedOutput struct {
	buffer   bytes.Buffer
	exceeded bool
}

func (b *limitedOutput) Len() int      { return b.buffer.Len() }
func (b *limitedOutput) Bytes() []byte { return b.buffer.Bytes() }

func (b *limitedOutput) Write(data []byte) (int, error) {
	if len(data) > maxOutput-b.Len() {
		b.exceeded = true
		return 0, errOperation
	}
	return b.buffer.Write(data)
}

func runCommand(path string, args []string, input string) ([]byte, error) {
	timeout := 5 * time.Second
	if len(args) == 1 && args[0] == "--version" {
		timeout = 2 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.WaitDelay = 250 * time.Millisecond
	cmd.Stdin = strings.NewReader(input)
	var output limitedOutput
	cmd.Stdout = &output
	cmd.Stderr = io.Discard // Host rules, command paths and diagnostic text are private.
	err := cmd.Run()
	if ctx.Err() != nil {
		return nil, phaseError("command timed out", errOperation)
	}
	if output.exceeded {
		return nil, phaseError("command output limit exceeded", errOperation)
	}
	if err != nil {
		var exited *exec.ExitError
		switch {
		case errors.As(err, &exited):
			return nil, phaseError("command exited with code "+strconv.Itoa(exited.ExitCode()), errOperation)
		case errors.Is(err, exec.ErrNotFound), errors.Is(err, os.ErrNotExist):
			return nil, phaseError("command executable not found", errOperation)
		case errors.Is(err, os.ErrPermission):
			return nil, phaseError("command execution permission denied", errOperation)
		case errors.Is(err, exec.ErrWaitDelay):
			return nil, phaseError("command output pipe deadline exceeded", errOperation)
		default:
			return nil, phaseError("command could not start or complete", errOperation)
		}
	}
	return output.Bytes(), nil
}
