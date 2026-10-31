//go:build linux

package firewall

import (
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const controlMarker = "xboard-node-private-firewall-control:v1\n"

type controlServer struct {
	listener *net.UnixListener
	lock     *os.File
	path     string
	identity os.FileInfo
	once     sync.Once
}

// StartControl exposes the running process registry only to local root peers.
// Failure is diagnostic-only; callers must keep node services running.
func StartControl() (io.Closer, error) { return startControlAt(DefaultSocket, Default) }

func startControlAt(path string, provider reportProvider) (*controlServer, error) {
	if os.Geteuid() != 0 || provider == nil || !filepath.IsAbs(path) {
		return nil, ErrControlUnavailable
	}
	dir := filepath.Dir(path)
	if err := secureControlDirectory(dir, true); err != nil {
		return nil, err
	}
	lock, known, err := controlLease(filepath.Join(dir, "control.lock"))
	if err != nil {
		return nil, err
	}
	var listener *net.UnixListener
	success := false
	defer func() {
		if !success {
			if listener != nil {
				listener.Close()
			}
			lock.Close()
		}
	}()
	if info, err := os.Lstat(path); err == nil {
		// A matching, locked ownership marker and exact private socket are
		// required before reclaiming an endpoint left by a terminated process.
		if !known || !privateRootObject(info, os.ModeSocket, 0600) {
			return nil, ErrControlUnavailable
		}
		conn, err := net.DialTimeout("unix", path, 200*time.Millisecond)
		if err == nil {
			conn.Close()
			return nil, errors.New("firewall control socket is already active")
		}
		if !errors.Is(err, syscall.ECONNREFUSED) {
			return nil, ErrControlUnavailable
		}
		if err := os.Remove(path); err != nil {
			return nil, ErrControlUnavailable
		}
	} else if !os.IsNotExist(err) {
		return nil, ErrControlUnavailable
	}
	listener, err = net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, ErrControlUnavailable
	}
	listener.SetUnlinkOnClose(false)
	if err := os.Chmod(path, 0600); err != nil {
		return nil, ErrControlUnavailable
	}
	identity, err := os.Lstat(path)
	if err != nil || !privateRootObject(identity, os.ModeSocket, 0600) {
		return nil, ErrControlUnavailable
	}
	server := &controlServer{listener: listener, lock: lock, path: path, identity: identity}
	success = true
	go server.serve(provider)
	return server, nil
}

func (s *controlServer) serve(provider reportProvider) {
	slots := make(chan struct{}, 8)
	for {
		conn, err := s.listener.AcceptUnix()
		if err != nil {
			return
		}
		if !rootPeer(conn) {
			conn.Close()
			continue
		}
		select {
		case slots <- struct{}{}:
			go func() { defer func() { <-slots }(); handleControl(conn, provider) }()
		default:
			conn.Close()
		}
	}
}

func (s *controlServer) Close() error {
	var result error
	s.once.Do(func() {
		result = s.listener.Close()
		if info, err := os.Lstat(s.path); err == nil && os.SameFile(info, s.identity) {
			_ = os.Remove(s.path)
		}
		_ = s.lock.Close()
	})
	return result
}

func rootPeer(conn *net.UnixConn) bool {
	raw, err := conn.SyscallConn()
	if err != nil {
		return false
	}
	allowed := false
	err = raw.Control(func(fd uintptr) {
		credentials, e := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		allowed = e == nil && credentials.Uid == 0
	})
	return err == nil && allowed
}

func privateRootObject(info os.FileInfo, kind os.FileMode, mode os.FileMode) bool {
	if info == nil || info.Mode().Type() != kind || info.Mode().Perm() != mode || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == 0 && stat.Nlink == 1
}

// Ancestors must be immutable to unprivileged users; the final directory has
// exactly 0700, so unprivileged processes cannot inspect or replace endpoints.
func secureControlDirectory(dir string, create bool) error {
	if !filepath.IsAbs(dir) {
		return ErrControlUnavailable
	}
	root, err := os.Lstat("/")
	if err != nil || !root.IsDir() || root.Mode().Perm()&0022 != 0 {
		return ErrControlUnavailable
	}
	rootStat, ok := root.Sys().(*syscall.Stat_t)
	if !ok || rootStat.Uid != 0 {
		return ErrControlUnavailable
	}
	current := "/"
	parts := strings.Split(strings.TrimPrefix(filepath.Clean(dir), "/"), "/")
	for i, part := range parts {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if os.IsNotExist(err) && create && i == len(parts)-1 {
			if err = os.Mkdir(current, 0700); err == nil {
				info, err = os.Lstat(current)
			}
		}
		if err != nil || info == nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
			return ErrControlUnavailable
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 {
			return ErrControlUnavailable
		}
		if i == len(parts)-1 && info.Mode().Perm() != 0700 {
			return ErrControlUnavailable
		}
	}
	return nil
}

func controlLease(path string) (*os.File, bool, error) {
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	created := err == nil
	if errors.Is(err, unix.EEXIST) {
		fd, err = unix.Open(path, unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	}
	if err != nil {
		return nil, false, ErrControlUnavailable
	}
	file := os.NewFile(uintptr(fd), path)
	info, err := file.Stat()
	if err != nil || !privateRootObject(info, 0, 0600) {
		file.Close()
		return nil, false, ErrControlUnavailable
	}
	if unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB) != nil {
		file.Close()
		return nil, false, errors.New("firewall control is already owned by a running Node")
	}
	if created {
		if _, err = file.WriteString(controlMarker); err == nil {
			err = file.Sync()
		}
		if err != nil {
			file.Close()
			return nil, false, ErrControlUnavailable
		}
		return file, false, nil
	}
	data, err := io.ReadAll(io.LimitReader(file, int64(len(controlMarker)+1)))
	if err != nil || string(data) != controlMarker {
		file.Close()
		return nil, false, ErrControlUnavailable
	}
	return file, true, nil
}

func QueryControl(path, action string) (ControlResponse, error) {
	if !validAction(action) {
		return ControlResponse{}, errors.New("unknown firewall action")
	}
	if err := secureControlDirectory(filepath.Dir(path), false); err != nil {
		return ControlResponse{}, ErrControlUnavailable
	}
	info, err := os.Lstat(path)
	if err != nil || !privateRootObject(info, os.ModeSocket, 0600) {
		return ControlResponse{}, ErrControlUnavailable
	}
	conn, err := net.DialTimeout("unix", path, 2*time.Second)
	if err != nil {
		return ControlResponse{}, ErrControlUnavailable
	}
	unixConn, ok := conn.(*net.UnixConn)
	if !ok || !rootPeer(unixConn) {
		conn.Close()
		return ControlResponse{}, ErrControlUnavailable
	}
	return requestControl(conn, action)
}

func persistenceInventory() Persistence {
	exists := func(path string) bool { info, err := os.Stat(path); return err == nil && info.Mode().IsRegular() }
	return Persistence{
		Strategy:                     "rebuild from successful runtime inbounds on Node startup; reconcile periodically; never save host rules",
		NetfilterPersistentInstalled: exists("/usr/sbin/netfilter-persistent") || exists("/sbin/netfilter-persistent"),
		SavedIPv4Rules:               exists("/etc/iptables/rules.v4"), SavedIPv6Rules: exists("/etc/iptables/rules.v6"),
	}
}
