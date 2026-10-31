//go:build linux

package portforward

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"time"

	"github.com/cedar2025/xboard-node/internal/nftsnapshot"
	"golang.org/x/sys/unix"
)

type linuxSystem struct{}

func newSystem() system { return linuxSystem{} }

func (linuxSystem) available() bool {
	_, err := exec.LookPath("nft")
	return os.Geteuid() == 0 && err == nil
}

func (linuxSystem) lease(name string) (func(), error) {
	fd, err := openLock("/run/xboard-node-portforward-" + name + ".lock")
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("UDP port hopping owner is already active in another process; use a unique stable instance owner: %w", err)
	}
	return func() { _ = unix.Flock(fd, unix.LOCK_UN); _ = unix.Close(fd) }, nil
}

func openLock(path string) (int, error) {
	fd, err := unix.Open(path, unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return -1, fmt.Errorf("UDP port hopping cannot acquire its root-owned lock; run Node with root/NET_ADMIN and writable /run: %w", err)
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || st.Uid != 0 || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0077 != 0 || st.Nlink != 1 {
		unix.Close(fd)
		return -1, fmt.Errorf("UDP port hopping lock must be a root-owned regular 0600 file without links")
	}
	return fd, nil
}

func (linuxSystem) lock() (func(), error) {
	const path = "/run/xboard-node-portforward.lock"
	fd, err := openLock(path)
	if err != nil {
		return nil, err
	}
	// Bound contention rather than hanging the control channel indefinitely.
	deadline := time.Now().Add(10 * time.Second)
	for {
		err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			break
		}
		if (err != unix.EWOULDBLOCK && err != unix.EAGAIN) || time.Now().After(deadline) {
			unix.Close(fd)
			return nil, fmt.Errorf("UDP port hopping could not lock concurrent rule updates: %w", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	return func() { _ = unix.Flock(fd, unix.LOCK_UN); _ = unix.Close(fd) }, nil
}

func nft(input string, args ...string) ([]byte, error) {
	path, err := exec.LookPath("nft")
	if err != nil {
		return nil, fmt.Errorf("UDP port hopping requires the nftables 'nft' command on the node host; install nftables before enabling a range")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...)
	if input != "" {
		cmd.Stdin = bytes.NewBufferString(input)
	}
	// Do not promote bytes.Buffer.ReadFrom: io.Copy would bypass Write's cap.
	var data nftOutput
	cmd.Stdout = &data
	cmd.Stderr = io.Discard
	err = cmd.Run()
	if data.exceeded {
		return nil, nftsnapshot.ErrTooLarge
	}
	if err != nil {
		return nil, fmt.Errorf("UDP port hopping nftables operation failed; verify root/CAP_NET_ADMIN, kernel NAT support and nftables syntax (existing rules were not replaced): %w", err)
	}
	return data.buffer.Bytes(), nil
}

type nftOutput struct {
	buffer   bytes.Buffer
	exceeded bool
}

func (b *nftOutput) Write(data []byte) (int, error) {
	if len(data) > nftsnapshot.MaxOutput-b.buffer.Len() {
		b.exceeded = true
		return 0, nftsnapshot.ErrTooLarge
	}
	return b.buffer.Write(data)
}

func (linuxSystem) snapshot(table, marker string) ([]byte, error) {
	return readSnapshot(func(args ...string) ([]byte, error) { return nft("", args...) }, table, marker)
}
func (linuxSystem) apply(script string) error {
	_, err := nft(script, "-f", "-")
	return err
}
