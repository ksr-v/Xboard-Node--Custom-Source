# Maintained bandwidth patch for the frozen Xray core

These three source files originate from the already backed-up
`github.com/cedar2025/Xray-core@v0.0.0-20260409213332-f47935539965`.
They retain the original module's MPL-2.0 license (included here). No historical
module archive, checksum, replacement version, public protocol or API is changed.

The changes add upload gating to `DispatchLink` while preserving the concrete
reader shape used by mux/XUDP, and allow large writes and existing streams to
observe a stable bandwidth bucket changing between finite and unlimited rates.
Reservations are bounded and pending waits recheck changes every 20 ms.

`tools/kernel_patches.py` verifies the original full source tree against the
historical `go.sum`, checks both original and patched file SHA-256 values, and
creates a verified maintained source copy under `.dependency-work`. It generates
a private `-modfile` pointing at that copy. Original `go.mod`, `go.sum`, module
cache and immutable dependency snapshot stay unchanged. A modified maintained
copy is refused. The Node compile-time revision guard rejects an accidental
build without the patch.

The replacement path in the private modfile is relative, so Go's embedded module
metadata does not disclose the absolute path of the local maintenance copy.

Use `make build`, `make test`, or `tools/dependencies.py build/test`; CI, Docker
and protected-source recovery use the same preparation. For a focused local
Go command with dependencies already restored:

```sh
export GOFLAGS="$(python3 tools/kernel_patches.py)"
go test ./internal/limiter ./internal/kernel/singbox ./internal/kernel/xray ./internal/service
```

If these maintained files change, update their `patched_sha256` values in
`manifest.json` after review. An upstream version change requires a new explicit
review of the original source and hashes; there is no automatic upstream fetch.
