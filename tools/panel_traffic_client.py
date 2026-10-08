"""Loopback-only VLESS TCP/TLS client for authorized panel integration tests.

The credential JSON stays in the VM runtime directory, outside Git. The client
creates its own loopback HTTP origin and verifies response bytes end to end.
No external origin, third-party Python library or extra Go module is required.
"""
import argparse
import hashlib
import http.server
import json
from pathlib import Path
import socket
import ssl
import struct
import threading
import time
import uuid


BODY = (b'xboard-selective-dependency-panel-integration\n' * 12000)


class TunnelResponseError(Exception):
    """TCP/TLS connected, but the authenticated tunnel did not serve HTTP."""


def read_exact(conn, size):
    chunks = bytearray()
    while len(chunks) < size:
        chunk = conn.recv(size - len(chunks))
        if not chunk:
            raise EOFError('Peer closed before the expected response')
        chunks.extend(chunk)
    return bytes(chunks)


class Origin(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self):
        super().__init__(('127.0.0.1', 0), OriginHandler)
        self.lock = threading.Lock()
        self.requests = {}
        self.release = threading.Event()

    def hits(self, token):
        with self.lock:
            return self.requests.get(token, 0)


class OriginHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, *_args):
        pass

    def do_GET(self):
        token = self.path.rsplit('/', 1)[-1]
        with self.server.lock:
            self.server.requests[token] = self.server.requests.get(token, 0) + 1
        hold = self.path.startswith('/hold/')
        self.send_response(200)
        self.send_header('Content-Length', str(len(BODY) + (1 if hold else 0)))
        self.send_header('Connection', 'close')
        self.end_headers()
        try:
            self.wfile.write(BODY)
            self.wfile.flush()
            if hold:
                # Keep the first source IP active while testing a second IP.
                self.server.release.wait(90)
                self.wfile.write(b'!')
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass


class Client:
    def __init__(self, args, credential, origin):
        self.args = args
        self.credential = credential
        self.origin = origin
        self.tls_evidence = None

    def connect(self, source_ip):
        conn = socket.create_connection(('127.0.0.1', self.args.port),
                                        timeout=self.args.timeout,
                                        source_address=(source_ip, 0))
        if self.args.ca_file:
            context = ssl.create_default_context(cafile=str(self.args.ca_file))
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            try:
                conn = context.wrap_socket(conn, server_hostname=self.args.server_name)
            except BaseException:
                conn.close()
                raise
            self.tls_evidence = dict(version=conn.version(), cipher=conn.cipher()[0],
                                     peer_certificate_sha256=hashlib.sha256(conn.getpeercert(True)).hexdigest(),
                                     verified=True, server_name=self.args.server_name)
        return conn

    def request(self, token, source_ip='127.0.0.2', identity=None, hold=False):
        conn = self.connect(source_ip)
        retained = False
        try:
            # VLESS v0, UUID, zero addon length, TCP command, big-endian port,
            # IPv4 address type and loopback destination. Verified against the
            # project's pinned sing-vmess/vless/protocol.go implementation.
            header = (b'\x00' + uuid.UUID(identity or self.credential).bytes + b'\x00\x01'
                      + struct.pack('!H', self.origin.server_port) + b'\x01\x7f\x00\x00\x01')
            path = ('/hold/' if hold else '/body/') + token
            request = (f'GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n').encode('ascii')
            conn.sendall(header + request)
            version, addons = read_exact(conn, 2)
            if version != 0:
                raise ValueError('Unexpected VLESS response version')
            read_exact(conn, addons)
            response = bytearray()
            while b'\r\n\r\n' not in response:
                if len(response) > 32768:
                    raise ValueError('Oversized origin HTTP headers')
                response.extend(read_exact(conn, 1))
            if not response.startswith(b'HTTP/1.1 200 '):
                raise ValueError('Origin did not return HTTP 200')
            body = read_exact(conn, len(BODY))
            if body != BODY:
                raise ValueError('Origin response bytes changed in transit')
            evidence = dict(source_ip=source_ip, origin_response_bytes=len(body),
                            body_sha256=hashlib.sha256(body).hexdigest(),
                            request_bytes=len(header) + len(request), origin_hits=self.origin.hits(token))
            if hold:
                retained = True
                return evidence, conn
            return evidence, None
        except (OSError, EOFError, ValueError) as error:
            raise TunnelResponseError(type(error).__name__ + ': ' + str(error)) from error
        finally:
            if not retained:
                conn.close()

    def rejected(self, source_ip, identity=None):
        token = uuid.uuid4().hex
        # request() leaves TCP/TLS connection errors unwrapped, so they cannot
        # be misreported as successful UUID/device-limit rejections.
        reason = None
        try:
            self.request(token, source_ip=source_ip, identity=identity)
        except TunnelResponseError as error:
            reason = type(error).__name__
        if reason is None or self.origin.hits(token):
            raise AssertionError('Rejected credential/IP reached the loopback origin')
        return dict(source_ip=source_ip, rejected=True, origin_hits=0, failure_type=reason)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--port', type=int, required=True, help='Local Node VLESS listener port')
    ap.add_argument('--credential-file', type=Path, required=True, help='Private runtime JSON containing uuid')
    ap.add_argument('--ca-file', type=Path, help='Trust this test certificate; omitted means plain VLESS')
    ap.add_argument('--server-name', default='localhost')
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--timeout', type=float, default=5)
    ap.add_argument('--hold-seconds', type=float, default=5,
                    help='Keep the first connection active for device/traffic reporting')
    ap.add_argument('--release-timeout', type=float, default=75)
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument('--device-limit', action='store_true', help='Require fixture user device_limit=1')
    mode.add_argument('--expect-rejected', action='store_true',
                      help='After fixture user revocation, require its original UUID to be rejected')
    args = ap.parse_args()
    credential = json.loads(args.credential_file.read_text(encoding='utf-8'))['uuid']
    uuid.UUID(credential)
    origin = Origin()
    thread = threading.Thread(target=origin.serve_forever, daemon=True)
    thread.start()
    client = Client(args, credential, origin)
    rows = []
    result = dict(passed=False, tests=rows, encrypted=bool(args.ca_file),
                  origin='127.0.0.1', destination='127.0.0.1',
                  credential_recorded=False)
    hold_conn = None
    try:
        if args.expect_rejected:
            rows.append(dict(step='revoked-fixture-uuid-rejected', passed=True,
                             **client.rejected('127.0.0.2', credential)))
            result['tls'] = client.tls_evidence
            result['passed'] = True
            return
        transfer, _ = client.request(uuid.uuid4().hex)
        rows.append(dict(step='valid-uuid-end-to-end-response', passed=True, **transfer))
        rows.append(dict(step='invalid-uuid-rejected', passed=True,
                         **client.rejected('127.0.0.2', str(uuid.uuid4()))))
        if args.device_limit:
            transfer, hold_conn = client.request(uuid.uuid4().hex, hold=True)
            rows.append(dict(step='first-source-ip-held-open', passed=True, **transfer))
            print(json.dumps(dict(step='first-source-ip-held-open', hold_seconds=args.hold_seconds)), flush=True)
            time.sleep(max(0, args.hold_seconds))
            transfer, _ = client.request(uuid.uuid4().hex)
            rows.append(dict(step='same-source-ip-allowed', passed=True, **transfer))
            rows.append(dict(step='second-source-ip-rejected', passed=True,
                             **client.rejected('127.0.0.3')))
            hold_conn.close()
            hold_conn = None
            origin.release.set()
            # With WS sync.devices, a recently reported IP may remain globally
            # known until the next snapshot. Check eventual release explicitly.
            deadline = time.monotonic() + args.release_timeout
            last_error = None
            while time.monotonic() < deadline:
                try:
                    transfer, _ = client.request(uuid.uuid4().hex, source_ip='127.0.0.3')
                    rows.append(dict(step='device-slot-released', passed=True, **transfer))
                    break
                except TunnelResponseError as error:
                    last_error = error
                    time.sleep(1)
            else:
                raise AssertionError('Device slot did not release') from last_error
        result['tls'] = client.tls_evidence
        result['passed'] = True
    except BaseException as error:
        result['error_type'] = type(error).__name__
        result['error'] = str(error)
        raise
    finally:
        if hold_conn:
            hold_conn.close()
        origin.release.set()
        origin.shutdown()
        origin.server_close()
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8', newline='\n')
        print(json.dumps(dict(passed=result['passed'], evidence=str(args.output), tests=len(rows))))


if __name__ == '__main__':
    main()
