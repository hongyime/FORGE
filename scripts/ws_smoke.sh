#!/usr/bin/env bash
# Linux counterpart to scripts/ws_smoke.ps1.
set -euo pipefail
host=localhost port=9000 timeout_ms=3000
while (($#)); do case "$1" in --host) host=$2; shift 2;; --port) port=$2; shift 2;; --timeout-ms) timeout_ms=$2; shift 2;; -h|--help) echo "Usage: $0 [--host HOST] [--port PORT] [--timeout-ms MS]"; exit 0;; *) echo "Unknown argument: $1" >&2; exit 2;; esac; done
python3 - "$host" "$port" "$timeout_ms" <<'PY'
import base64, os, socket, struct, sys, time
host, port, timeout_ms = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]); timeout = timeout_ms / 1000
sock = None
try:
    print(f"WS smoke: connecting to ws://{host}:{port}/ws/progress ...")
    sock = socket.create_connection((host, port), timeout=timeout); sock.settimeout(timeout)
    key = base64.b64encode(os.urandom(16)).decode()
    request = f"GET /ws/progress HTTP/1.1\r\nHost: {host}:{port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
    sock.sendall(request.encode()); response=b""
    while b"\r\n\r\n" not in response: response += sock.recv(4096)
    head, buffered = response.split(b"\r\n\r\n",1)
    if b" 101 " not in head.split(b"\r\n",1)[0]: raise RuntimeError(f"handshake rejected: {head.splitlines()[0].decode(errors='replace')}")
    print("WS smoke: connected (state=Open)")
    payload=b"ping"; mask=os.urandom(4); masked=bytes(v ^ mask[i%4] for i,v in enumerate(payload)); sock.sendall(bytes([0x81,0x80|len(payload)])+mask+masked); print("WS smoke: sent 'ping'")
    deadline=time.monotonic()+timeout
    def take(n):
        global buffered
        while len(buffered)<n:
            sock.settimeout(max(.001, deadline-time.monotonic())); chunk=sock.recv(4096)
            if not chunk: raise RuntimeError("server closed before echo")
            buffered+=chunk
        value, buffered=buffered[:n],buffered[n:]; return value
    first, second=take(2); length=second&127
    if length==126: length=struct.unpack("!H",take(2))[0]
    elif length==127: length=struct.unpack("!Q",take(8))[0]
    mask_key=take(4) if second&128 else b""; data=take(length)
    if mask_key: data=bytes(v ^ mask_key[i%4] for i,v in enumerate(data))
    received=data.decode(); print(f"WS smoke: received '{received}'")
    if received!="ping": raise RuntimeError(f"expected 'ping', got '{received}'")
    sock.sendall(bytes([0x88,0x82])+b"abcd"+bytes([1000^97,0^98])); print("WS smoke: PASS (echo verified)")
except Exception as exc:
    print(f"FAIL: {exc}", file=sys.stderr); sys.exit(1)
finally:
    if sock: sock.close()
PY
