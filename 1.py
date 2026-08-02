from locust import User, task, constant, events
import socket
import random
import os
import time
import threading
import contextlib
from urllib.parse import urlparse
try:
    import psutil
except ImportError:
    psutil = None

class PureSendUser(User):
    # 零延迟，上一个请求抛出即刻发送下一个
    wait_time = constant(0)
    
    # 5 个不同的 User-Agent
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0"
    ]

    stats_lock = threading.Lock()
    total_requests = 0

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.protocol = os.getenv("PROTOCOL", "http").lower()

        # 解析 host，兼容带或不带 scheme 的 host 值，剥离 path
        raw_host = (self.host or "").strip()
        if not raw_host:
            self.target_ip = None
            self.target_port = None
            return

        # 如果没有 scheme，urlparse 需要以 '//' 前缀来正确解析 hostname 和 port
        if not raw_host.startswith(("http://", "https://")):
            parsed = urlparse("//" + raw_host)
        else:
            parsed = urlparse(raw_host)

        # hostname/port 可能为 None（比如只有路径），回退到简单切分以尽量兼容旧配置
        hostname = parsed.hostname or raw_host.split(":")[0]
        port = parsed.port

        default_port = 80 if self.protocol == "http" else 9000

        self.target_ip = hostname
        self.target_port = int(port) if port else default_port

    @classmethod
    def setup_stats_logger(cls):
        def monitor():
            process = psutil.Process(os.getpid()) if psutil else None
            while True:
                time.sleep(60)
                with cls.stats_lock:
                    reqs = cls.total_requests
                    cls.total_requests = 0

                cpu_percent = psutil.cpu_percent(interval=None) if psutil else 0.0
                mem_info = process.memory_info().rss / (1024 * 1024) if process else 0.0
                
                print(f"\n[控制台自定统计 - 每分钟汇报]")
                print(f" -> 过去一分钟发包动作数: {reqs}")
                print(f" -> 当前机器 CPU 占用: {cpu_percent}% | 内存占用: {mem_info:.2f} MB\n", flush=True)

        t = threading.Thread(target=monitor, daemon=True)
        t.start()

    def on_start(self):
        if not hasattr(PureSendUser, "_monitor_started"):
            with PureSendUser.stats_lock:
                if not hasattr(PureSendUser, "_monitor_started"):
                    PureSendUser._monitor_started = True
                    PureSendUser.setup_stats_logger()

    @task
    def send_packet(self):
        if self.protocol == "http":
            self._fire_http()
        elif self.protocol == "tcp":
            self._fire_tcp()
        elif self.protocol == "udp":
            self._fire_udp()

    def _record(self, proto: str, name: str, start_time: float, length: int):
        elapsed = (time.time() - start_time) * 1000
        # 主动触发 Locust 内置事件，让面板和表格不再显示 0
        events.request.fire(
            request_type=proto,
            name=name,
            response_time=elapsed,
            response_length=length,
            exception=None
        )
        with PureSendUser.stats_lock:
            PureSendUser.total_requests += 1

    def _fire_http(self):
        start_time = time.time()
        headers = {"User-Agent": random.choice(self.user_agents)}
        length = 0
        try:
            import requests
            # 使用 GET 发包，0.5秒即时断开
            resp = requests.get(self.host, headers=headers, timeout=0.5)
            length = len(resp.content)
        except Exception:
            pass # 纯发包模式忽略连接终止或报错
        finally:
            # 无论目标服务有没有正常响应，只要完成了发包均计入吞吐总量
            self._record("HTTP", "http_pure_send", start_time, length)

    def _fire_tcp(self):
        start_time = time.time()
        payload = random.choice(self.user_agents).encode('utf-8')
        length = len(payload)

        # 如果没有解析到 target_ip/port，直接记录并返回
        if not self.target_ip or not self.target_port:
            self._record("TCP", "tcp_pure_send", start_time, length)
            return

        try:
            # 使用 create_connection 更稳健地处理 DNS 与 timeout，并用 contextlib.closing 确保关闭
            with contextlib.closing(socket.create_connection((self.target_ip, self.target_port), timeout=0.5)) as s:
                try:
                    s.sendall(payload)
                except Exception:
                    # 发送可能失败，但我们仍然把这次发包计入统计
                    pass
        except Exception:
            # 连接建立失败或超时，忽略（纯发包模式）
            pass
        finally:
            self._record("TCP", "tcp_pure_send", start_time, length)

    def _fire_udp(self):
        start_time = time.time()
        payload = random.choice(self.user_agents).encode('utf-8')
        length = len(payload)

        if not self.target_ip or not self.target_port:
            self._record("UDP", "udp_pure_send", start_time, length)
            return

        s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(0.5)
            s.sendto(payload, (self.target_ip, self.target_port))
        except Exception:
            pass
        finally:
            try:
                if s:
                    s.close()
            except Exception:
                pass
            self._record("UDP", "udp_pure_send", start_time, length)
