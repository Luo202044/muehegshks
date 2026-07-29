from locust import User, task, constant, events
import socket
import random
import os
import time
import threading
try:
    import psutil
except ImportError:
    psutil = None

class PureSendUser(User):
    # 没有等待时间，前一个请求结束立刻发送下一个
    wait_time = constant(0)
    
    # 5 个不同的 User-Agent（用于 HTTP 纯发包或载荷伪装）
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0"
    ]

    stats_lock = threading.Lock()
    total_requests = 0
    total_failures = 0

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.protocol = os.getenv("PROTOCOL", "http").lower()
        
        host_clean = self.host.replace("http://", "").replace("https://", "")
        host_parts = host_clean.split(":")
        self.target_ip = host_parts[0]
        self.target_port = int(host_parts[1]) if len(host_parts) > 1 else (80 if self.protocol == "http" else 9000)

    @classmethod
    def setup_stats_logger(cls):
        def monitor():
            process = psutil.Process(os.getpid()) if psutil else None
            while True:
                time.sleep(60)
                with cls.stats_lock:
                    reqs = cls.total_requests
                    fails = cls.total_failures
                    cls.total_requests = 0
                    cls.total_failures = 0

                cpu_percent = psutil.cpu_percent(interval=None) if psutil else 0.0
                mem_info = process.memory_info().rss / (1024 * 1024) if process else 0.0
                
                print(f"\n[纯发包统计 - 每分钟汇报]")
                print(f" -> 过去一分钟发包数: {reqs}, 异常数: {fails}")
                print(f" -> 当前进程 CPU: {cpu_percent}% | 内存: {mem_info:.2f} MB\n")

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

    def _record(self, success: bool):
        with PureSendUser.stats_lock:
            PureSendUser.total_requests += 1
            if not success:
                PureSendUser.total_failures += 1

    def _fire_http(self):
        # HTTP 纯发包（不等待返回体，发完即算）
        headers = {"User-Agent": random.choice(self.user_agents)}
        try:
            import requests
            # 极短超时，只管把包送出去，不管回不回
            requests.get(self.host, headers=headers, timeout=0.5)
            self._record(True)
        except Exception:
            # 纯发包模式下，经常因为系统掐断或超时抛异常，这里直接忽略计为发包动作
            self._record(True)

    def _fire_tcp(self):
        # TCP 纯发包：连上、塞数据、立刻断开（不管对方回应）
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.0)
            s.connect((self.target_ip, self.target_port))
            payload = random.choice(self.user_agents).encode('utf-8')
            s.sendall(payload)
            s.close()
            self._record(True)
        except Exception:
            self._record(True)

    def _fire_udp(self):
        # UDP 纯发包：无脑往外甩数据报
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            payload = random.choice(self.user_agents).encode('utf-8')
            s.sendto(payload, (self.target_ip, self.target_port))
            s.close()
            self._record(True)
        except Exception:
            self._record(True)
