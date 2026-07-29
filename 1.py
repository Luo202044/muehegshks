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

class MultiProtocolUser(User):
    # 没有等待时间，前一个请求结束立刻发送下一个
    wait_time = constant(0)
    
    # 定义 5 个不同的 User-Agent（用于 HTTP 模式验证）
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0"
    ]

    # 用于全局统计请求数据
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
        """ 启动一个后台线程，每分钟打印一次数据与机器资源占用 """
        def monitor():
            process = psutil.Process(os.getpid()) if psutil else None
            while True:
                time.sleep(60)  # 每分钟执行一次
                with cls.stats_lock:
                    reqs = cls.total_requests
                    fails = cls.total_failures
                    cls.total_requests = 0
                    cls.total_failures = 0

                # 获取机器资源占用
                cpu_percent = psutil.cpu_percent(interval=None) if psutil else 0.0
                mem_info = process.memory_info().rss / (1024 * 1024) if process else 0.0
                
                print(f"\n[状态统计 - 每分钟汇报]")
                print(f" -> 过去一分钟发送请求数: {reqs}, 失败数: {fails}")
                print(f" -> 当前进程 CPU 占用: {cpu_percent}% | 内存占用: {mem_info:.2f} MB\n")

        t = threading.Thread(target=monitor, daemon=True)
        t.start()

    def on_start(self):
        # 仅在第一个用户启动时初始化一次监控线程
        if not hasattr(MultiProtocolUser, "_monitor_started"):
            with MultiProtocolUser.stats_lock:
                if not hasattr(MultiProtocolUser, "_monitor_started"):
                    MultiProtocolUser._monitor_started = True
                    MultiProtocolUser.setup_stats_logger()

    @task
    def send_request(self):
        if self.protocol == "http":
            self._send_http()
        elif self.protocol == "tcp":
            self._send_tcp()
        elif self.protocol == "udp":
            self._send_udp()

    def _record_result(self, success: bool):
        with MultiProtocolUser.stats_lock:
            MultiProtocolUser.total_requests += 1
            if not success:
                MultiProtocolUser.total_failures += 1

    def _send_http(self):
        headers = {"User-Agent": random.choice(self.user_agents)}
        start_time = time.time()
        try:
            import requests
            response = requests.get(self.host, headers=headers, timeout=5)
            response_time = (time.time() - start_time) * 1000
            success = response.status_code < 400
            
            events.request.fire(
                request_type="HTTP", name="http_request",
                response_time=response_time, response_length=len(response.content),
                exception=None if success else Exception(f"Bad Status: {response.status_code}")
            )
            self._record_result(success)
        except Exception as e:
            events.request.fire(
                request_type="HTTP", name="http_request",
                response_time=0, response_length=0, exception=e
            )
            self._record_result(False)

    def _send_tcp(self):
        start_time = time.time()
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3.0)
            s.connect((self.target_ip, self.target_port))
            payload = b"PING_ALIVE\r\n"
            s.sendall(payload)
            try:
                s.recv(1024)
            except socket.timeout:
                pass
            s.close()
            response_time = (time.time() - start_time) * 1000
            
            events.request.fire(
                request_type="TCP", name="tcp_ping",
                response_time=response_time, response_length=len(payload), exception=None
            )
            self._record_result(True)
        except Exception as e:
            events.request.fire(
                request_type="TCP", name="tcp_ping",
                response_time=0, response_length=0, exception=e
            )
            self._record_result(False)

    def _send_udp(self):
        start_time = time.time()
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            payload = random.choice(self.user_agents).encode('utf-8')
            s.sendto(payload, (self.target_ip, self.target_port))
            s.close()
            response_time = (time.time() - start_time) * 1000
            
            events.request.fire(
                request_type="UDP", name="udp_ping",
                response_time=response_time, response_length=len(payload), exception=None
            )
            self._record_result(True)
        except Exception as e:
            events.request.fire(
                request_type="UDP", name="udp_ping",
                response_time=0, response_length=0, exception=e
            )
            self._record_result(False)
