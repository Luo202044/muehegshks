from locust import HttpUser, task, constant
import random

class PureLoadTestUser(HttpUser):
    # 没有等待时间，前一个请求结束立刻发送下一个
    wait_time = constant(0)
    
    # 定义 5 个不同的 User-Agent
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0"
    ]

    @task
    def fire_request(self):
        # 随机选择一个 User-Agent
        headers = {
            "User-Agent": random.choice(self.user_agents)
        }
        
        # 发送带 Header 的请求
        with self.client.get("/", headers=headers, catch_response=True) as response:
            pass
