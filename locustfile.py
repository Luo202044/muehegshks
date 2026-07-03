from locust import HttpUser, task, constant

class PureLoadTestUser(HttpUser):
    # 没有等待时间，前一个请求结束立刻发送下一个
    wait_time = constant(0)

    @task
    def fire_request(self):
        # 自动拼接到外部传入的 host 后面
        with self.client.get("/", catch_response=True) as response:
            pass
