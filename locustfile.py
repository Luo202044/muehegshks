from locust import HttpUser, task, constant

class PureLoadTestUser(HttpUser):
    # constant(0) 表示没有思考时间，前一个请求一结束立刻发送下一个
    wait_time = constant(0)

    @task
    def fire_request(self):
        # 这里的 "/" 会自动拼接到你从外部传入的 URL 后面
        # catch_response=True 并在内部不进行任何断言，可以最大程度降低施压机的 CPU 消耗
        with self.client.get("/", catch_response=True) as response:
            pass
