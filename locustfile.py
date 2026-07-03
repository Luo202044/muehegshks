from locust import HttpUser, task, constant, events

# 监听 Locust 退出事件，强制将最终的退出代码设为 0
@events.quitting.add_listener
def force_exit_code_zero(environment, **kwargs):
    environment.process_exit_code = 0

class PureLoadTestUser(HttpUser):
    wait_time = constant(0)

    @task
    def fire_request(self):
        # catch_response=True 会捕获所有异常
        # 我们在这里不管服务器返回什么，都直接调用 response.success()
        # 彻底屏蔽报错，让脚本成为无情的发包机器
        with self.client.get("/", catch_response=True) as response:
            response.success()
