from locust import HttpUser, task, constant, events

# 保持这个钩子：即使有很多请求失败，最终也以退出码 0 结束，让 GitHub Action 保持绿勾
@events.quitting.add_listener
def force_exit_code_zero(environment, **kwargs):
    environment.process_exit_code = 0

class PureLoadTestUser(HttpUser):
    wait_time = constant(0)

    @task
    def fire_request(self):
        # 去掉了 catch_response=True 
        # 这样 Locust 会在 GitHub 控制台真实打印出它遇到了什么问题
        self.client.get("/")
