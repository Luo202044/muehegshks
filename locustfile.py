import os
from locust import HttpUser, task, between

# --- 分片配置提取 ---
# 默认当作单机运行 (Shard 1/1)
SHARD_ID = int(os.getenv("SHARD_ID", 1))
TOTAL_SHARDS = int(os.getenv("TOTAL_SHARDS", 1))

# --- 模拟全局测试数据 ---
# 假设我们有 1000 个测试账号
GLOBAL_USER_ACCOUNTS = [f"test_user_{i}" for i in range(1, 1001)]

# --- 数据分片逻辑 ---
def get_shard_data(data_list, shard_id, total_shards):
    """根据分片ID均匀切割数据"""
    chunk_size = len(data_list) // total_shards
    start_idx = (shard_id - 1) * chunk_size
    # 最后一个分片包揽剩余的所有数据
    end_idx = start_idx + chunk_size if shard_id < total_shards else len(data_list)
    return data_list[start_idx:end_idx]

# 当前 Runner 获取分配给自己的专属数据
MY_SHARD_ACCOUNTS = get_shard_data(GLOBAL_USER_ACCOUNTS, SHARD_ID, TOTAL_SHARDS)

class ShardedUser(HttpUser):
    wait_time = between(1, 3)

    def on_start(self):
        """每个虚拟用户启动时，从专属数据池中拿一个账号"""
        if MY_SHARD_ACCOUNTS:
            self.account = MY_SHARD_ACCOUNTS.pop()
        else:
            self.account = "fallback_account"
            
        print(f"[分片 {SHARD_ID}/{TOTAL_SHARDS}] 虚拟用户上线，使用账号: {self.account}")

    @task
    def access_profile(self):
        # 携带分片分配的账号进行请求
        with self.client.get(f"/api/profile?user={self.account}", catch_response=True, name="/api/profile") as response:
            if response.status_code == 200:
                response.success()
            else:
                response.failure(f"Error for {self.account}: {response.status_code}")
