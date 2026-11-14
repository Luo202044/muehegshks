import asyncio
import aiohttp
import time
import sys

class LoadTester:
    def __init__(self, target_url, concurrency, total_requests):
        self.url = target_url
        self.concurrency = concurrency
        self.total = total_requests
        self.success = 0
        self.fail = 0

    async def worker(self, session, queue):
        while True:
            req_id = await queue.get()
            try:
                async with session.get(self.url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                    if resp.status == 200:
                        self.success += 1
                    else:
                        self.fail += 1
            except Exception:
                self.fail += 1
            queue.task_done()

    async def run(self):
        print(f"目标: {self.url}\n并发: {self.concurrency}\n总请求: {self.total}\n开始...")
        queue = asyncio.Queue(maxsize=self.concurrency * 2)
        connector = aiohttp.TCPConnector(limit=self.concurrency, keepalive_timeout=30)
        timeout = aiohttp.ClientTimeout(total=30)

        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            # 填充队列
            for i in range(self.total):
                await queue.put(i)

            start = time.time()
            workers = [asyncio.create_task(self.worker(session, queue)) for _ in range(self.concurrency)]
            await queue.join()
            await asyncio.gather(*workers)

        elapsed = time.time() - start
        rps = self.total / elapsed if elapsed > 0 else 0
        print(f"\n完成! 耗时 {elapsed:.2f}s, 成功 {self.success}, 失败 {self.fail}, RPS {rps:.1f}")

if __name__ == '__main__':
    url = sys.argv[1] if len(sys.argv) > 1 else 'http://example.com'
    concurrency = int(sys.argv[2]) if len(sys.argv) > 2 else 200
    total = int(sys.argv[3]) if len(sys.argv) > 3 else 10000
    asyncio.run(LoadTester(url, concurrency, total).run())
