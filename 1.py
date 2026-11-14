import asyncio
import aiohttp
import time
import sys

class LoadTester:
    def __init__(self, target, concurrency, duration, protocol='http'):
        self.target = target
        self.concurrency = concurrency
        self.duration = duration
        self.protocol = protocol
        self.success = 0
        self.fail = 0
        self.done = 0

    def _bump(self, ok):
        if ok:
            self.success += 1
        else:
            self.fail += 1
        self.done += 1

    async def worker_http(self, session, idx, stop_event, start_time):
        while True:
            if stop_event.is_set() or time.time() - start_time >= self.duration:
                break
            try:
                async with session.get(self.target, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                    self._bump(resp.status == 200)
            except Exception:
                self._bump(False)

    async def worker_tcp(self, idx, stop_event, start_time):
        host, port = self.target.rsplit(':', 1)
        port = int(port)
        while True:
            if stop_event.is_set() or time.time() - start_time >= self.duration:
                break
            try:
                reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=5)
                writer.close()
                await writer.wait_closed()
                self._bump(True)
            except Exception:
                self._bump(False)

    async def worker_udp(self, idx, stop_event, start_time):
        import socket
        host, port = self.target.rsplit(':', 1)
        port = int(port)
        payload = b'\x00' * 512
        while True:
            if stop_event.is_set() or time.time() - start_time >= self.duration:
                break
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.sendto(payload, (host, port))
                sock.close()
                self._bump(True)
            except Exception:
                self._bump(False)

    async def stopper(self, stop_event):
        await asyncio.sleep(self.duration)
        stop_event.set()

    async def run(self):
        print(f"目标: {self.target}", flush=True)
        print(f"协议: {self.protocol}", flush=True)
        print(f"并发: {self.concurrency}", flush=True)
        print(f"时长: {self.duration}s", flush=True)
        print("开始...", flush=True)

        stop_event = asyncio.Event()
        start_time = time.time()
        tasks = [asyncio.create_task(self.stopper(stop_event))]

        if self.protocol == 'http':
            connector = aiohttp.TCPConnector(limit=self.concurrency, keepalive_timeout=30)
            async with aiohttp.ClientSession(connector=connector) as session:
                for idx in range(self.concurrency):
                    tasks.append(asyncio.create_task(self.worker_http(session, idx, stop_event, start_time)))
                await asyncio.wait([tasks[0]], return_when=asyncio.FIRST_COMPLETED)
                for t in tasks[1:]:
                    if not t.done():
                        t.cancel()
                await asyncio.gather(*tasks[1:], return_exceptions=True)
        elif self.protocol == 'tcp':
            for idx in range(self.concurrency):
                tasks.append(asyncio.create_task(self.worker_tcp(idx, stop_event, start_time)))
            await asyncio.wait([tasks[0]], return_when=asyncio.FIRST_COMPLETED)
            for t in tasks[1:]:
                if not t.done():
                    t.cancel()
            await asyncio.gather(*tasks[1:], return_exceptions=True)
        elif self.protocol == 'udp':
            for idx in range(self.concurrency):
                tasks.append(asyncio.create_task(self.worker_udp(idx, stop_event, start_time)))
            await asyncio.wait([tasks[0]], return_when=asyncio.FIRST_COMPLETED)
            for t in tasks[1:]:
                if not t.done():
                    t.cancel()
            await asyncio.gather(*tasks[1:], return_exceptions=True)
        else:
            print(f"不支持的协议: {self.protocol}", flush=True)
            return

        elapsed = time.time() - start_time
        rps = self.done / elapsed if elapsed > 0 else 0
        print(f"完成! 耗时 {elapsed:.2f}s, 成功 {self.success}, 失败 {self.fail}, RPS {rps:.1f}", flush=True)

if __name__ == '__main__':
    target = sys.argv[1] if len(sys.argv) > 1 else 'http://example.com'
    concurrency = int(sys.argv[2]) if len(sys.argv) > 2 else 200
    duration = int(sys.argv[3]) if len(sys.argv) > 3 else 300
    protocol = sys.argv[4] if len(sys.argv) > 4 else 'http'
    # 非HTTP协议 target 格式: IP:端口
    asyncio.run(LoadTester(target, concurrency, duration, protocol).run())
