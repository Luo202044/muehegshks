package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"time"
)

// 真实浏览器 User-Agent 池
var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
}

func main() {
	// 接收命令行参数
	targetURL := flag.String("url", "https://example.com", "目标地址")
	threads := flag.Int("c", 100, "并发线程数")
	durationMin := flag.Int("t", 5, "持续时间(分钟)")
	flag.Parse()

	fmt.Printf("🚀 启动 Go 压测引擎...\n🎯 目标 URL: %s\n⚡ 并发线程: %d\n⏳ 持续时间: %d 分钟\n", *targetURL, *threads, *durationMin)

	// 核心优化：配置底层传输以支持极高并发
	transport := &http.Transport{
		MaxIdleConns:        *threads, // 最大空闲连接数等于并发数
		MaxIdleConnsPerHost: *threads, // 每个 Host 的最大连接数
		MaxConnsPerHost:     *threads, // 限制最大连接，防止资源耗尽
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true}, // 忽略证书错误
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second, // 防止死连接卡住 Goroutine
	}

	// 使用 Context 控制总运行时间
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(*durationMin)*time.Minute)
	defer cancel()

	// 初始化随机数种子
	rand.Seed(time.Now().UnixNano())

	// 启动指定数量的 Goroutine (类似于线程)
	for i := 0; i < *threads; i++ {
		go func() {
			for {
				select {
				case <-ctx.Done():
					// 时间到，自动退出该 Goroutine
					return
				default:
					// 疯狂发包逻辑
					req, err := http.NewRequest("GET", *targetURL, nil)
					if err == nil {
						// 随机挑选一个伪装 UA
						req.Header.Set("User-Agent", userAgents[rand.Intn(len(userAgents))])
						
						resp, err := client.Do(req)
						if err == nil {
							// 极其重要：必须读取并丢弃 Body，然后关闭它，否则连接无法复用！
							io.Copy(io.Discard, resp.Body)
							resp.Body.Close()
						} else {
							// 如果遇到网络超时或拒绝，打印出来但绝不中断程序
							fmt.Printf("[Error] %v\n", err)
						}
					}
				}
			}
		}()
	}

	// 阻塞主进程，直到 Context 超时
	<-ctx.Done()
	fmt.Println("\n✅ 压测时间到，任务圆满结束。")
	
	// 强制以退出码 0 结束，保证 GitHub Actions 一路绿灯
	os.Exit(0)
}
