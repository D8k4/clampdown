// SPDX-License-Identifier: GPL-3.0-only

package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "proxy: "+format+"\n", args...)
	os.Exit(1)
}

func main() {
	upstream, err := url.Parse(requireEnv("PROXY_UPSTREAM"))
	if err != nil {
		fatalf("bad PROXY_UPSTREAM: %v", err)
	}
	port := requireEnv("PROXY_PORT")
	headerName := requireEnv("PROXY_HEADER_NAME")
	headerPrefix := os.Getenv("PROXY_HEADER_PREFIX") // may be empty
	keyValue := requireEnv("PROXY_KEY")

	proxy := &httputil.ReverseProxy{
		FlushInterval: -1, // immediate flush for SSE streaming
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(upstream)
			pr.Out.Host = upstream.Host
			pr.Out.Header.Del(headerName)
			pr.Out.Header.Set(headerName, headerPrefix+keyValue)
		},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		start := time.Now()
		proxy.ServeHTTP(w, req)
		fmt.Fprintf(os.Stderr, "proxy: %s %s %s\n",
			req.Method, req.URL.Path, time.Since(start).Truncate(time.Millisecond))
	})

	addr := "127.0.0.1:" + port
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		fatalf("listen %s: %v", addr, err)
	}

	srv := &http.Server{Handler: mux}
	go func() {
		err := srv.Serve(ln)
		if err != nil && err != http.ErrServerClosed {
			fatalf("serve %s: %v", addr, err)
		}
	}()

	fmt.Fprintf(os.Stderr, "proxy: %s -> %s\n", addr, upstream)
	fmt.Fprintln(os.Stderr, "proxy: ready")

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
}

func requireEnv(name string) string {
	v := os.Getenv(name)
	if v == "" {
		fatalf("%s not set", name)
	}
	return v
}
