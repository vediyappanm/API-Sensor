// gotls_server.go — minimal self-contained Go crypto/tls workload for the e2e
// capture test. It serves HTTPS and continuously makes HTTPS requests to itself,
// so a sensor attached to this process exercises the Go crypto/tls uprobe path
// (the trickiest capture path — offsets resolved via ELF symbols + disassembly).
// Stdlib only, no external modules, so it builds offline in CI.
//
// Usage: gotls_server <port> <cert.pem> <key.pem>
package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

func main() {
	if len(os.Args) != 4 {
		fmt.Fprintln(os.Stderr, "usage: gotls_server <port> <cert.pem> <key.pem>")
		os.Exit(2)
	}
	port := os.Args[1]
	cert, err := tls.LoadX509KeyPair(os.Args[2], os.Args[3])
	if err != nil {
		fmt.Fprintln(os.Stderr, "cert load:", err)
		os.Exit(1)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "ok\n")
	})
	srv := &http.Server{
		Addr:      "127.0.0.1:" + port,
		Handler:   mux,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}},
	}

	// Self-driving client loop: generates Go crypto/tls read+write traffic.
	go func() {
		client := &http.Client{
			Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
			Timeout:   2 * time.Second,
		}
		url := "https://127.0.0.1:" + port + "/ping?ssn=123-45-6789&email=carol@example.com"
		for {
			time.Sleep(300 * time.Millisecond)
			if resp, err := client.Get(url); err == nil {
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
		}
	}()

	if err := srv.ListenAndServeTLS("", ""); err != nil {
		fmt.Fprintln(os.Stderr, "server:", err)
		os.Exit(1)
	}
}
