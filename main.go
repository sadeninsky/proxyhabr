package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
)

const (
	port = ":8080"
)

func handleTunneling(w http.ResponseWriter, r *http.Request) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		panic("Hijacking not supported")
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		panic("Cannot hijack connection " + err.Error())
	}
	mitm(r, clientConn)
}

func main() {

	certificate, err := generateCertificate()
	if err != nil {
		log.Fatalf("cannot generate certificate: %v", err)
	}
	tlsConfig = &tls.Config{
		Certificates: make([]tls.Certificate, 1),
	}
	tlsConfig.Certificates[0] = certificate

	server := &http.Server{
		Addr: port,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodConnect {
				http.Error(w, "not implemented", http.StatusNotImplemented)
			}
			handleTunneling(w, r)
		}),
		// Disable HTTP/2.
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
	}
	fmt.Printf("Starting on %s ...\n", port)
	log.Fatal(server.ListenAndServe())
}
