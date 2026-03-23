// Go gRPC test server — exercises crypto/tls + HTTP/2 + gRPC content-type detection
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"log"
	"math/big"
	"net"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthgrpc "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"
)

func selfSignedCert() (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{"grpc-server", "localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, priv.Public(), priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	privDER, _ := x509.MarshalECPrivateKey(priv)
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privDER})
	return tls.X509KeyPair(certPEM, privPEM)
}

func main() {
	cert, err := selfSignedCert()
	if err != nil {
		log.Fatalf("cert gen failed: %v", err)
	}

	creds := credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})

	s := grpc.NewServer(grpc.Creds(creds))

	// Health service — standard gRPC service that generates application/grpc traffic
	hs := health.NewServer()
	healthgrpc.RegisterHealthServer(s, hs)
	hs.SetServingStatus("", healthgrpc.HealthCheckResponse_SERVING)
	hs.SetServingStatus("sentinel.test.TradeService", healthgrpc.HealthCheckResponse_SERVING)

	// Reflection — allows service discovery via gRPC reflection protocol
	reflection.Register(s)

	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("listen failed: %v", err)
	}
	log.Println("gRPC TLS server on grpcs://0.0.0.0:50051")
	log.Fatal(s.Serve(lis))
}
