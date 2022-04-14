package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"
)

const (
	rsaBits      = 2048
	certDuration = 1000000
	certHost     = "habr.com:443"
	isCA         = true
)

func publicKey(priv any) any {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	case ed25519.PrivateKey:
		return k.Public().(ed25519.PublicKey)
	default:
		return tls.Certificate{}
	}
}

func generateCertificate() (tls.Certificate, error) {
	var priv any
	var err error
	priv, err = rsa.GenerateKey(rand.Reader, rsaBits)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to generate private key: %v", err)
	}
	keyUsage := x509.KeyUsageDigitalSignature
	if _, isRSA := priv.(*rsa.PrivateKey); isRSA {
		keyUsage |= x509.KeyUsageKeyEncipherment
	}

	notBefore := time.Now()

	notAfter := notBefore.Add(certDuration)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to generate serial number: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              keyUsage,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	hosts := strings.Split(certHost, ",")
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	if isCA {
		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey(priv), priv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to create certificate: %v", err)
	}

	var certOut bytes.Buffer
	if err := pem.Encode(&certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to write data to cert.pem: %v", err)
	}

	var keyOut bytes.Buffer

	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("unable to marshal private key: %v", err)
	}
	if err := pem.Encode(&keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}); err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to write data to key.pem: %v", err)
	}

	return tls.X509KeyPair(certOut.Bytes(), keyOut.Bytes())
}
