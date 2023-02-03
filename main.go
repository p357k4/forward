package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"github.com/gookit/slog"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

func certSetup(host string) (serverTLSConf *tls.Config, err error) {
	// set up our CA certificate
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			Organization:  []string{"Company, INC."},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"San Francisco"},
			StreetAddress: []string{"Golden Gate Bridge"},
			PostalCode:    []string{"94016"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	// create our private and public key
	caPrivateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, err
	}

	// create the CA
	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivateKey.PublicKey, caPrivateKey)
	if err != nil {
		return nil, err
	}

	// pem encode
	caPEM := new(bytes.Buffer)
	pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})

	caPrivKeyPEM := new(bytes.Buffer)
	pem.Encode(caPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(caPrivateKey),
	})

	// set up our server certificate
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			CommonName:    host,
			Organization:  []string{"Company, INC."},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"San Francisco"},
			StreetAddress: []string{"Golden Gate Bridge"},
			PostalCode:    []string{"94016"},
		},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	certPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, err
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, ca, &certPrivKey.PublicKey, caPrivateKey)
	if err != nil {
		return nil, err
	}

	certPEM := new(bytes.Buffer)
	pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	certPrivKeyPEM := new(bytes.Buffer)
	pem.Encode(certPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(certPrivKey),
	})

	serverCert, err := tls.X509KeyPair(certPEM.Bytes(), certPrivKeyPEM.Bytes())
	if err != nil {
		return nil, err
	}

	serverTLSConf = &tls.Config{
		CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256},
		MinVersion:       tls.VersionTLS13,
		Certificates:     []tls.Certificate{serverCert},
	}

	return serverTLSConf, nil
}

// mitmProxy is a type implementing http.Handler that serves as a MITM proxy
// for CONNECT tunnels. Create new instances of mitmProxy using createMitmProxy.
type mitmProxy struct {
	//caCert *x509.Certificate
	//caKey  any
}

// createMitmProxy creates a new MITM proxy. It should be passed the filenames
// for the certificate and private key of a certificate authority trusted by the
// client's machine.
func createMitmProxy() *mitmProxy {
	return &mitmProxy{}
}

func (p *mitmProxy) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method == http.MethodConnect {
		p.proxyConnect(w, req)
	} else {
		http.Error(w, "this proxy only supports CONNECT", http.StatusMethodNotAllowed)
	}
}

// proxyConnect implements the MITM proxy for CONNECT tunnels.
func (p *mitmProxy) proxyConnect(w http.ResponseWriter, proxyReq *http.Request) {
	slog.Printf("CONNECT requested to %v (from %v)", proxyReq.Host, proxyReq.RemoteAddr)

	w.WriteHeader(http.StatusOK)

	// "Hijack" the client connection to get a TCP (or TLS) socket we can read
	// and write arbitrary data to/from.
	hj, ok := w.(http.Hijacker)
	if !ok {
		slog.Error("http server doesn't support hijacking connection")
		return
	}

	clientConn, _, err := hj.Hijack()
	if err != nil {
		slog.Error("http hijacking failed")
		return
	}

	// proxyReq.Host will hold the CONNECT target host, which will typically have
	// a port - e.g. example.org:443
	// To generate a fake certificate for example.org, we have to first split off
	// the host from the port.
	host, _, err := net.SplitHostPort(proxyReq.Host)
	if err != nil {
		slog.Error("error splitting host/port:", err)
		return
	}

	// Configure a new TLS server, pointing it at the client connection, using
	// our certificate. This server will now pretend being the target.
	tlsConfig, _ := certSetup(host)

	server := tls.Server(clientConn, tlsConfig)
	defer server.Close()

	dial, err := net.Dial("tcp", proxyReq.RequestURI)
	if err != nil {
		return
	}
	client := tls.Client(dial, &tls.Config{
		InsecureSkipVerify: true,
	})
	defer client.Close()

	// Create a buffered reader for the client connection; this is required to
	// use http package functions with this connection.
	connReader := bufio.NewReader(server)

	wg := &sync.WaitGroup{}

	// Run the proxy in a loop until the client closes the connection.
	for {
		request, err := http.ReadRequest(connReader)
		if err != nil {
			return
		}

		request.Header.Set("Authorization", "bearer token")
		request.Write(client)
		http.Request{}.Write()
		str, err := connReader.ReadString('\n')
		if err == io.EOF {
			break
		}

		if err != nil {
			slog.Errorf("injection failed %+v", err)
			break
		}

		slog.Print(str)
		_, err = client.Write([]byte(str))
		if err != nil {
			slog.Errorf("injection failed %+v", err)
			break
		}

		if !strings.HasPrefix(str, "Host: ") {
			continue
		}

		_, err = client.Write([]byte(str))
		if err != nil {
			slog.Errorf("injection failed %+v", err)
			break
		}

		wg.Add(1)
		go func(wg *sync.WaitGroup) {
			defer wg.Done()
			io.Copy(server, client)
		}(wg)

		wg.Add(1)
		go func(wg *sync.WaitGroup) {
			defer wg.Done()
			io.Copy(client, server)
		}(wg)

		break
	}

	wg.Wait()
}

func main() {
	proxy := createMitmProxy()

	if err := http.ListenAndServe(":8080", proxy); err != nil {
		slog.Fatal("ListenAndServe:", err)
	}
}
