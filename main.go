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
	"sync"
	"time"
)

func createCACert() (*x509.Certificate, *rsa.PrivateKey, error) {
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

	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)

	// create our private and public key
	return ca, privateKey, err
}

func (p *mitmProxy) certSetup(host string) (serverTLSConf *tls.Config, err error) {
	// set up our server certificate
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			Organization:  []string{"Company, INC."},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"San Francisco"},
			StreetAddress: []string{"Golden Gate Bridge"},
			PostalCode:    []string{"94016"},
		},
		DNSNames:     []string{host},
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

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, p.caCert, &certPrivKey.PublicKey, p.caKey)
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
	caCert      *x509.Certificate
	caKey       any
	configCache map[string]*tls.Config
}

// createMitmProxy creates a new MITM proxy. It should be passed the filenames
// for the certificate and private key of a certificate authority trusted by the
// client's machine.
func createMitmProxy() *mitmProxy {
	caCert, caKey, err := createCACert()
	if err != nil {
		return nil
	}
	return &mitmProxy{caCert: caCert, caKey: caKey, configCache: map[string]*tls.Config{}}
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
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		slog.Error("http server doesn't support hijacking connection")
		return
	}

	hijacked, _, err := hijacker.Hijack()
	if err != nil {
		slog.Error("http hijacking failed")
		return
	}
	defer closeConnection(hijacked)

	host, _, err := net.SplitHostPort(proxyReq.Host)
	if err != nil {
		slog.Error("error splitting host/port: %+v", err)
		return
	}

	// Configure a new TLS server, pointing it at the client connection, using
	// our certificate. This server will now pretend being the target.
	tlsConfig, ok := p.configCache[host]
	if !ok {
		tlsConfig, err = p.certSetup(host)
		if err != nil {
			slog.Error("error creating server configuration: %+v", err)
			return
		}

		p.configCache[host] = tlsConfig
	}

	server := tls.Server(hijacked, tlsConfig)

	// Run the proxy in a loop until the client closes the connection.
	request, err := http.ReadRequest(bufio.NewReader(server))
	if err != nil {
		slog.Errorf("reading request failed %+v", err)
		return
	}

	// modify request
	request.Header.Set("Authorization", "bearer token")
	request.Header.Set("Connection", "close")

	dial, err := net.DialTimeout("tcp", proxyReq.RequestURI, 10*time.Second)
	if err != nil {
		slog.Errorf("dialing failed %+v", err)
		return
	}
	defer closeConnection(dial)

	client := tls.Client(dial, &tls.Config{
		InsecureSkipVerify: true,
	})

	err = request.Write(client)
	if err != nil {
		slog.Errorf("forwarding request failed %+v", err)
		return
	}

	wg := &sync.WaitGroup{}

	tunnel(wg, server, client)
	tunnel(wg, client, server)

	wg.Wait()
}

func closeConnection(server io.Closer) {
	slog.Println("closing connection")
	err := server.Close()
	slog.ErrorT(err)
}

func tunnel(wg *sync.WaitGroup, dst io.Writer, src io.Reader) {
	wg.Add(1)
	go func() {
		_, err := io.Copy(dst, src)
		slog.ErrorT(err)
		wg.Done()
	}()
}

func main() {
	proxy := createMitmProxy()

	if err := http.ListenAndServe(":8080", proxy); err != nil {
		slog.Fatal("ListenAndServe:", err)
	}
}
