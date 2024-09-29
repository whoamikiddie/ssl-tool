package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/urfave/cli/v2"
)

const (
	R = "\033[38;5;196m"
	G = "\033[38;5;82m"
	C = "\033[38;5;117m"
	W = "\033[0m"
	Y = "\033[38;5;226m"
)

type OutputConfig struct {
	FilePath string `json:"filePath"`
}

type CertificateInfo struct {
	Protocol           string              `json:"protocol"`
	Cipher             uint16              `json:"cipher"`
	Subject            map[string]string   `json:"subject"`
	Issuer             map[string]string   `json:"issuer"`
	Version            string              `json:"version"`
	SerialNumber       string              `json:"serialNumber"`
	NotBefore          string              `json:"notBefore"`
	NotAfter           string              `json:"notAfter"`
	KeyLength          int                 `json:"keyLength"`
	SignatureAlgorithm string              `json:"signatureAlgorithm"`
	Chain              []CertificateDetail `json:"chain,omitempty"`
}

type CertificateDetail struct {
	Subject            map[string]string `json:"subject"`
	Issuer             map[string]string `json:"issuer"`
	Version            string            `json:"version"`
	SerialNumber       string            `json:"serialNumber"`
	NotBefore          string            `json:"notBefore"`
	NotAfter           string            `json:"notAfter"`
	KeyLength          int               `json:"keyLength"`
	SignatureAlgorithm string            `json:"signatureAlgorithm"`
}

func logWriter(message string) {
	logFile, err := os.OpenFile("ssl_log.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Failed to open log file: %v", err)
	}
	defer logFile.Close()
	if _, err := logFile.WriteString(message + "\n"); err != nil {
		log.Fatalf("Failed to write to log file: %v", err)
	}
}

func display(data CertificateInfo) {
	fmt.Println("\n" + Y + "[+] SSL Certificate Information:" + W)
	fmt.Printf("%sProtocol: %s\n", G, data.Protocol)
	fmt.Printf("%sCipher:\n", G)
	fmt.Printf("        └╴0: %s\n", tls.CipherSuiteName(data.Cipher))

	fmt.Println(Y + "[+] Subject:" + W)
	for k, v := range data.Subject {
		fmt.Printf("        └╴%s: %s\n", k, v)
	}

	fmt.Println(Y + "[+] Issuer:" + W)
	for k, v := range data.Issuer {
		fmt.Printf("        └╴%s: %s\n", k, v)
	}

	fmt.Printf("%sVersion: %s\n", G, data.Version)
	fmt.Printf("%sSerial Number: %s\n", G, data.SerialNumber)
	fmt.Printf("%sNot Before: %s\n", G, data.NotBefore)
	fmt.Printf("%sNot After: %s\n", G, data.NotAfter)
	fmt.Printf("%sKey Length: %d bits\n", G, data.KeyLength)
	fmt.Printf("%sSignature Algorithm: %s\n", G, data.SignatureAlgorithm)

	if len(data.Chain) > 0 {
		fmt.Println(Y + "[+] Certificate Chain:" + W)
		for i, cert := range data.Chain {
			fmt.Printf("  └╴Certificate %d:\n", i)
			for k, v := range cert.Subject {
				fmt.Printf("        └╴%s: %s\n", k, v)
			}
			for k, v := range cert.Issuer {
				fmt.Printf("        └╴%s: %s\n", k, v)
			}
			fmt.Printf("        └╴Version: %s\n", cert.Version)
			fmt.Printf("        └╴Serial Number: %s\n", cert.SerialNumber)
			fmt.Printf("        └╴Not Before: %s\n", cert.NotBefore)
			fmt.Printf("        └╴Not After: %s\n", cert.NotAfter)
			fmt.Printf("        └╴Key Length: %d bits\n", cert.KeyLength)
			fmt.Printf("        └╴Signature Algorithm: %s\n", cert.SignatureAlgorithm)
		}
	}
}

func export(output OutputConfig, data CertificateInfo) {
	var content string
	fileExt := filepath.Ext(output.FilePath)

	if fileExt == ".txt" {
		content = formatText(data)
	} else {
		content = formatJSON(data)
	}

	if err := ioutil.WriteFile(output.FilePath, []byte(content), 0644); err != nil {
		log.Fatalf("Failed to write to output file: %v", err)
	}
	fmt.Printf("%s[+] Data exported to %s%s\n", G, output.FilePath, W)
}

func formatText(data CertificateInfo) string {
	content := fmt.Sprintf("Protocol: %s\n", data.Protocol)
	content += fmt.Sprintf("Cipher:\n  └╴0: %s\n", tls.CipherSuiteName(data.Cipher))
	content += "Subject:\n"
	for k, v := range data.Subject {
		content += fmt.Sprintf("  └╴%s: %s\n", k, v)
	}
	content += "Issuer:\n"
	for k, v := range data.Issuer {
		content += fmt.Sprintf("  └╴%s: %s\n", k, v)
	}
	content += fmt.Sprintf("Version: %s\n", data.Version)
	content += fmt.Sprintf("Serial Number: %s\n", data.SerialNumber)
	content += fmt.Sprintf("Not Before: %s\n", data.NotBefore)
	content += fmt.Sprintf("Not After: %s\n", data.NotAfter)
	content += fmt.Sprintf("Key Length: %d bits\n", data.KeyLength)
	content += fmt.Sprintf("Signature Algorithm: %s\n", data.SignatureAlgorithm)

	for i, cert := range data.Chain {
		content += fmt.Sprintf("Certificate %d:\n", i)
		for k, v := range cert.Subject {
			content += fmt.Sprintf("  └╴%s: %s\n", k, v)
		}
		for k, v := range cert.Issuer {
			content += fmt.Sprintf("  └╴%s: %s\n", k, v)
		}
		content += fmt.Sprintf("  └╴Version: %s\n", cert.Version)
		content += fmt.Sprintf("  └╴Serial Number: %s\n", cert.SerialNumber)
		content += fmt.Sprintf("  └╴Not Before: %s\n", cert.NotBefore)
		content += fmt.Sprintf("  └╴Not After: %s\n", cert.NotAfter)
		content += fmt.Sprintf("  └╴Key Length: %d bits\n", cert.KeyLength)
		content += fmt.Sprintf("  └╴Signature Algorithm: %s\n", cert.SignatureAlgorithm)
	}
	return content
}

func formatJSON(data CertificateInfo) string {
	contentBytes, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		log.Fatalf("Failed to marshal JSON: %v", err)
	}
	return string(contentBytes)
}

func getCertificateInfo(ctx context.Context, hostname string, timeout time.Duration, verifyTLS bool) (*CertificateInfo, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", hostname, 443), timeout)
	if err != nil {
		log.Printf("Failed to connect to %s: %v", hostname, err)
		return nil, err
	}
	defer conn.Close()

	tlsConfig := &tls.Config{InsecureSkipVerify: !verifyTLS}
	tlsConn := tls.Client(conn, tlsConfig)

	// Set a timeout for the handshake.
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- tlsConn.Handshake()
	}()

	select {
	case err := <-done:
		if err != nil {
			log.Printf("TLS handshake failed: %v", err)
			return nil, err
		}
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	certs := tlsConn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates found")
	}

	chain := make([]CertificateDetail, len(certs))
	for i, cert := range certs {
		subject := make(map[string]string)
		for _, attr := range cert.Subject.Names {
			subject[attr.Type.String()] = attr.Value.(string)
		}

		issuer := make(map[string]string)
		for _, attr := range cert.Issuer.Names {
			issuer[attr.Type.String()] = attr.Value.(string)
		}

		chain[i] = CertificateDetail{
			Subject:            subject,
			Issuer:             issuer,
			Version:            fmt.Sprintf("%d", cert.Version),
			SerialNumber:       cert.SerialNumber.String(),
			NotBefore:          cert.NotBefore.UTC().Format(time.RFC1123),
			NotAfter:           cert.NotAfter.UTC().Format(time.RFC1123),
			KeyLength:          getKeyLength(cert.PublicKey),
			SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		}
	}

	cert := certs[0]
	subject := make(map[string]string)
	for _, attr := range cert.Subject.Names {
		subject[attr.Type.String()] = attr.Value.(string)
	}

	issuer := make(map[string]string)
	for _, attr := range cert.Issuer.Names {
		issuer[attr.Type.String()] = attr.Value.(string)
	}

	return &CertificateInfo{
		Protocol:           tlsConn.ConnectionState().NegotiatedProtocol,
		Cipher:             tlsConn.ConnectionState().CipherSuite,
		Subject:            subject,
		Issuer:             issuer,
		Version:            fmt.Sprintf("%d", cert.Version),
		SerialNumber:       cert.SerialNumber.String(),
		NotBefore:          cert.NotBefore.UTC().Format(time.RFC1123),
		NotAfter:           cert.NotAfter.UTC().Format(time.RFC1123),
		KeyLength:          getKeyLength(cert.PublicKey),
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		Chain:              chain,
	}, nil
}

// getKeyLength returns the key length in bits for a given public key.
func getKeyLength(pubKey interface{}) int {
	switch key := pubKey.(type) {
	case *rsa.PublicKey:
		return key.Size() * 8
	case *ecdsa.PublicKey:
		return key.Params().BitSize
	default:
		return 0
	}
}

func banner() {
	fmt.Println(G + "===================================================" + W)
	fmt.Println(G + "               SSL Certificate Tool                  " + W)
	fmt.Println(G + "            Fetch  SSL Certificates   --> whoamikiide{v0.0}   " + W)
	fmt.Println(G + "===================================================" + W)
}

func main() {
	app := &cli.App{
		Name:  "sslinfo",
		Usage: "Fetch SSL certificate information",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "domain",
				Aliases:  []string{"d"},
				Usage:    "Domain to fetch SSL information from",
				Required: true,
			},
			&cli.StringFlag{
				Name:     "output",
				Aliases:  []string{"o"},
				Usage:    "Output file path",
				Required: true,
			},
			&cli.DurationFlag{
				Name:    "timeout",
				Aliases: []string{"t"},
				Value:   5 * time.Second,
				Usage:   "Timeout duration for the connection",
			},
			&cli.BoolFlag{
				Name:  "verify",
				Value: false,
				Usage: "Verify the SSL certificate",
			},
		},
		Action: func(c *cli.Context) error {
			banner()

			domain := c.String("domain")
			outputFilePath := c.String("output")
			timeout := c.Duration("timeout")
			verifyTLS := c.Bool("verify")

			output := OutputConfig{
				FilePath: outputFilePath,
			}

			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			certInfo, err := getCertificateInfo(ctx, domain, timeout, verifyTLS)
			if err != nil {
				fmt.Printf("%s[-] %sSSL is not present on target URL... Skipping...%s\n", R, C, W)
				logWriter("[sslinfo] SSL is not present on target URL... Skipping...")
				os.Exit(1)
			}

			display(*certInfo)
			export(output, *certInfo)
			logWriter("[sslinfo] Completed")

			return nil
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatalf("Error running application: %v", err)
	}
}
