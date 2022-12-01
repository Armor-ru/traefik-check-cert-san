package checkCertSAN

import (
	"bytes"
	"log"
	"os"
	"context"
	"fmt"
	"net/http"
	"net/url"
	"net"
	"text/template"
)

type CertificateRequest struct {
    DNSNames       []string
    URIs           []*url.URL
    IPAddresses    []*net.IP
}

type Config struct {
    CheckDNS    bool     `json:"CheckDNS, omitempty"`
    CheckURI    bool     `json:"CheckURI, omitempty"`
    CheckIP    bool     `json:"CheckIP, omitempty"`
}

func CreateConfig() *Config {
	return &Config {}
}

type checkSAN struct {
	next        http.Handler
	name        string
    CheckDNS    bool
    CheckURI    bool
    CheckIP     bool
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	return &checkSAN{
		next: next,
		name: name,
        CheckDNS: config.CheckDNS,
        CheckURI: config.CheckURI,
        CheckIP: config.CheckIP,
	}, nil
}

func (e *checkSAN) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	certs := req.TLS.PeerCertificates[0]

    if e.CheckIP {
        ips := certs.IPAddresses

        for _, ip := range ips {
            if ip.String() == req.RemoteAddr {
                e.CheckIP = false
                break
            }
        }
    }

    if e.CheckDNS {
        dnses := certs.DNSNames

        for _, dns := range dnses {
            if dns == req.URL.Host {
                e.CheckDNS = false
                break
            }
        }
    }

    if e.CheckURI {
        uris := certs.URIs

        for _, uri := range uris {
            if uri.Path == req.URL.Path {
                e.CheckURI = false
                break
            }
        }
    }


    if e.CheckIP || e.CheckDNS || e.CheckURI {
        http.Error(rw, "You don't have permission to access /cgi-bin on this server.", 403)
        return
    }

	e.next.ServeHTTP(rw, req)
}
