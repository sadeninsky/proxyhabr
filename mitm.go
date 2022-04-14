package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"github.com/PuerkitoBio/goquery"
	"golang.org/x/net/html"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

var (
	httpsRegexp      = regexp.MustCompile(`^https:\/\/`)
	defaultTLSConfig = &tls.Config{InsecureSkipVerify: true}
	tr               = &http.Transport{TLSClientConfig: defaultTLSConfig}
	tlsConfig        *tls.Config
)

func isEof(r *bufio.Reader) bool {
	_, err := r.Peek(1)
	if err == io.EOF {
		return true
	}
	return false
}

func replaceNodesData(n *html.Node, wordLen int) {
	if n.Type == html.TextNode {
		var data, word strings.Builder
		checkAndModify := func() {
			if word.Len() > 0 {
				str := word.String()
				if utf8.RuneCountInString(str) == wordLen {
					word.WriteString("\u2122")
				}
				data.WriteString(word.String())
				word.Reset()
			}
		}
		for _, sym := range n.Data {
			if unicode.IsLetter(sym) {
				word.WriteRune(sym)
			} else {
				checkAndModify()
				data.WriteRune(sym)
			}
		}
		checkAndModify()
		n.Data = data.String()
	}
	if n.FirstChild != nil {
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			replaceNodesData(c, wordLen)
		}
	}
}

func transform(text string) (string, error) {
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(text))
	if err != nil {
		return "", err
	}

	node := doc.Find("body").Nodes[0]
	replaceNodesData(node, 6)
	return doc.Html()
}

func filterResponse(r *http.Response) *http.Response {
	b, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Printf("Cannot read string from resp body: %v\n", err)
		return r
	}
	r.Body.Close()
	transformed, err := transform(string(b))
	if err != nil {
		log.Printf("Cannot transform string from resp body: %v\n", err)
		r.Body = ioutil.NopCloser(bytes.NewReader(b))
		return r
	}
	r.Body = ioutil.NopCloser(bytes.NewBufferString(transformed))
	return r
}

func removeProxyHeaders(r *http.Request) {
	r.RequestURI = ""
	r.Header.Del("Accept-Encoding")
	r.Header.Del("Proxy-Connection")
	r.Header.Del("Proxy-Authenticate")
	r.Header.Del("Proxy-Authorization")
	if r.Header.Get("Connection") == "close" {
		r.Close = false
	}
	r.Header.Del("Connection")
}

func mitm(r *http.Request, proxyClient net.Conn) {
	proxyClient.Write([]byte("HTTP/1.0 200 OK\r\n\r\n"))

	go func() {
		rawClientTls := tls.Server(proxyClient, tlsConfig)
		if err := rawClientTls.Handshake(); err != nil {
			log.Printf("Cannot handshake client %v %v\n", r.Host, err)
			return
		}
		defer rawClientTls.Close()
		clientTlsReader := bufio.NewReader(rawClientTls)
		for !isEof(clientTlsReader) {
			req, err := http.ReadRequest(clientTlsReader)
			if err != nil && err != io.EOF {
				return
			}
			if err != nil {
				log.Printf("Cannot read TLS request from mitm'd client %v %v\n", r.Host, err)
				return
			}
			req.RemoteAddr = r.RemoteAddr
			log.Printf("req %v\n", r.Host)

			if !httpsRegexp.MatchString(req.URL.String()) {
				req.URL, err = url.Parse("https://" + r.Host + req.URL.String())
			}

			removeProxyHeaders(req)

			resp, err := tr.RoundTrip(req)
			if err != nil {
				log.Printf("Cannot read TLS response from mitm'd server %v\n", err)
				return
			}

			resp = filterResponse(resp)
			defer resp.Body.Close()

			text := resp.Status
			statusCode := strconv.Itoa(resp.StatusCode) + " "
			if strings.HasPrefix(text, statusCode) {
				text = text[len(statusCode):]
			}
			if _, err := io.WriteString(rawClientTls, "HTTP/1.1"+" "+statusCode+text+"\r\n"); err != nil {
				log.Printf("Cannot write TLS response HTTP status from mitm'd client: %v\n", err)
				return
			}

			resp.Header.Del("Content-Length")
			resp.Header.Set("Transfer-Encoding", "chunked")
			resp.Header.Set("Connection", "close")
			if err := resp.Header.Write(rawClientTls); err != nil {
				log.Printf("Cannot write TLS response header from mitm'd client: %v\n", err)
				return
			}
			if _, err = io.WriteString(rawClientTls, "\r\n"); err != nil {
				log.Printf("Cannot write TLS response header end from mitm'd client: %v\n", err)
				return
			}
			chunked := newChunkedWriter(rawClientTls)
			if _, err := io.Copy(chunked, resp.Body); err != nil {
				log.Printf("Cannot write TLS response body from mitm'd client: %v\n", err)
				return
			}
			if err := chunked.Close(); err != nil {
				log.Printf("Cannot write TLS chunked EOF from mitm'd client: %v\n", err)
				return
			}
			if _, err = io.WriteString(rawClientTls, "\r\n"); err != nil {
				log.Printf("Cannot write TLS response chunked trailer from mitm'd client: %v\n", err)
				return
			}
		}
		log.Printf("Exiting on EOF\n")
	}()

}
