package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
)

func validateOAuthToken(authHeader, validateURL string) (string, []string, bool) {
	req, err := http.NewRequest("GET", validateURL, nil)
	if err != nil {
		return "", nil, false
	}
	req.Header.Set("Authorization", authHeader)
	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}}
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != 200 {
		return "", nil, false
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", nil, false
	}
	var info struct {
		PreferredUsername string `json:"preferred_username"`
	}
	if err := json.Unmarshal(body, &info); err != nil || info.PreferredUsername == "" {
		return "", nil, false
	}
	return info.PreferredUsername, []string{"system:authenticated"}, true
}

func handleTokenReview(w http.ResponseWriter, body []byte, userinfoURL string) {
	var review struct {
		APIVersion string `json:"apiVersion"`
		Kind       string `json:"kind"`
		Spec       struct {
			Token     string   `json:"token"`
			Audiences []string `json:"audiences"`
		} `json:"spec"`
	}
	if err := json.Unmarshal(body, &review); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	user, groups, ok := validateOAuthToken("Bearer "+review.Spec.Token, userinfoURL)
	if !ok {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"apiVersion": review.APIVersion,
			"kind":       "TokenReview",
			"status": map[string]interface{}{
				"authenticated": false,
			},
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"apiVersion": review.APIVersion,
		"kind":       "TokenReview",
		"status": map[string]interface{}{
			"authenticated": true,
			"user": map[string]interface{}{
				"username": user,
				"uid":      "ocp-sim-" + user,
				"groups":   groups,
			},
		},
	})
}

func serveUserObject(w http.ResponseWriter, username string) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"apiVersion": "user.openshift.io/v1",
		"kind":       "User",
		"metadata": map[string]interface{}{
			"name": username,
			"uid":  "ocp-sim-" + username,
		},
		"fullName":   username,
		"identities": []string{"ocp-sim:" + username},
		"groups":     []string{"system:authenticated"},
	})
}

func main() {
	listen := flag.String("listen", ":6443", "address to listen on")
	upstream := flag.String("upstream", "https://localhost:16443", "upstream API server URL")
	tlsCert := flag.String("tls-cert-file", "", "TLS certificate file")
	tlsKey := flag.String("tls-key-file", "", "TLS key file")
	clientCAFile := flag.String("client-ca-file", "", "CA certificate for verifying client certs")
	proxyClientCert := flag.String("proxy-client-cert-file", "", "client cert for authenticating to upstream as front-proxy")
	proxyClientKey := flag.String("proxy-client-key-file", "", "client key for authenticating to upstream as front-proxy")
	wellKnownFile := flag.String("well-known-file", "", "path to well-known OAuth discovery JSON file")
	oauthUserinfoURL := flag.String("oauth-userinfo-url", "https://localhost:9443/oauth/userinfo", "URL of the simulator OAuth userinfo endpoint")
	flag.Parse()

	if *tlsCert == "" || *tlsKey == "" {
		log.Fatal("--tls-cert-file and --tls-key-file are required")
	}
	if *wellKnownFile == "" {
		log.Fatal("--well-known-file is required")
	}

	wellKnownData, err := os.ReadFile(*wellKnownFile)
	if err != nil {
		log.Fatalf("failed to read well-known file: %v", err)
	}

	upstreamURL, err := url.Parse(*upstream)
	if err != nil {
		log.Fatalf("failed to parse upstream URL: %v", err)
	}

	var clientCAs *x509.CertPool
	if *clientCAFile != "" {
		caPEM, err := os.ReadFile(*clientCAFile)
		if err != nil {
			log.Fatalf("failed to read client CA file: %v", err)
		}
		clientCAs = x509.NewCertPool()
		if !clientCAs.AppendCertsFromPEM(caPEM) {
			log.Fatal("failed to parse client CA certificate")
		}
	}

	upstreamTLS := &tls.Config{InsecureSkipVerify: true}
	if *proxyClientCert != "" && *proxyClientKey != "" {
		cert, err := tls.LoadX509KeyPair(*proxyClientCert, *proxyClientKey)
		if err != nil {
			log.Fatalf("failed to load proxy client cert: %v", err)
		}
		upstreamTLS.Certificates = []tls.Certificate{cert}
	}

	proxy := httputil.NewSingleHostReverseProxy(upstreamURL)
	proxy.Transport = &http.Transport{
		TLSClientConfig: upstreamTLS,
	}

	userinfoURL := *oauthUserinfoURL

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(wellKnownData)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Bearer token validation: translate sha256~ tokens to front-proxy headers
		if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer sha256~") {
			user, groups, ok := validateOAuthToken(auth, userinfoURL)
			if ok {
				r.Header.Del("Authorization")
				r.Header.Set("X-Remote-User", user)
				for _, g := range groups {
					r.Header.Add("X-Remote-Group", g)
				}
			}
		}

		// Client certificate → front-proxy headers (existing behavior)
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			cert := r.TLS.PeerCertificates[0]
			r.Header.Set("X-Remote-User", cert.Subject.CommonName)
			var groups []string
			groups = append(groups, cert.Subject.Organization...)
			for _, g := range groups {
				r.Header.Add("X-Remote-Group", g)
			}
		}

		// Intercept POST /apis/authentication.k8s.io/v1/tokenreviews for sha256~ tokens
		if r.Method == "POST" && r.URL.Path == "/apis/authentication.k8s.io/v1/tokenreviews" {
			bodyBytes, err := io.ReadAll(r.Body)
			if err == nil && strings.Contains(string(bodyBytes), "sha256~") {
				handleTokenReview(w, bodyBytes, userinfoURL)
				return
			}
			r.Body = io.NopCloser(strings.NewReader(string(bodyBytes)))
		}

		// Intercept GET /apis/user.openshift.io/v1/users/~
		if r.Method == "GET" && r.URL.Path == "/apis/user.openshift.io/v1/users/~" {
			user := r.Header.Get("X-Remote-User")
			if user == "" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte(`{"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"Unauthorized","reason":"Unauthorized","code":401}`))
				return
			}
			serveUserObject(w, user)
			return
		}

		proxy.ServeHTTP(w, r)
	})

	tlsConfig := &tls.Config{}
	if clientCAs != nil {
		tlsConfig.ClientCAs = clientCAs
		tlsConfig.ClientAuth = tls.VerifyClientCertIfGiven
	}

	server := &http.Server{
		Addr:      *listen,
		Handler:   mux,
		TLSConfig: tlsConfig,
	}

	fmt.Printf("ocp-shim: listening on %s, proxying to %s\n", *listen, *upstream)
	if clientCAs != nil {
		fmt.Println("ocp-shim: client certificate verification enabled")
	}
	if upstreamTLS.Certificates != nil {
		fmt.Println("ocp-shim: front-proxy client certificate configured")
	}
	fmt.Printf("ocp-shim: OAuth userinfo URL: %s\n", userinfoURL)
	if err := server.ListenAndServeTLS(*tlsCert, *tlsKey); err != nil {
		log.Fatalf("server failed: %v", err)
	}
}
