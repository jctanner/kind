package main

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// JWKSCache fetches and caches JWKS keys from an OIDC issuer
type JWKSCache struct {
	mu   sync.RWMutex
	keys map[string]*rsa.PublicKey
}

func newJWKSCache(issuerURL string) *JWKSCache {
	cache := &JWKSCache{keys: make(map[string]*rsa.PublicKey)}
	cache.refresh(issuerURL)
	go func() {
		for {
			time.Sleep(5 * time.Minute)
			cache.refresh(issuerURL)
		}
	}()
	return cache
}

func (c *JWKSCache) refresh(issuerURL string) {
	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}

	// Fetch OIDC discovery
	discoveryURL := strings.TrimRight(issuerURL, "/") + "/.well-known/openid-configuration"
	resp, err := client.Get(discoveryURL)
	if err != nil {
		log.Printf("[ocp-shim] JWKS refresh: discovery fetch failed: %v", err)
		return
	}
	defer resp.Body.Close()
	var discovery struct {
		JwksURI string `json:"jwks_uri"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&discovery); err != nil || discovery.JwksURI == "" {
		log.Printf("[ocp-shim] JWKS refresh: discovery parse failed: %v", err)
		return
	}

	// Fetch JWKS
	resp2, err := client.Get(discovery.JwksURI)
	if err != nil {
		log.Printf("[ocp-shim] JWKS refresh: jwks fetch failed: %v", err)
		return
	}
	defer resp2.Body.Close()
	var jwks struct {
		Keys []struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(resp2.Body).Decode(&jwks); err != nil {
		log.Printf("[ocp-shim] JWKS refresh: jwks parse failed: %v", err)
		return
	}

	newKeys := make(map[string]*rsa.PublicKey)
	for _, k := range jwks.Keys {
		if k.Kty != "RSA" {
			continue
		}
		nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			continue
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			continue
		}
		e := 0
		for _, b := range eBytes {
			e = e<<8 + int(b)
		}
		newKeys[k.Kid] = &rsa.PublicKey{
			N: new(big.Int).SetBytes(nBytes),
			E: e,
		}
	}

	c.mu.Lock()
	c.keys = newKeys
	c.mu.Unlock()
	log.Printf("[ocp-shim] JWKS refresh: loaded %d keys", len(newKeys))
}

func (c *JWKSCache) getKey(kid string) *rsa.PublicKey {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.keys[kid]
}

func validateJWTToken(tokenStr string, cache *JWKSCache) (string, []string, bool) {
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		kid, _ := token.Header["kid"].(string)
		key := cache.getKey(kid)
		if key == nil {
			return nil, fmt.Errorf("unknown kid: %s", kid)
		}
		return key, nil
	})
	if err != nil || !token.Valid {
		log.Printf("[ocp-shim] JWT validation failed: %v", err)
		return "", nil, false
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", nil, false
	}

	username, _ := claims["preferred_username"].(string)
	if username == "" {
		username, _ = claims["sub"].(string)
	}
	if username == "" {
		return "", nil, false
	}

	var groups []string
	if g, ok := claims["groups"].([]interface{}); ok {
		for _, v := range g {
			if s, ok := v.(string); ok {
				groups = append(groups, s)
			}
		}
	}
	if len(groups) == 0 {
		groups = []string{"system:authenticated"}
	}

	return username, groups, true
}

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
		PreferredUsername string   `json:"preferred_username"`
		Groups           []string `json:"groups"`
	}
	if err := json.Unmarshal(body, &info); err != nil || info.PreferredUsername == "" {
		return "", nil, false
	}
	groups := info.Groups
	if len(groups) == 0 {
		groups = []string{"system:authenticated"}
	}
	return info.PreferredUsername, groups, true
}

func extractTokenFromBody(body []byte) string {
	s := string(body)
	for _, prefix := range []string{"sha256~", "eyJ"} {
		idx := strings.Index(s, prefix)
		if idx < 0 {
			continue
		}
		end := idx
		for end < len(s) && s[end] >= '!' && s[end] <= '~' {
			end++
		}
		return s[idx:end]
	}
	return ""
}

func handleTokenReview(w http.ResponseWriter, body []byte, userinfoURL string, jwksCache *JWKSCache) {
	var token string
	isJSON := len(body) > 0 && body[0] == '{'

	if isJSON {
		var review struct {
			Spec struct {
				Token string `json:"token"`
			} `json:"spec"`
		}
		if err := json.Unmarshal(body, &review); err != nil {
			log.Printf("[ocp-shim] TokenReview unmarshal error: %v", err)
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		token = review.Spec.Token
	} else {
		token = extractTokenFromBody(body)
	}

	if token == "" {
		log.Printf("[ocp-shim] TokenReview: no token found")
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	log.Printf("[ocp-shim] TokenReview: tokenLen=%d isJSON=%v", len(token), isJSON)

	var user string
	var groups []string
	var ok bool
	if strings.HasPrefix(token, "eyJ") && jwksCache != nil {
		user, groups, ok = validateJWTToken(token, jwksCache)
	} else {
		user, groups, ok = validateOAuthToken("Bearer "+token, userinfoURL)
	}
	if !ok {
		log.Printf("[ocp-shim] TokenReview: auth failed")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"apiVersion": "authentication.k8s.io/v1",
			"kind":       "TokenReview",
			"metadata":   map[string]interface{}{},
			"status": map[string]interface{}{
				"authenticated": false,
			},
		})
		return
	}

	log.Printf("[ocp-shim] TokenReview: auth OK user=%s", user)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"apiVersion": "authentication.k8s.io/v1",
		"kind":       "TokenReview",
		"metadata":   map[string]interface{}{},
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

func serveUserObject(w http.ResponseWriter, username string, groups []string) {
	if len(groups) == 0 {
		groups = []string{"system:authenticated"}
	}
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
		"groups":     groups,
	})
}

func handleProjectRequest(w http.ResponseWriter, r *http.Request, proxy *httputil.ReverseProxy) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	var req struct {
		Metadata struct {
			Name string `json:"name"`
		} `json:"metadata"`
		DisplayName string `json:"displayName"`
		Description string `json:"description"`
	}
	if err := json.Unmarshal(body, &req); err != nil || req.Metadata.Name == "" {
		http.Error(w, "bad request: missing metadata.name", http.StatusBadRequest)
		return
	}

	projectBody, _ := json.Marshal(map[string]interface{}{
		"apiVersion": "project.openshift.io/v1",
		"kind":       "Project",
		"metadata": map[string]interface{}{
			"name": req.Metadata.Name,
		},
	})

	projectReq, _ := http.NewRequest("POST",
		"/apis/project.openshift.io/v1/projects",
		strings.NewReader(string(projectBody)))
	projectReq.Header.Set("Content-Type", "application/json")
	for _, h := range []string{"X-Remote-User", "X-Remote-Group", "Authorization"} {
		if v := r.Header.Get(h); v != "" {
			projectReq.Header.Set(h, v)
		}
	}

	recorder := &responseRecorder{headers: http.Header{}, statusCode: 200}
	proxy.ServeHTTP(recorder, projectReq)

	if recorder.statusCode >= 300 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(recorder.statusCode)
		w.Write(recorder.body)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"apiVersion": "project.openshift.io/v1",
		"kind":       "Project",
		"metadata": map[string]interface{}{
			"name": req.Metadata.Name,
		},
		"status": map[string]interface{}{
			"phase": "Active",
		},
	})
}

type responseRecorder struct {
	headers    http.Header
	body       []byte
	statusCode int
}

func (r *responseRecorder) Header() http.Header         { return r.headers }
func (r *responseRecorder) WriteHeader(statusCode int)   { r.statusCode = statusCode }
func (r *responseRecorder) Write(b []byte) (int, error)  { r.body = append(r.body, b...); return len(b), nil }

const wsSubprotocolPrefix = "base64url.bearer.authorization.k8s.io."

func extractWebSocketBearerToken(r *http.Request) string {
	for _, proto := range r.Header.Values("Sec-WebSocket-Protocol") {
		for _, p := range strings.Split(proto, ",") {
			p = strings.TrimSpace(p)
			if strings.HasPrefix(p, wsSubprotocolPrefix) {
				encoded := strings.TrimPrefix(p, wsSubprotocolPrefix)
				decoded, err := base64.RawURLEncoding.DecodeString(encoded)
				if err != nil {
					log.Printf("ocp-shim: failed to decode websocket bearer token: %v", err)
					return ""
				}
				return string(decoded)
			}
		}
	}
	return ""
}

func removeWebSocketBearerSubprotocol(r *http.Request) {
	var kept []string
	for _, proto := range r.Header.Values("Sec-WebSocket-Protocol") {
		for _, p := range strings.Split(proto, ",") {
			p = strings.TrimSpace(p)
			if !strings.HasPrefix(p, wsSubprotocolPrefix) && p != "" {
				kept = append(kept, p)
			}
		}
	}
	r.Header.Del("Sec-WebSocket-Protocol")
	if len(kept) > 0 {
		r.Header.Set("Sec-WebSocket-Protocol", strings.Join(kept, ", "))
	}
}

func handleWebSocketProxy(w http.ResponseWriter, r *http.Request, upstreamURL *url.URL, upstreamTLS *tls.Config) {
	upstreamHost := upstreamURL.Host
	if !strings.Contains(upstreamHost, ":") {
		upstreamHost += ":443"
	}

	upstreamConn, err := tls.Dial("tcp", upstreamHost, upstreamTLS)
	if err != nil {
		log.Printf("ocp-shim: websocket upstream dial failed: %v", err)
		http.Error(w, "upstream connection failed", http.StatusBadGateway)
		return
	}

	r.URL.Scheme = "https"
	r.URL.Host = upstreamURL.Host
	r.Header.Set("Origin", upstreamURL.Scheme+"://"+upstreamURL.Host)
	r.Host = upstreamURL.Host
	if err := r.Write(upstreamConn); err != nil {
		log.Printf("ocp-shim: websocket write request to upstream failed: %v", err)
		upstreamConn.Close()
		http.Error(w, "upstream write failed", http.StatusBadGateway)
		return
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		log.Println("ocp-shim: hijacking not supported")
		upstreamConn.Close()
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		log.Printf("ocp-shim: hijack failed: %v", err)
		upstreamConn.Close()
		return
	}

	log.Printf("ocp-shim: websocket proxy established for %s", r.URL.Path)

	var wg sync.WaitGroup
	wg.Add(2)
	cp := func(label string, dst, src net.Conn) {
		defer wg.Done()
		n, err := io.Copy(dst, src)
		log.Printf("ocp-shim: ws copy %s done: %d bytes, err=%v", label, n, err)
	}
	go cp("client→upstream", upstreamConn, clientConn)
	go cp("upstream→client", clientConn, upstreamConn)
	wg.Wait()
	clientConn.Close()
	upstreamConn.Close()
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
	oauthUserinfoURL := flag.String("oauth-userinfo-url", "https://localhost:443/oauth/userinfo", "URL of the simulator OAuth userinfo endpoint")
	oidcIssuerURL := flag.String("oidc-issuer-url", "", "OIDC issuer URL for JWT validation via JWKS (enables dual-mode auth)")
	flag.Parse()

	logFile, err := os.OpenFile("/tmp/ocp-shim.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err == nil {
		log.SetOutput(logFile)
	}

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

	issuerURL := *oidcIssuerURL
	if envIssuer := os.Getenv("OIDC_ISSUER_URL"); envIssuer != "" {
		issuerURL = envIssuer
	}
	var jwksCache *JWKSCache
	if issuerURL != "" {
		jwksCache = newJWKSCache(issuerURL)
		fmt.Printf("ocp-shim: OIDC JWKS validation enabled (issuer: %s)\n", issuerURL)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(wellKnownData)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Bearer token validation: translate tokens to front-proxy headers
		if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
			tokenStr := strings.TrimPrefix(auth, "Bearer ")
			var user string
			var groups []string
			var ok bool
			if strings.HasPrefix(tokenStr, "sha256~") {
				user, groups, ok = validateOAuthToken(auth, userinfoURL)
			} else if strings.HasPrefix(tokenStr, "eyJ") && jwksCache != nil {
				user, groups, ok = validateJWTToken(tokenStr, jwksCache)
			}
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

		// Log all tokenreview requests for debugging
		if strings.Contains(r.URL.Path, "tokenreview") {
			log.Printf("[ocp-shim] tokenreview request: method=%s path=%s from=%s", r.Method, r.URL.Path, r.RemoteAddr)
		}

		// Intercept POST /apis/authentication.k8s.io/v1/tokenreviews for sha256~ and JWT tokens
		if r.Method == "POST" && r.URL.Path == "/apis/authentication.k8s.io/v1/tokenreviews" {
			bodyBytes, err := io.ReadAll(r.Body)
			hasSHA := strings.Contains(string(bodyBytes), "sha256~")
			hasJWT := strings.Contains(string(bodyBytes), "eyJ")
			log.Printf("[ocp-shim] TokenReview body: len=%d hasSHA256=%v hasJWT=%v from=%s", len(bodyBytes), hasSHA, hasJWT, r.RemoteAddr)
			if err == nil && (hasSHA || (hasJWT && jwksCache != nil)) {
				handleTokenReview(w, bodyBytes, userinfoURL, jwksCache)
				return
			}
			r.Body = io.NopCloser(strings.NewReader(string(bodyBytes)))
		}

		// Intercept POST /apis/project.openshift.io/v1/projectrequests
		if r.Method == "POST" && r.URL.Path == "/apis/project.openshift.io/v1/projectrequests" {
			handleProjectRequest(w, r, proxy)
			return
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
			serveUserObject(w, user, r.Header.Values("X-Remote-Group"))
			return
		}

		// WebSocket upgrade: extract bearer token from subprotocol, authenticate, then tunnel
		if strings.EqualFold(r.Header.Get("Connection"), "upgrade") &&
			strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			token := extractWebSocketBearerToken(r)
			log.Printf("ocp-shim: ws %s subproto=%q token=%q remoteUser=%q",
				r.URL.Path,
				r.Header.Get("Sec-WebSocket-Protocol"),
				token,
				r.Header.Get("X-Remote-User"))
			if token != "" {
				var user string
				var groups []string
				var ok bool
				if strings.HasPrefix(token, "sha256~") {
					user, groups, ok = validateOAuthToken("Bearer "+token, userinfoURL)
				} else if strings.HasPrefix(token, "eyJ") && jwksCache != nil {
					user, groups, ok = validateJWTToken(token, jwksCache)
				} else {
					log.Printf("ocp-shim: websocket token unrecognized: %s", token[:min(len(token), 20)])
				}
				if ok {
					r.Header.Set("X-Remote-User", user)
					for _, g := range groups {
						r.Header.Add("X-Remote-Group", g)
					}
					removeWebSocketBearerSubprotocol(r)
					log.Printf("ocp-shim: websocket auth for user %s on %s", user, r.URL.Path)
				} else if user == "" && !ok && token != "" {
					log.Printf("ocp-shim: websocket auth failed for %s", r.URL.Path)
				}
			}
			handleWebSocketProxy(w, r, upstreamURL, upstreamTLS)
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
	if issuerURL != "" {
		fmt.Printf("ocp-shim: OIDC issuer URL: %s\n", issuerURL)
	}
	if err := server.ListenAndServeTLS(*tlsCert, *tlsKey); err != nil {
		log.Fatalf("server failed: %v", err)
	}
}
