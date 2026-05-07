# OCP Shim: Bearer Token Auth & `users/~` Endpoint

## Problem

After the OAuth flow completes, kube-auth-proxy holds a bearer token (`sha256~<random>`)
issued by the simulator's mock OAuth server. It then calls:

```
GET /apis/user.openshift.io/v1/users/~
Authorization: Bearer sha256~<random>
```

This request flows through the ocp-shim (port 6443) to the real kube-apiserver (port 16443).
Two things fail:

1. **Token authentication** — the kube-apiserver doesn't recognize our OAuth tokens → 401
2. **`users/~` endpoint** — the `~` alias ("current user") is an OpenShift-specific feature.
   In vanilla k8s with a CRD, `~` is not a valid resource name → would be 404 even if auth passed.

## Solution

Extend the ocp-shim reverse proxy to handle both. It already intercepts
`/.well-known/oauth-authorization-server` and serves it directly. We add two more behaviors:

### 1. Bearer token → front-proxy header translation

When the ocp-shim sees `Authorization: Bearer sha256~...`:

1. Call the simulator's OAuth userinfo endpoint to validate the token:
   ```
   GET https://localhost:9443/oauth/userinfo
   Authorization: Bearer sha256~<token>
   ```
2. If 200 OK, parse `preferred_username` from the JSON response.
3. Strip the `Authorization` header from the proxied request.
4. Set front-proxy headers that the kube-apiserver trusts:
   ```
   X-Remote-User: <preferred_username>
   X-Remote-Group: system:authenticated
   ```
5. Proxy to the upstream API server as usual.
6. If the userinfo call fails (non-200), proxy the request unmodified — the kube-apiserver
   will handle it (e.g., service account tokens with `Bearer ey...` still work natively).

**Key detail:** Only intercept tokens matching the `sha256~` prefix. All other Bearer tokens
(service account JWTs, etc.) must pass through untouched to the real API server.

### 2. Handle `GET /apis/user.openshift.io/v1/users/~`

When the path is `/apis/user.openshift.io/v1/users/~` and the request is authenticated
(i.e., `X-Remote-User` is set after step 1, or the client presented a certificate):

Return a synthetic OpenShift User object:

```json
{
  "apiVersion": "user.openshift.io/v1",
  "kind": "User",
  "metadata": {
    "name": "<username>",
    "uid": "ocp-sim-<username>"
  },
  "fullName": "<username>",
  "identities": ["ocp-sim:<username>"],
  "groups": ["system:authenticated"]
}
```

Where `<username>` comes from `X-Remote-User` (bearer token auth) or
`X-Remote-User` derived from client certificate CN (existing logic).

If the request is not authenticated, return 401.

## Changes to `cmd/ocp-shim/main.go`

### Current structure (unchanged)

```go
mux.HandleFunc("/.well-known/oauth-authorization-server", ...)  // serves JSON file
mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
    // if client cert → set X-Remote-User/X-Remote-Group from cert CN
    proxy.ServeHTTP(w, r)
})
```

### New structure

```go
mux.HandleFunc("/.well-known/oauth-authorization-server", ...)  // unchanged

mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
    // --- NEW: bearer token validation ---
    if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer sha256~") {
        user, groups, ok := validateOAuthToken(auth, oauthValidateURL)
        if ok {
            r.Header.Del("Authorization")
            r.Header.Set("X-Remote-User", user)
            for _, g := range groups {
                r.Header.Add("X-Remote-Group", g)
            }
        }
        // if !ok, pass through unmodified — API server returns 401
    }

    // existing: client cert → X-Remote-User (unchanged)
    if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 { ... }

    // --- NEW: intercept users/~ ---
    if r.Method == "GET" && r.URL.Path == "/apis/user.openshift.io/v1/users/~" {
        user := r.Header.Get("X-Remote-User")
        if user == "" {
            http.Error(w, `{"kind":"Status","apiVersion":"v1","status":"Failure","message":"Unauthorized","code":401}`, 401)
            return
        }
        serveUserObject(w, user)
        return
    }

    proxy.ServeHTTP(w, r)
})
```

### New functions

```go
// validateOAuthToken calls the simulator's /oauth/userinfo to validate a bearer token.
// Returns (username, groups, ok).
func validateOAuthToken(authHeader, validateURL string) (string, []string, bool) {
    req, _ := http.NewRequest("GET", validateURL, nil)
    req.Header.Set("Authorization", authHeader)
    // Use InsecureSkipVerify since the OAuth server uses a self-signed cert
    client := &http.Client{Transport: &http.Transport{
        TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
    }}
    resp, err := client.Do(req)
    if err != nil || resp.StatusCode != 200 {
        return "", nil, false
    }
    defer resp.Body.Close()
    var info struct {
        PreferredUsername string `json:"preferred_username"`
    }
    json.NewDecoder(resp.Body).Decode(&info)
    if info.PreferredUsername == "" {
        return "", nil, false
    }
    return info.PreferredUsername, []string{"system:authenticated"}, true
}

// serveUserObject returns a synthetic OpenShift User object for the given username.
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
```

### New CLI flag

```
--oauth-userinfo-url   URL of the simulator's userinfo endpoint (default: https://localhost:9443/oauth/userinfo)
```

This is passed in the kube-apiserver static pod manifest alongside the existing flags:
```yaml
- --oauth-userinfo-url=https://localhost:9443/oauth/userinfo
```

## Request flow after changes

```
kube-auth-proxy                     ocp-shim (:6443)                kube-apiserver (:16443)
     |                                   |                                |
     |-- GET /apis/.../users/~ --------->|                                |
     |   Authorization: Bearer sha256~X  |                                |
     |                                   |-- GET /oauth/userinfo -------->| (simulator :9443)
     |                                   |   Authorization: Bearer sha256~X
     |                                   |<-- 200 {preferred_username: admin}
     |                                   |                                |
     |                                   | (path matches users/~)         |
     |                                   | (X-Remote-User = admin)        |
     |<-- 200 {kind: User, name: admin} -|                                |
```

## Dependencies

- The simulator's OAuth server already serves `GET /oauth/userinfo` with bearer token
  validation (see `simulator/src/oauth.rs` `handle_userinfo`).
- The ocp-shim runs on `hostNetwork: true` in the same pod as the API server,
  so `localhost:9443` reaches the simulator (which also runs `hostNetwork: true`).
- No kube-apiserver flag changes needed. No CRD changes needed.
- No changes to the simulator Rust code.

## Testing

```bash
# 1. Get a token from the OAuth server
CODE=$(curl -sk 'https://localhost:9443/oauth/authorize?response_type=code&client_id=data-science&redirect_uri=https://rh-ai.apps.ocp-sim.localhost/oauth2/callback' -D - -o /dev/null | grep location | grep -oP 'code=\K[^&]+')
TOKEN=$(curl -sk -X POST https://localhost:9443/oauth/token -d "grant_type=authorization_code&code=$CODE&client_id=data-science&client_secret=..." | jq -r .access_token)

# 2. Call users/~ through the API server (via ocp-shim)
curl -sk -H "Authorization: Bearer $TOKEN" https://localhost:6443/apis/user.openshift.io/v1/users/~
# Expected: 200 with User object {kind: User, metadata: {name: admin}, ...}

# 3. Full browser test
# Open https://rh-ai.apps.ocp-sim.localhost/ → should complete OAuth flow and show dashboard
```
