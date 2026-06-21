package main

import (
	"bufio"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"hash/fnv"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"path"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/go-redis/redis/v7"
	"github.com/golang-jwt/jwt/v5"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
)

// argoCDSecretKeyField is the data key in the ArgoCD secret holding the HMAC
// key ArgoCD uses to sign session JWTs (both local-user and SSO sessions go
// through ArgoCD's own session manager, which always signs with this key).
const argoCDSecretKeyField = "server.secretkey"

const listApplicationsPath = "/api/v1/applications"

// rbacPolicy holds the object glob patterns a subject (user or group) is
// granted, split by ArgoCD policy effect. A deny match always overrides an
// allow match for the same object, so the two are kept separate rather than
// merged into a single pattern list.
type rbacPolicy struct {
	allow []string
	deny  []string
}

// applicationsResource is the only ArgoCD RBAC resource type that gates
// visibility of items in the cached application list. The proxy only ever
// serves /api/v1/applications, so "p" rules for other resource types (e.g.
// "applicationsets", "logs", "exec", "clusters") are out of scope and ignored
// by parsePolicyCSV.
const applicationsResource = "applications"

// Define Prometheus metrics for HTTP request duration (milliseconds) and total request count.
var requestDuration = prometheus.NewHistogramVec(
	prometheus.HistogramOpts{
		Name:    "argocd_proxy_request_duration_milliseconds",
		Help:    "Duration of HTTP requests handled by the argocd proxy in milliseconds.",
		Buckets: []float64{1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000},
	},
	[]string{"method", "path", "statuscode"},
)

var requestTotal = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "argocd_proxy_requests_total",
		Help: "Total number of HTTP requests handled by the argocd proxy.",
	},
	[]string{"method", "path", "statuscode"},
)

func init() {
	log.SetFormatter(&log.JSONFormatter{})
	log.SetOutput(os.Stdout)
}

func main() {
	// Register Prometheus metrics
	prometheus.MustRegister(requestDuration, requestTotal)

	// Define flags for configuration
	redisAddr := flag.String("redis-addr", "localhost:16379", "Redis server address")
	redisDB := flag.Int("redis-db", 1, "Redis database number")
	proxyBackend := flag.String("proxy-backend", "http://localhost:8080", "Backend URL for reverse proxy")
	listenAddr := flag.String("listen-addr", ":8081", "Address the proxy listens on")
	namespace := flag.String("namespace", "argocd", "Namespace where the ArgoCD RBAC ConfigMap lives")
	rbacConfigMap := flag.String("rbac-configmap", "argocd-rbac-cm", "Name of the ArgoCD RBAC ConfigMap")
	argocdSecret := flag.String("argocd-secret", "argocd-secret", "Name of the ArgoCD Secret holding the session-signing key (server.secretkey)")

	// Parse command-line flags
	flag.Parse()

	config := ctrl.GetConfigOrDie()

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Fatalf("Failed to create Kubernetes client: %v", err)
	}

	userToObjectPatternMapping, groupToObjectPatternMapping := loadRBACPolicyFromConfigMap(clientset, *namespace, *rbacConfigMap)
	signingKey := loadSigningKeyFromSecret(clientset, *namespace, *argocdSecret)
	if len(signingKey) == 0 {
		log.Errorf("No JWT signing key available; the cached list-applications fast path is disabled and all requests will be proxied to the backend")
	}

	// Initialize Redis client
	redisClient := initializeRedis(*redisAddr, *redisDB)

	// Create a reverse proxy
	proxy := createReverseProxy(*proxyBackend)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		start := time.Now() // Start measuring time

		rw := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		handleRequest(rw, r, proxy, redisClient, signingKey, userToObjectPatternMapping, groupToObjectPatternMapping)

		// Record duration and total request count
		duration := float64(time.Since(start).Milliseconds())
		statusCodeStr := fmt.Sprintf("%d", rw.statusCode)

		requestTotal.WithLabelValues(r.Method, r.URL.Path, statusCodeStr).Inc()
		requestDuration.WithLabelValues(r.Method, r.URL.Path, statusCodeStr).Observe(duration)
	})

	// Expose Prometheus metrics endpoint
	mux.Handle("/metrics", promhttp.Handler())

	// Liveness and readiness probes for Kubernetes.
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		if err := redisClient.Ping().Err(); err != nil {
			http.Error(w, "redis unavailable", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	srv := &http.Server{
		Addr:    *listenAddr,
		Handler: mux,
		// ReadTimeout/WriteTimeout are left unset to support long-running
		// streaming responses, but ReadHeaderTimeout bounds how long a client
		// may take to send headers, mitigating slowloris-style attacks.
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       15 * time.Second,
	}

	// Handle SIGINT/SIGTERM for graceful shutdown.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		log.Infof("Proxy server running on %s", *listenAddr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()

	// Wait for a termination signal, then drain in-flight requests.
	<-ctx.Done()
	stop()
	log.Infoln("Shutdown signal received, draining connections...")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Errorf("Graceful shutdown failed: %v", err)
	}
	log.Infoln("Proxy server stopped")
}

// Custom response writer to capture status codes
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func loadRBACPolicyFromConfigMap(clientset *kubernetes.Clientset, namespace, configMapName string) (map[string]rbacPolicy, map[string]rbacPolicy) {
	cm, err := clientset.CoreV1().ConfigMaps(namespace).Get(context.Background(), configMapName, metav1.GetOptions{})
	if err != nil {
		log.Errorf("Failed to fetch ConfigMap %s: %v", configMapName, err)
		return nil, nil
	}

	policyCSV, ok := cm.Data["policy.csv"]
	if !ok {
		log.Errorf("policy.csv not found in ConfigMap %s\n", configMapName)
		return nil, nil
	}

	return parsePolicyCSV(policyCSV)
}

// loadSigningKeyFromSecret fetches the HMAC key ArgoCD uses to sign session
// JWTs from the ArgoCD Secret. Without this key the proxy cannot verify the
// authenticity of a token's claims, so callers must treat a nil/empty result
// as "verification unavailable" rather than trusting unverified claims.
func loadSigningKeyFromSecret(clientset *kubernetes.Clientset, namespace, secretName string) []byte {
	secret, err := clientset.CoreV1().Secrets(namespace).Get(context.Background(), secretName, metav1.GetOptions{})
	if err != nil {
		log.Errorf("Failed to fetch Secret %s: %v", secretName, err)
		return nil
	}

	key, ok := secret.Data[argoCDSecretKeyField]
	if !ok || len(key) == 0 {
		log.Errorf("%s not found in Secret %s", argoCDSecretKeyField, secretName)
		return nil
	}
	return key
}

func initializeRedis(addr string, db int) *redis.Client {
	client := redis.NewClient(&redis.Options{
		Addr:        addr,
		DB:          db,
		DialTimeout: 5 * time.Second,
	})

	if _, err := client.Ping().Result(); err != nil {
		log.Fatalf("Failed to connect to Redis: %v", err)
	}
	log.Infoln("Connected to Redis successfully")
	return client
}

func createReverseProxy(target string) *httputil.ReverseProxy {
	parsedURL, err := url.Parse(target)
	if err != nil {
		log.Fatalf("Invalid ArgoCD server URL: %v", err)
	}

	return &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = parsedURL.Scheme
			req.URL.Host = parsedURL.Host
			req.Host = parsedURL.Host
		},
		FlushInterval: 100 * time.Millisecond, // Enable periodic flushing for streaming
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			if r.Context().Err() == context.Canceled {
				log.Printf("Client disconnected: %s", r.URL.Path)
			} else {
				log.Printf("Proxy error: %v (URL: %s)", err, r.URL.Path)
			}
			http.Error(w, "Error during proxying request", http.StatusBadGateway)
		},
	}
}

// shouldInterceptListRequest reports whether a request targets the list
// applications endpoint that the proxy serves from Redis. Only the exact list
// path is intercepted; single-application reads (e.g. /api/v1/applications/foo)
// and applicationsets are forwarded to the backend unchanged.
func shouldInterceptListRequest(r *http.Request) bool {
	return r.Method == http.MethodGet && r.URL.Path == listApplicationsPath
}

func handleRequest(w http.ResponseWriter, r *http.Request, proxy *httputil.ReverseProxy, redisClient *redis.Client, signingKey []byte, userToObjectPatternMapping, groupToObjectPatternMapping map[string]rbacPolicy) {
	token := extractToken(r)
	if token == "" || !shouldInterceptListRequest(r) {
		proxy.ServeHTTP(w, r)
		return
	}

	payload, err := verifyAndDecodeJWT(token, signingKey)
	if err != nil {
		log.Errorf("Failed to verify JWT: %v\n", err)
		proxy.ServeHTTP(w, r)
		return
	}

	email, _ := payload["email"].(string)
	groups := extractGroups(payload)
	allowPatterns, denyPatterns := resolveObjectPatterns(email, groups, userToObjectPatternMapping, groupToObjectPatternMapping)

	items := fetchRawApplications(redisClient, allowPatterns)
	if len(items) == 0 {
		proxy.ServeHTTP(w, r)
		return
	}

	if len(denyPatterns) > 0 {
		items = excludeDenied(items, denyPatterns)
	}

	queryParams := r.URL.Query()
	cluster := queryParams.Get("cluster")
	namespace := queryParams.Get("namespace")
	if cluster != "" || namespace != "" {
		items = filterRawByClusterAndNamespace(items, cluster, namespace)
	}

	serveCachedList(w, r, items)
}

// computeETag returns a strong, quoted ETag over the application list body, so an
// unchanged response can be answered with 304 Not Modified. fetchRawApplications
// sorts its keys, so the body — and therefore this ETag — is stable across
// requests when the underlying data has not changed.
func computeETag(items [][]byte) string {
	h := fnv.New64a()
	h.Write([]byte(`{"items":[`))
	for i, raw := range items {
		if i > 0 {
			h.Write([]byte{','})
		}
		h.Write(raw)
	}
	h.Write([]byte("]}"))
	return `"` + strconv.FormatUint(h.Sum64(), 16) + `"`
}

// serveCachedList writes the application list with an ETag. A request whose
// If-None-Match matches the current ETag gets 304 Not Modified with no body,
// saving the (potentially large) response transfer when nothing has changed.
func serveCachedList(w http.ResponseWriter, r *http.Request, items [][]byte) {
	etag := computeETag(items)
	h := w.Header()
	h.Set("ETag", etag)
	h.Set("Content-Type", "application/json")

	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	writeApplicationList(w, items)
}

// writeApplicationList streams the cached applications as a {"items":[...]}
// envelope. Each element is the raw JSON the watcher already stored in Redis, so
// no per-application marshaling happens here; the bytes are concatenated
// directly. This is the hot path for large, unfiltered list responses.
func writeApplicationList(w http.ResponseWriter, items [][]byte) {
	bw := bufio.NewWriter(w)
	bw.WriteString(`{"items":[`)
	for i, raw := range items {
		if i > 0 {
			bw.WriteByte(',')
		}
		bw.Write(raw)
	}
	bw.WriteString("]}")
	if err := bw.Flush(); err != nil {
		// Headers and a partial body may already be written, so we cannot fall
		// back to the proxy here; just log the failure.
		log.Errorf("Failed to write response: %v", err)
	}
}

// extractGroups reads the "groups" claim from a decoded JWT payload. JSON arrays
// unmarshal into []interface{}, so each element is converted to a string;
// non-string elements are skipped.
func extractGroups(payload map[string]interface{}) []string {
	raw, ok := payload["groups"].([]interface{})
	if !ok {
		return nil
	}
	groups := make([]string, 0, len(raw))
	for _, g := range raw {
		if s, ok := g.(string); ok {
			groups = append(groups, s)
		}
	}
	return groups
}

func extractToken(r *http.Request) string {
	if authHeader := r.Header.Get("Authorization"); strings.HasPrefix(authHeader, "Bearer ") {
		return strings.TrimPrefix(authHeader, "Bearer ")
	}
	if cookie, err := r.Cookie("argocd.token"); err == nil {
		return cookie.Value
	}
	return ""
}

// verifyAndDecodeJWT verifies the token's HMAC signature against signingKey
// and returns its claims. The signing method is pinned to HS256 so a forged
// token cannot switch to "none" or otherwise smuggle an unverified signature
// past this check (the classic JWT algorithm-confusion attack); the standard
// exp/nbf/iat claims are validated by the underlying library when present.
func verifyAndDecodeJWT(token string, signingKey []byte) (map[string]interface{}, error) {
	if len(signingKey) == 0 {
		return nil, fmt.Errorf("no signing key configured")
	}

	claims := jwt.MapClaims{}
	parsed, err := jwt.ParseWithClaims(token, claims, func(*jwt.Token) (interface{}, error) {
		return signingKey, nil
	}, jwt.WithValidMethods([]string{"HS256"}))
	if err != nil {
		return nil, fmt.Errorf("failed to verify token: %w", err)
	}
	if !parsed.Valid {
		return nil, fmt.Errorf("invalid token")
	}
	return claims, nil
}

// resolveObjectPatterns unions the allow and deny object patterns granted to a
// user directly and through their groups. ArgoCD's policy effect rule is
// "some(where (p.eft == allow)) && !some(where (p.eft == deny))", i.e. a deny
// match always overrides any allow match for the same object, regardless of
// which subject (user or group) it came from; the deny patterns returned here
// are applied as a post-fetch filter by the caller to honor that rule even
// when a deny pattern doesn't textually overlap an allow pattern.
func resolveObjectPatterns(email string, groups []string, userToObjectPatternMapping, groupToObjectPatternMapping map[string]rbacPolicy) (map[string]struct{}, []string) {
	allow := make(map[string]struct{})
	var deny []string

	addPolicy := func(policy rbacPolicy) {
		for _, pattern := range policy.allow {
			allow[pattern] = struct{}{}
		}
		deny = append(deny, policy.deny...)
	}

	addPolicy(userToObjectPatternMapping[email])
	for _, group := range groups {
		addPolicy(groupToObjectPatternMapping[group])
	}

	return allow, deny
}

// caseInsensitiveGlob rewrites a glob pattern so that Redis SCAN's
// case-sensitive MATCH performs a case-insensitive comparison instead. Team
// names are granted access via an AppProject naming convention of
// "<team>-XXX-YYY", and team membership is compared to the AppProject prefix
// case-insensitively, so each ASCII letter is expanded into a "[aA]"-style
// character class. Existing "[...]" character classes and "\"-escaped
// characters are passed through unchanged, since folding letters inside them
// would change their meaning.
func caseInsensitiveGlob(pattern string) string {
	var b strings.Builder
	inBracket := false
	for i := 0; i < len(pattern); i++ {
		c := pattern[i]
		switch {
		case c == '\\' && i+1 < len(pattern):
			b.WriteByte(c)
			b.WriteByte(pattern[i+1])
			i++
		case c == '[':
			inBracket = true
			b.WriteByte(c)
		case c == ']':
			inBracket = false
			b.WriteByte(c)
		case !inBracket && c >= 'a' && c <= 'z':
			b.WriteByte('[')
			b.WriteByte(c)
			b.WriteByte(c - 'a' + 'A')
			b.WriteByte(']')
		case !inBracket && c >= 'A' && c <= 'Z':
			b.WriteByte('[')
			b.WriteByte(c)
			b.WriteByte(c - 'A' + 'a')
			b.WriteByte(']')
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// scanKeys returns all Redis keys matching the given glob pattern using SCAN,
// which iterates the keyspace in bounded batches instead of blocking the server
// like KEYS does.
func scanKeys(redisClient *redis.Client, match string) ([]string, error) {
	var keys []string
	var cursor uint64
	for {
		batch, next, err := redisClient.Scan(cursor, match, 100).Result()
		if err != nil {
			return nil, err
		}
		keys = append(keys, batch...)
		cursor = next
		if cursor == 0 {
			break
		}
	}
	return keys, nil
}

// fetchRawApplications returns the raw JSON bytes of every application whose key
// matches one of the object patterns. Values are returned exactly as the watcher
// stored them in Redis; they are not deserialized, so callers can stream them
// straight into the response without re-marshaling. Matching is case-insensitive,
// since team-to-AppProject access is granted by a case-insensitive prefix match.
func fetchRawApplications(redisClient *redis.Client, objectPatterns map[string]struct{}) [][]byte {
	var allKeys []string
	for pattern := range objectPatterns {
		keys, err := scanKeys(redisClient, fmt.Sprintf("%s|*", caseInsensitiveGlob(pattern)))
		if err != nil {
			log.Printf("Failed to scan keys for pattern %s: %v", pattern, err)
			continue
		}
		allKeys = append(allKeys, keys...)
	}

	if len(allKeys) == 0 {
		return nil
	}
	// Redis SCAN returns keys in an unspecified order; sort so the response body
	// — and the ETag computed from it — are deterministic across requests.
	sort.Strings(allKeys)

	pipe := redisClient.Pipeline()
	cmds := make([]*redis.StringCmd, len(allKeys))
	for i, key := range allKeys {
		cmds[i] = pipe.Get(key)
	}
	if _, err := pipe.Exec(); err != nil && err != redis.Nil {
		log.Printf("Failed to fetch values for keys: %v", err)
	}

	items := make([][]byte, 0, len(allKeys))
	for i, cmd := range cmds {
		val, err := cmd.Result()
		if err != nil {
			log.Printf("Failed to fetch value for key %s: %v", allKeys[i], err)
			continue
		}
		items = append(items, []byte(val))
	}
	return items
}

// filterRawByClusterAndNamespace filters raw application JSON by destination
// cluster and/or namespace. The cluster parameter matches against
// spec.destination.server or spec.destination.name; the namespace parameter
// matches against spec.destination.namespace. Each item is unmarshaled into a
// minimal struct purely to read the destination, but the original raw bytes are
// what gets retained, so no re-marshaling occurs. The order of the returned
// items matches the input order.
func filterRawByClusterAndNamespace(items [][]byte, cluster, namespace string) [][]byte {
	filtered := make([][]byte, 0, len(items))
	for _, raw := range items {
		var app struct {
			Spec struct {
				Destination struct {
					Server    string `json:"server"`
					Name      string `json:"name"`
					Namespace string `json:"namespace"`
				} `json:"destination"`
			} `json:"spec"`
		}
		if err := json.Unmarshal(raw, &app); err != nil {
			continue
		}
		dest := app.Spec.Destination

		if cluster != "" && dest.Server != cluster && dest.Name != cluster {
			continue
		}
		if namespace != "" && dest.Namespace != namespace {
			continue
		}

		filtered = append(filtered, raw)
	}
	return filtered
}

// matchesObjectPattern reports whether object (typically "<project>/<name>")
// matches an ArgoCD-style glob pattern. "*" is treated as matching everything,
// including objects containing "/", which path.Match would otherwise reject
// since "/" is a segment separator for it. The comparison is case-insensitive,
// matching the case-insensitive team-to-AppProject prefix grant used on the
// allow path.
func matchesObjectPattern(pattern, object string) bool {
	if pattern == "*" {
		return true
	}
	matched, err := path.Match(strings.ToLower(pattern), strings.ToLower(object))
	return err == nil && matched
}

// excludeDenied removes applications matching any deny pattern from items.
// Each item is unmarshaled just enough to read its project and name, mirroring
// the approach filterRawByClusterAndNamespace uses for the destination fields.
func excludeDenied(items [][]byte, denyPatterns []string) [][]byte {
	filtered := make([][]byte, 0, len(items))
	for _, raw := range items {
		var app struct {
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
			Spec struct {
				Project string `json:"project"`
			} `json:"spec"`
		}
		if err := json.Unmarshal(raw, &app); err != nil {
			continue
		}
		object := app.Spec.Project + "/" + app.Metadata.Name

		denied := false
		for _, pattern := range denyPatterns {
			if matchesObjectPattern(pattern, object) {
				denied = true
				break
			}
		}
		if denied {
			continue
		}

		filtered = append(filtered, raw)
	}
	return filtered
}

// parseCSVLine parses a single RBAC policy line into trimmed fields, using
// encoding/csv so quoted fields may safely contain commas (e.g. an LDAP group
// DN like "CN=Team Alpha,OU=Groups,DC=example,DC=com").
func parseCSVLine(line string) ([]string, error) {
	reader := csv.NewReader(strings.NewReader(line))
	reader.TrimLeadingSpace = true
	fields, err := reader.Read()
	if err != nil {
		return nil, err
	}
	for i := range fields {
		fields[i] = strings.TrimSpace(fields[i])
	}
	return fields, nil
}

// resolveReachableRoles returns every role transitively reachable from
// subject by following "g" (subject-to-role) edges, supporting ArgoCD's
// role-to-role inheritance (e.g. "g, role:org-admin, role:admin"). Cycles are
// guarded against via the visited set so a misconfigured policy can't cause
// infinite recursion.
func resolveReachableRoles(subject string, edges map[string][]string) []string {
	visited := make(map[string]bool)
	var roles []string

	var visit func(string)
	visit = func(s string) {
		for _, role := range edges[s] {
			if visited[role] {
				continue
			}
			visited[role] = true
			roles = append(roles, role)
			visit(role)
		}
	}
	visit(subject)

	return roles
}

// parsePolicyCSV parses an ArgoCD RBAC policy.csv document into per-subject
// allow/deny object pattern policies, one map for users (subjects containing
// "@") and one for groups. "g" lines are also used to build a generic
// subject-to-role graph so role-to-role inheritance (e.g.
// "g, role:org-admin, role:admin") is resolved transitively, not just one
// level deep. Only "p" rules for the "applications" resource contribute
// object patterns; rules for other resource types (e.g. "applicationsets",
// "logs", "exec", "clusters") are out of scope for this proxy and ignored.
func parsePolicyCSV(policyCSV string) (map[string]rbacPolicy, map[string]rbacPolicy) {
	// subjectEdges records every "g, subject, role" edge. It doubles as the
	// graph resolveReachableRoles walks for role-to-role inheritance, since a
	// role can itself be the subject of another "g" line.
	subjectEdges := make(map[string][]string)

	seenUser := make(map[string]bool)
	seenGroup := make(map[string]bool)
	var userSubjects, groupSubjects []string

	roleToPolicyMapping := make(map[string]rbacPolicy)
	// default rules
	// - role:admin: unrestricted access to all objects
	// - role:readonly: read-only access to all objects
	roleToPolicyMapping["role:admin"] = rbacPolicy{allow: []string{"*"}}
	roleToPolicyMapping["role:readonly"] = rbacPolicy{allow: []string{"*"}}

	scanner := bufio.NewScanner(strings.NewReader(policyCSV))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		fields, err := parseCSVLine(line)
		if err != nil {
			log.Errorf("Failed to parse RBAC policy line %q: %v", line, err)
			continue
		}

		switch {
		case fields[0] == "g" && len(fields) >= 3:
			userOrGroup := fields[1]
			role := fields[2]
			subjectEdges[userOrGroup] = append(subjectEdges[userOrGroup], role)

			if strings.Contains(userOrGroup, "@") {
				if !seenUser[userOrGroup] {
					seenUser[userOrGroup] = true
					userSubjects = append(userSubjects, userOrGroup)
				}
			} else if !seenGroup[userOrGroup] {
				seenGroup[userOrGroup] = true
				groupSubjects = append(groupSubjects, userOrGroup)
			}

		case fields[0] == "p" && len(fields) >= 5:
			role := fields[1]
			resource := fields[2]
			// action := fields[3]
			objectPattern := fields[4]
			effect := "allow"
			if len(fields) >= 6 && fields[5] != "" {
				effect = strings.ToLower(fields[5])
			}

			if resource != applicationsResource {
				continue
			}

			policy := roleToPolicyMapping[role]
			if effect == "deny" {
				// Deny patterns are matched per-application against the raw
				// "<project>/<name>" object, so they keep their original
				// "/*" suffix rather than being trimmed for SCAN prefixing.
				policy.deny = append(policy.deny, objectPattern)
			} else {
				policy.allow = append(policy.allow, strings.TrimSuffix(objectPattern, "/*"))
			}
			roleToPolicyMapping[role] = policy
		}
	}

	aggregate := func(subjects []string) map[string]rbacPolicy {
		result := make(map[string]rbacPolicy, len(subjects))
		for _, subject := range subjects {
			var policy rbacPolicy
			for _, role := range resolveReachableRoles(subject, subjectEdges) {
				rolePolicy, exists := roleToPolicyMapping[role]
				if !exists {
					continue
				}
				policy.allow = append(policy.allow, rolePolicy.allow...)
				policy.deny = append(policy.deny, rolePolicy.deny...)
			}
			result[subject] = policy
		}
		return result
	}

	return aggregate(userSubjects), aggregate(groupSubjects)
}
