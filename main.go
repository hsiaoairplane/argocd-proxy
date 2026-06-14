package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/go-redis/redis/v7"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
)

const listApplicationsPath = "/api/v1/applications"

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

	// Parse command-line flags
	flag.Parse()

	config := ctrl.GetConfigOrDie()

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Fatalf("Failed to create Kubernetes client: %v", err)
	}

	userToObjectPatternMapping, groupToObjectPatternMapping := loadRBACPolicyFromConfigMap(clientset, *namespace, *rbacConfigMap)

	// Initialize Redis client
	redisClient := initializeRedis(*redisAddr, *redisDB)

	// Create a reverse proxy
	proxy := createReverseProxy(*proxyBackend)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		start := time.Now() // Start measuring time

		rw := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		handleRequest(rw, r, proxy, redisClient, userToObjectPatternMapping, groupToObjectPatternMapping)

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

func loadRBACPolicyFromConfigMap(clientset *kubernetes.Clientset, namespace, configMapName string) (map[string][]string, map[string][]string) {
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

func handleRequest(w http.ResponseWriter, r *http.Request, proxy *httputil.ReverseProxy, redisClient *redis.Client, userToObjectPatternMapping, groupToObjectPatternMapping map[string][]string) {
	token := extractToken(r)
	if token == "" || !shouldInterceptListRequest(r) {
		proxy.ServeHTTP(w, r)
		return
	}

	payload, err := decodeJWTPayload(token)
	if err != nil {
		log.Errorf("Failed to decode JWT payload: %v\n", err)
		proxy.ServeHTTP(w, r)
		return
	}

	email, _ := payload["email"].(string)
	groups := extractGroups(payload)
	objectPatterns := resolveObjectPatterns(email, groups, userToObjectPatternMapping, groupToObjectPatternMapping)

	items := fetchRawApplications(redisClient, objectPatterns)
	if len(items) == 0 {
		proxy.ServeHTTP(w, r)
		return
	}

	queryParams := r.URL.Query()
	cluster := queryParams.Get("cluster")
	namespace := queryParams.Get("namespace")
	if cluster != "" || namespace != "" {
		items = filterRawByClusterAndNamespace(items, cluster, namespace)
	}

	w.Header().Set("Content-Type", "application/json")
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

func decodeJWTPayload(token string) (map[string]interface{}, error) {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid token format")
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode payload: %v", err)
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, fmt.Errorf("failed to unmarshal payload: %v", err)
	}
	return payload, nil
}

func resolveObjectPatterns(email string, groups []string, userToObjectPatternMapping, groupToObjectPatternMapping map[string][]string) map[string]struct{} {
	objectPatterns := make(map[string]struct{})

	for _, pattern := range userToObjectPatternMapping[email] {
		objectPatterns[pattern] = struct{}{}
	}

	for _, group := range groups {
		for _, pattern := range groupToObjectPatternMapping[group] {
			objectPatterns[pattern] = struct{}{}
		}
	}

	return objectPatterns
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
// straight into the response without re-marshaling.
func fetchRawApplications(redisClient *redis.Client, objectPatterns map[string]struct{}) [][]byte {
	var allKeys []string
	for pattern := range objectPatterns {
		keys, err := scanKeys(redisClient, fmt.Sprintf("%s|*", pattern))
		if err != nil {
			log.Printf("Failed to scan keys for pattern %s: %v", pattern, err)
			continue
		}
		allKeys = append(allKeys, keys...)
	}

	if len(allKeys) == 0 {
		return nil
	}

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

func parsePolicyCSV(policyCSV string) (map[string][]string, map[string][]string) {
	userToRoleMapping := make(map[string][]string)
	groupToRoleMapping := make(map[string][]string)

	roleToObjectPatternMapping := make(map[string][]string)
	// default rules
	// - role:admin: unrestricted access to all objects
	// - role:readonly: read-only access to all objects
	roleToObjectPatternMapping["role:admin"] = []string{"*"}
	roleToObjectPatternMapping["role:readonly"] = []string{"*"}

	lines := strings.Split(policyCSV, "\n")
	for _, line := range lines {
		// Ignore empty lines and comments
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Split the line into fields
		fields := strings.Split(line, ",")
		for i := range fields {
			fields[i] = strings.TrimSpace(fields[i]) // Trim spaces around each field
		}

		// Process "g" entries (group-role mappings)
		if fields[0] == "g" && len(fields) >= 3 {
			userOrGroup := fields[1]
			role := fields[2]

			if strings.Contains(userOrGroup, "@") {
				// Process user-role mappings
				user := userOrGroup
				if _, exists := userToRoleMapping[user]; !exists {
					// Initialize the role in the groupToRoleMapping map if it doesn't exist
					userToRoleMapping[user] = []string{}
				}
				userToRoleMapping[user] = append(userToRoleMapping[user], role)
			} else {
				// Process group-role mappings
				group := userOrGroup
				if _, exists := groupToRoleMapping[group]; !exists {
					// Initialize the role in the groupToRoleMapping map if it doesn't exist
					groupToRoleMapping[group] = []string{}
				}
				groupToRoleMapping[group] = append(groupToRoleMapping[group], role)
			}
		}

		// Process "p" entries (role-resource mappings)
		if fields[0] == "p" && len(fields) >= 5 {
			role := fields[1]
			resource := fields[2]
			// action := fields[3]
			objectPattern := fields[4]
			// effect := field[5]

			if resource == "applications" || resource == "applicationsets" || resource == "logs" || resource == "exec" {
				objectPattern = strings.TrimSuffix(objectPattern, "/*")
			}

			if _, exists := roleToObjectPatternMapping[role]; !exists {
				// Initialize the role in the roleToObjectPatternMapping map if it doesn't exist
				roleToObjectPatternMapping[role] = []string{}
			}
			roleToObjectPatternMapping[role] = append(roleToObjectPatternMapping[role], objectPattern)
		}
	}

	// Aggregate the user to object pattern mapping
	userToObjectPatternMapping := make(map[string][]string)
	for user, roles := range userToRoleMapping {
		userToObjectPatternMapping[user] = []string{}

		for _, role := range roles {
			if objectPatterns, exists := roleToObjectPatternMapping[role]; exists {
				userToObjectPatternMapping[user] = append(userToObjectPatternMapping[user], objectPatterns...)
			}
		}
	}

	// Aggregate the group to object pattern mapping
	groupToObjectPatternMapping := make(map[string][]string)
	for group, roles := range groupToRoleMapping {
		groupToObjectPatternMapping[group] = []string{}

		for _, role := range roles {
			if objectPatterns, exists := roleToObjectPatternMapping[role]; exists {
				groupToObjectPatternMapping[group] = append(groupToObjectPatternMapping[group], objectPatterns...)
			}
		}
	}
	return userToObjectPatternMapping, groupToObjectPatternMapping
}
