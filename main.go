package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/go-redis/redis/v7"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
)

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

// rbacPolicy holds the resolved RBAC mappings and allows concurrent reads while
// the background reloader swaps in fresh mappings.
type rbacPolicy struct {
	mu                          sync.RWMutex
	userToObjectPatternMapping  map[string][]string
	groupToObjectPatternMapping map[string][]string
}

func (p *rbacPolicy) get() (map[string][]string, map[string][]string) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.userToObjectPatternMapping, p.groupToObjectPatternMapping
}

func (p *rbacPolicy) set(userMapping, groupMapping map[string][]string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.userToObjectPatternMapping = userMapping
	p.groupToObjectPatternMapping = groupMapping
}

func main() {
	// Register Prometheus metrics
	prometheus.MustRegister(requestDuration, requestTotal)

	// Define flags for configuration
	redisAddr := flag.String("redis-addr", "localhost:16379", "Redis server address")
	redisDB := flag.Int("redis-db", 1, "Redis database number")
	proxyBackend := flag.String("proxy-backend", "http://localhost:8080", "Backend URL for reverse proxy")
	rbacReloadInterval := flag.Duration("rbac-reload-interval", 5*time.Minute, "How often to reload the RBAC ConfigMap (0 disables periodic reload)")

	// Parse command-line flags
	flag.Parse()

	config := ctrl.GetConfigOrDie()

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Fatalf("Failed to create Kubernetes client: %v", err)
	}

	// Load the initial RBAC policy. Failure is non-fatal: the proxy stays
	// fail-open by forwarding requests to the backend, which enforces RBAC.
	policy := &rbacPolicy{}
	if userMapping, groupMapping, err := loadRBACPolicyFromConfigMap(clientset, "argocd", "argocd-rbac-cm"); err != nil {
		log.Errorf("Failed to load initial RBAC policy: %v", err)
	} else {
		policy.set(userMapping, groupMapping)
	}

	// Periodically reload the RBAC policy so ConfigMap changes are picked up
	// without restarting the proxy.
	if *rbacReloadInterval > 0 {
		go reloadRBACPolicy(context.Background(), clientset, "argocd", "argocd-rbac-cm", *rbacReloadInterval, policy)
	}

	// Initialize Redis client
	redisClient := initializeRedis(*redisAddr, *redisDB)

	// Create a reverse proxy
	proxy := createReverseProxy(*proxyBackend)

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		start := time.Now() // Start measuring time

		rw := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		handleRequest(rw, r, proxy, redisClient, policy)

		// Record duration and total request count
		duration := float64(time.Since(start).Milliseconds())
		statusCodeStr := fmt.Sprintf("%d", rw.statusCode)

		requestTotal.WithLabelValues(r.Method, r.URL.Path, statusCodeStr).Inc()
		requestDuration.WithLabelValues(r.Method, r.URL.Path, statusCodeStr).Observe(duration)
	})

	// Expose Prometheus metrics endpoint
	http.Handle("/metrics", promhttp.Handler())

	log.Println("Proxy server running on :8081")
	srv := &http.Server{
		Addr:         ":8081",
		Handler:      nil,              // default mux
		ReadTimeout:  0,                // Disable read timeout for long-running connections
		WriteTimeout: 0,                // Disable write timeout for streaming responses
		IdleTimeout:  15 * time.Second, // Only applies to idle connections
	}
	log.Fatal(srv.ListenAndServe())
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

// reloadRBACPolicy reloads the RBAC ConfigMap on a fixed interval until the
// context is cancelled. The existing policy is retained if a reload fails.
func reloadRBACPolicy(ctx context.Context, clientset *kubernetes.Clientset, namespace, configMapName string, interval time.Duration, policy *rbacPolicy) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			userMapping, groupMapping, err := loadRBACPolicyFromConfigMap(clientset, namespace, configMapName)
			if err != nil {
				log.Errorf("Failed to reload RBAC policy, keeping previous policy: %v", err)
				continue
			}
			policy.set(userMapping, groupMapping)
			log.Infoln("Reloaded RBAC policy")
		}
	}
}

func loadRBACPolicyFromConfigMap(clientset *kubernetes.Clientset, namespace, configMapName string) (map[string][]string, map[string][]string, error) {
	cm, err := clientset.CoreV1().ConfigMaps(namespace).Get(context.Background(), configMapName, metav1.GetOptions{})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to fetch ConfigMap %s/%s: %w", namespace, configMapName, err)
	}

	policyCSV, ok := cm.Data["policy.csv"]
	if !ok {
		return nil, nil, fmt.Errorf("policy.csv not found in ConfigMap %s/%s", namespace, configMapName)
	}

	userMapping, groupMapping := parsePolicyCSV(policyCSV)
	return userMapping, groupMapping, nil
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

func handleRequest(w http.ResponseWriter, r *http.Request, proxy *httputil.ReverseProxy, redisClient *redis.Client, policy *rbacPolicy) {
	token := extractToken(r)
	if token == "" || (r.Method != http.MethodGet || !strings.HasPrefix(r.URL.Path, "/api/v1/applications")) {
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
	groups, _ := payload["groups"].([]string)
	userToObjectPatternMapping, groupToObjectPatternMapping := policy.get()
	objectPatterns := resolveObjectPatterns(email, groups, userToObjectPatternMapping, groupToObjectPatternMapping)

	resp := fetchApplicationsFromRedis(redisClient, objectPatterns)
	if len(resp.Items) == 0 {
		proxy.ServeHTTP(w, r)
		return
	}

	queryParams := r.URL.Query()
	cluster := queryParams.Get("cluster")
	namespace := queryParams.Get("namespace")
	resp.Items = filterApplicationsByClusterAndNamespace(resp.Items, cluster, namespace)

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Printf("Failed to write response: %v", err)
		proxy.ServeHTTP(w, r)
	}
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

func fetchApplicationsFromRedis(redisClient *redis.Client, objectPatterns map[string]struct{}) struct {
	Items []interface{} `json:"items"`
} {
	resp := struct {
		Items []interface{} `json:"items"`
	}{Items: []interface{}{}}

	var allKeys []string
	for pattern := range objectPatterns {
		keys, err := redisClient.Keys(fmt.Sprintf("%s|*", pattern)).Result()
		if err != nil {
			log.Printf("Failed to fetch keys for pattern %s: %v", pattern, err)
			continue
		}
		allKeys = append(allKeys, keys...)
	}

	if len(allKeys) > 0 {
		pipe := redisClient.Pipeline()
		cmds := make([]*redis.StringCmd, len(allKeys))
		for i, key := range allKeys {
			cmds[i] = pipe.Get(key)
		}
		_, err := pipe.Exec()
		if err != nil && err != redis.Nil {
			log.Printf("Failed to fetch values for keys: %v", err)
		}

		for i, cmd := range cmds {
			if cmd.Err() == nil {
				var rawJson interface{}
				if err := json.Unmarshal([]byte(cmd.Val()), &rawJson); err == nil {
					resp.Items = append(resp.Items, rawJson)
				} else {
					log.Printf("Failed to unmarshal value for key %s: %v", allKeys[i], err)
				}
			} else {
				log.Printf("Failed to fetch value for key %s: %v", allKeys[i], cmd.Err())
			}
		}
	}
	return resp
}

// filterApplicationsByClusterAndNamespace filters application items by destination cluster and/or namespace.
// The cluster parameter matches against spec.destination.server or spec.destination.name.
// The namespace parameter matches against spec.destination.namespace.
// An empty string for either parameter means no filtering is applied for that field.
// The order of items in the returned slice matches the order of items in the input slice.
func filterApplicationsByClusterAndNamespace(items []interface{}, cluster, namespace string) []interface{} {
	if cluster == "" && namespace == "" {
		return items
	}

	filtered := make([]interface{}, 0)
	for _, item := range items {
		app, ok := item.(map[string]interface{})
		if !ok {
			continue
		}

		spec, ok := app["spec"].(map[string]interface{})
		if !ok {
			continue
		}

		destination, ok := spec["destination"].(map[string]interface{})
		if !ok {
			continue
		}

		if cluster != "" {
			server, _ := destination["server"].(string)
			name, _ := destination["name"].(string)
			if server != cluster && name != cluster {
				continue
			}
		}

		if namespace != "" {
			destNamespace, _ := destination["namespace"].(string)
			if destNamespace != namespace {
				continue
			}
		}

		filtered = append(filtered, item)
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

			if resource == "applications" || resource == "applicationsets" || resource == "logs" || resource == "exec " {
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
