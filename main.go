package main

import (
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
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"

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
	proxyBackend := flag.String("proxy-backend", "http://localhost:8080", "Backend URL for reverse proxy")
	listenAddr := flag.String("listen-addr", ":8081", "Address the proxy listens on")
	namespace := flag.String("namespace", "argocd", "Namespace where the ArgoCD RBAC ConfigMap lives")
	rbacConfigMap := flag.String("rbac-configmap", "argocd-rbac-cm", "Name of the ArgoCD RBAC ConfigMap")
	resyncPeriod := flag.Duration("resync-period", 30*time.Minute, "Application informer resync period")

	// Parse command-line flags
	flag.Parse()

	config := ctrl.GetConfigOrDie()

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Fatalf("Failed to create Kubernetes client: %v", err)
	}

	userToObjectPatternMapping, groupToObjectPatternMapping := loadRBACPolicyFromConfigMap(clientset, *namespace, *rbacConfigMap)

	dynamicClient := dynamic.NewForConfigOrDie(config)
	store := NewAppStore()
	fragCache := NewFragmentCache()

	// Handle SIGINT/SIGTERM for graceful shutdown and informer lifecycle.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := startApplicationInformer(ctx, dynamicClient, *namespace, *resyncPeriod, store); err != nil {
		log.Fatalf("Failed to start application informer: %v", err)
	}

	// Create a reverse proxy
	proxy := createReverseProxy(*proxyBackend)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		if served := tryServeList(rw, r, store, fragCache, userToObjectPatternMapping, groupToObjectPatternMapping); !served {
			proxy.ServeHTTP(rw, r)
		}

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
// applications endpoint that the proxy serves from the in-memory store. Only
// the exact list path is intercepted; single-application reads (e.g.
// /api/v1/applications/foo) and applicationsets are forwarded to the backend
// unchanged.
func shouldInterceptListRequest(r *http.Request) bool {
	return r.Method == http.MethodGet && r.URL.Path == listApplicationsPath
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
