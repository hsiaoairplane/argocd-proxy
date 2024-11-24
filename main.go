package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/go-redis/redis/v7"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
)

func main() {
	config := ctrl.GetConfigOrDie()
	namespace := "argocd"
	configMapName := "argocd-rbac-cm"

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Fatalf("Failed to create Kubernetes client: %v", err)
	}

	cm, err := clientset.CoreV1().ConfigMaps(namespace).Get(context.Background(), configMapName, metav1.GetOptions{})
	if err != nil {
		log.Fatalf("Failed to fetch ConfigMap %s: %v", configMapName, err)
	}

	// Extract policy data from ConfigMap
	policyCSV, ok := cm.Data["policy.csv"]
	if !ok {
		fmt.Printf("policy.csv not found in ConfigMap %s\n", configMapName)
	} else {
		fmt.Printf("Policy csv data: %s\n", policyCSV)

		// Parse the policy.csv content and build the map
		teamPermissions := parsePolicyCSV(policyCSV)

		// Print the team permissions
		fmt.Println("Team Permissions:")
		for team, permissions := range teamPermissions {
			fmt.Printf("Team: %s, Permissions: %v\n", team, permissions)
		}
	}

	// Redis configuration
	redisAddr := "localhost:16379" // Redis service DNS
	redisPassword := ""            // Set the password if Redis authentication is enabled

	// Initialize Redis client
	redisClient := redis.NewClient(&redis.Options{
		Addr:        redisAddr,
		Password:    redisPassword,
		DB:          1,
		DialTimeout: 5 * time.Second,
	})

	// Test connection
	pong, err := redisClient.Ping().Result()
	if err != nil {
		log.Fatalf("Failed to connect to Redis: %v", err)
	}

	fmt.Printf("Connected to Redis: %s\n", pong)

	// ArgoCD server URL
	argocdServerURL := "http://localhost:8443" // Update this to your actual ArgoCD server URL

	// Proxy handler
	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			argoURL, _ := url.Parse(argocdServerURL)
			req.URL.Scheme = argoURL.Scheme
			req.URL.Host = argoURL.Host
			req.Host = argoURL.Host
		},
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		token := func() string {
			if authHeader := r.Header.Get("Authorization"); strings.HasPrefix(authHeader, "Bearer ") {
				return strings.TrimPrefix(authHeader, "Bearer ")
			}
			if cookie, err := r.Cookie("argocd.token"); err == nil {
				return cookie.Value
			}
			return ""
		}()
		if token == "" {
			proxy.ServeHTTP(w, r)
			return
		}

		payload, err := decodeJWTPayload(token)
		if err != nil {
			proxy.ServeHTTP(w, r)
			return
		}

		// Extract the "email" and "groups" from the payload
		email, _ := payload["email"].(string)
		groups, _ := payload["groups"].([]interface{})
		fmt.Printf("Email: %s, Groups: %v\n", email, groups)

		// Capture GET requests to /api/v1/applications
		if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/v1/applications") {
			fmt.Printf("Request: %s %s\n", r.Method, r.URL.Path)
			// Get a key-value pair
			keys, err := redisClient.Keys("*|*|*|*|*").Result()
			if err != nil {
				log.Fatalf("Failed to get key: %v", err)
				proxy.ServeHTTP(w, r)
				return
			}

			var resp struct {
				Items []interface{} `json:"items"`
			}

			resp.Items = make([]interface{}, 0)
			for _, key := range keys {
				var rawJson interface{}

				value, err := redisClient.Get(key).Result()
				if err != nil {
					log.Fatalf("Failed to get value: %v", err)
					continue
				}

				// Unmarshal the value into a map
				err = json.Unmarshal([]byte(value), &rawJson)
				if err != nil {
					log.Printf("Failed to unmarshal value for key %s: %v", key, err)
					continue
				}

				resp.Items = append(resp.Items, rawJson)
			}

			if len(resp.Items) == 0 {
				proxy.ServeHTTP(w, r)
				return
			}

			// Serialize the key-value pairs as JSON
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(resp); err != nil {
				log.Printf("Failed to write response: %v", err)
				proxy.ServeHTTP(w, r)
				return
			}
			return
		}

		// Proxy other requests to the ArgoCD server
		proxy.ServeHTTP(w, r)
	})

	log.Println("Proxy server running on :8081")
	log.Fatal(http.ListenAndServe(":8081", nil))
}

// decodeJWTPayload decodes the payload of a JWT token without validating it
func decodeJWTPayload(token string) (map[string]interface{}, error) {
	// Split the token into its parts (header, payload, signature)
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid token format")
	}

	// Decode the payload (second part of the JWT)
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

// parsePolicyCSV parses the policy.csv content and returns a map of teams to their application permissions
func parsePolicyCSV(policyCSV string) map[string][]string {
	teamPermissions := make(map[string][]string)

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

		// Process policy entries
		if fields[0] == "p" && len(fields) >= 5 {
			team := fields[1]       // Extract the team
			permission := fields[4] // Extract the application pattern
			teamPermissions[team] = append(teamPermissions[team], permission)
		}
	}

	return teamPermissions
}
