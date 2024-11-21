package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/go-redis/redis/v7"
)

func main() {
	// write the proxy to capture the request matches to the HTTP GET and URL is the /api/v1/applications
	// and the response is the JSON object with the key-value pairs of the Redis database
	// The Redis database is running on the localhost:16379 and the password is empty

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
	argocdServerURL := "http://localhost:8080" // Update this to your actual ArgoCD server URL

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
		// Capture GET requests to /api/v1/applications
		if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/v1/applications") {
			fmt.Printf("Request: %s %s\n", r.Method, r.URL.Path)
			handleApplicationsRequest(w, redisClient)
			return
		}

		// Proxy other requests to the ArgoCD server
		proxy.ServeHTTP(w, r)
	})

	log.Println("Proxy server running on :8081")
	log.Fatal(http.ListenAndServe(":8081", nil))
}

// handleApplicationsRequest fetches data from Redis and responds as JSON
func handleApplicationsRequest(w http.ResponseWriter, redisClient *redis.Client) {
	// Get a key-value pair
	keys, err := redisClient.Keys("*|*|*|*|*").Result()
	if err != nil {
		log.Fatalf("Failed to get key: %v", err)
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
		}

		// Unmarshal the value into a map
		err = json.Unmarshal([]byte(value), &rawJson)
		if err != nil {
			log.Printf("Failed to unmarshal value for key %s: %v", key, err)
			continue
		}

		resp.Items = append(resp.Items, rawJson)
		fmt.Printf("Value of %s: %s\n", key, rawJson)
	}

	// Serialize the key-value pairs as JSON
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		http.Error(w, fmt.Sprintf("Failed to write response: %v", err), http.StatusInternalServerError)
		return
	}
}
