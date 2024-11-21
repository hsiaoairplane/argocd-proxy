package main

import (
	"fmt"
	"log"
	"time"

	"github.com/go-redis/redis/v7"
)

func main() {
	// Redis configuration
	redisAddr := "localhost:16379" // Redis service DNS
	redisPassword := ""            // Set the password if Redis authentication is enabled

	// Initialize Redis client
	rdb := redis.NewClient(&redis.Options{
		Addr:        redisAddr,
		Password:    redisPassword,
		DB:          1,
		DialTimeout: 5 * time.Second,
	})

	// Test connection
	pong, err := rdb.Ping().Result()
	if err != nil {
		log.Fatalf("Failed to connect to Redis: %v", err)
	}

	fmt.Printf("Connected to Redis: %s\n", pong)

	// Get a key-value pair
	keys, err := rdb.Keys("*|*|*|*|*").Result()
	if err != nil {
		log.Fatalf("Failed to get key: %v", err)
	}

	for _, key := range keys {
		value, err := rdb.Get(key).Result()
		if err != nil {
			log.Fatalf("Failed to get value: %v", err)
		}

		fmt.Printf("Value of %s: %s\n", key, value)
	}
}
