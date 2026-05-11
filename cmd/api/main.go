package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/joho/godotenv"
	"github.com/saajann/fugax/internal/db"
	"github.com/saajann/fugax/internal/handler"
)

func main() {
	godotenv.Load()

	database, err := db.Connect()
	if err != nil {
		log.Fatal("db connection failed: ", err)
	}
	defer database.Close()
	fmt.Println("✅ connected to database")

	// Background worker: delete expired secrets every 5 minutes
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		for range ticker.C {
			if err := database.DeleteExpired(); err != nil {
				log.Println("cleanup error:", err)
			} else {
				log.Println("🧹 expired secrets cleaned up")
			}
		}
	}()

	// Register routes
	mux := http.NewServeMux()
	h := handler.New(database)
	h.RegisterRoutes(mux)

	port := os.Getenv("APP_PORT")
	if port == "" {
		port = "8080"
	}

	fmt.Println("🚀 server listening on port", port)
	log.Fatal(http.ListenAndServe(":"+port, mux))
}