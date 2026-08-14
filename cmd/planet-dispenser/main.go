package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Native-Planet/perigee/dispenser"
)

func main() {
	listenAddr := envOrDefault("DISPENSER_LISTEN_ADDR", ":8090")
	adminToken := os.Getenv("DISPENSER_ADMIN_TOKEN")

	server := dispenser.NewServer(dispenser.ServerConfig{
		AdminToken: adminToken,
		Service:    dispenser.NewNoopPlanetService(),
	})

	httpServer := &http.Server{
		Addr:              listenAddr,
		Handler:           server.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		log.Printf("planet-dispenser listening on %s", listenAddr)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen failed: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(ctx); err != nil {
		log.Printf("shutdown error: %v", err)
	}
}

func envOrDefault(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}
