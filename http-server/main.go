package main

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/garyburd/redigo/redis"

	_ "github.com/lib/pq"
	"github.com/tanopwan/cookie-authentication/middleware"
)

func main() {
	host := os.Getenv("PG_HOST")
	database := os.Getenv("PG_DATABASE")
	user := os.Getenv("PG_USER")
	password := os.Getenv("PG_PASSWORD")

	fmt.Println("... connecting to postgresql ", host)

	connStr := fmt.Sprintf("postgres://%s:%s@%s/%s?sslmode=disable", user, password, host, database)
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		panic(err)
	}
	db.SetMaxOpenConns(2)
	db.SetMaxIdleConns(1)

	err = db.Ping()
	if err != nil {
		panic(err)
	}

	redisHost := os.Getenv("REDIS_HOST")
	redisPort := os.Getenv("REDIS_PORT")
	fmt.Println("... geting redis pool from ", host)
	redisPool := &redis.Pool{
		MaxIdle:     2,
		IdleTimeout: 60 * time.Minute,
		Dial: func() (redis.Conn, error) {
			return redis.Dial("tcp", redisHost+":"+redisPort)
		},
		TestOnBorrow: func(c redis.Conn, t time.Time) error {
			if time.Since(t) > time.Minute {
				return nil
			}
			_, err := c.Do("PING")
			return err
		},
	}

	config := middleware.DefaultConfig(redisPool)
	config.ValidateUserFunc = func(userID string) bool {
		if userID == "" {
			fmt.Printf("Non logged-in session\n")
			return true
		}
		fmt.Printf("ValidateUserFunc UserID: %s\n", userID)
		return true
	}

	server := http.Server{
		Addr: ":8080",
	}

	m := middleware.NewHTTPDefaultMiddleware(config)
	http.Handle("/api-auth/session", m(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Hello http.Server"))
	})))

	go func() {
		err := server.ListenAndServe()
		if err != http.ErrServerClosed {
			panic(err)
		}
	}()

	stop := make(chan os.Signal, 1)

	signal.Notify(stop, syscall.SIGTERM)

	<-stop

	// pkill -15 main
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	err = server.Shutdown(ctx)
	if err != nil {
		panic(err)
	}
}
