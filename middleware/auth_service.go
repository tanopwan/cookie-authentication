package middleware

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"log"
	"time"

	"github.com/garyburd/redigo/redis"
)

var (
	prefix = "cookie-auth-"
	maxAge = 3600
	domain = "localhost"
)

type authService struct {
	redisPool *redis.Pool
}

// AuthService ...
type AuthService interface {
	GetSession(hashID string) *Session
	CreateSession() *Session
	CreateLoginSession(userID string) *Session
}

// NewAuthService ... will return authService client that implements interfaces
func NewAuthService(redisPool *redis.Pool) AuthService {
	return &authService{redisPool: redisPool}
}

func (s *authService) CreateSession() *Session {
	db := s.redisPool.Get()
	defer db.Close()

	key := hashSHA256(prefix + generateRandomString(128))
	log.Printf("[cookie-auth] create new session: %s\n", key)
	_, err := db.Do("SETEX", key, int64(24*time.Hour/time.Second), 0)
	if err != nil {
		panic(err)
	}

	return &Session{
		ID:     key,
		UserID: "",
	}
}

func (s *authService) CreateLoginSession(userID string) *Session {
	db := s.redisPool.Get()
	defer db.Close()

	key := hashSHA256(prefix + generateRandomString(128))
	log.Printf("[cookie-auth] create new session: %s\n", key)
	_, err := db.Do("SETEX", key, int64(24*time.Hour/time.Second), userID)
	if err != nil {
		panic(err)
	}

	return &Session{
		ID:     key,
		UserID: userID,
	}
}

func (s *authService) GetSession(hashID string) *Session {
	log.Printf("[cookie-auth] get existing session: %s\n", hashID)
	db := s.redisPool.Get()
	defer db.Close()

	userID, err := redis.String(db.Do("GET", hashID))
	if err == redis.ErrNil {
		// return empty session
		return &Session{
			ID:     hashID,
			UserID: "",
		}
	}

	return &Session{
		ID:     hashID,
		UserID: userID,
	}
}

func hashSHA256(value string) string {
	h := sha256.New()
	h.Write([]byte(value))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

func generateRandomString(n int) string {
	b := make([]byte, n)
	io.ReadFull(rand.Reader, b)
	return base64.URLEncoding.EncodeToString(b)
}
