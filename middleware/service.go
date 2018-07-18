package middleware

import (
	"log"
	"net/http"
	"time"

	"github.com/garyburd/redigo/redis"
	"github.com/gin-gonic/gin"
)

func init() {
	log.SetFlags(log.LstdFlags)
}

// Session ... will keep track of user openning morroc website
type Session struct {
	ID     string
	UserID string
}

// ValidateUserFunc ... return if the userID is valid in the system
type ValidateUserFunc func(userID string) bool

// Config ...
type Config struct {
	RedisPool   *redis.Pool
	RedisPrefix string

	CookieHeader string
	CookieMaxAge time.Duration
	CookieDomain string
	CookieSecure bool

	ValidateUserFunc
}

// DefaultConfig ...
func DefaultConfig(redisPool *redis.Pool) Config {
	return Config{
		RedisPool:    redisPool,
		RedisPrefix:  "cookie-auth-",
		CookieHeader: "session",
		CookieMaxAge: 12 * time.Hour,
		CookieDomain: "localhost",
		CookieSecure: false,
		ValidateUserFunc: func(userID string) bool {
			return true
		},
	}
}

// NewGinDefaultMiddleware ...
func NewGinDefaultMiddleware(config Config) gin.HandlerFunc {
	generateHTTPCookie := func(sessionID string) *http.Cookie {
		return &http.Cookie{
			Name:     config.CookieHeader,
			Value:    sessionID,
			Path:     "/",
			HttpOnly: true,
			MaxAge:   int(config.CookieMaxAge),
			Domain:   config.CookieDomain,
			Secure:   config.CookieSecure,
		}
	}

	authService := NewAuthService(config.RedisPool)
	return func(c *gin.Context) {
		hashID, err := c.Cookie(config.CookieHeader)

		var sess *Session
		if err == http.ErrNoCookie {
			// Create empty session
			sess = authService.CreateSession()
			http.SetCookie(c.Writer, generateHTTPCookie(sess.ID))

			c.Next()
			return
		}

		if err != nil {
			c.AbortWithStatusJSON(500, gin.H{
				"code":    "fail",
				"message": err.Error(),
			})
			return
		}

		sess = authService.GetSession(hashID)
		http.SetCookie(c.Writer, generateHTTPCookie(sess.ID))

		valid := config.ValidateUserFunc(sess.UserID)
		if valid {
			c.Next()
		} else {
			c.AbortWithStatus(403)
			return
		}
	}
}

// Middleware ... function that excepts handler and return handler
type Middleware func(http.Handler) http.Handler

// NewHTTPDefaultMiddleware ...
func NewHTTPDefaultMiddleware(config Config) Middleware {
	generateHTTPCookie := func(sessionID string) *http.Cookie {
		return &http.Cookie{
			Name:     config.CookieHeader,
			Value:    sessionID,
			Path:     "/",
			HttpOnly: true,
			MaxAge:   int(config.CookieMaxAge),
			Domain:   config.CookieDomain,
			Secure:   config.CookieSecure,
		}
	}

	authService := NewAuthService(config.RedisPool)
	return Middleware(func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			hashID, err := r.Cookie(config.CookieHeader)

			var sess *Session
			if err == http.ErrNoCookie {
				// Create empty session
				sess = authService.CreateSession()
				http.SetCookie(w, generateHTTPCookie(sess.ID))

				h.ServeHTTP(w, r)
				return
			}

			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(err.Error()))
				return
			}

			sess = authService.GetSession(hashID.Value)
			http.SetCookie(w, generateHTTPCookie(sess.ID))

			valid := config.ValidateUserFunc(sess.UserID)
			if valid {
				h.ServeHTTP(w, r)
			} else {
				w.WriteHeader(http.StatusForbidden)
				return
			}
		})
	})
}
