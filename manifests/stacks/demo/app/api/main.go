package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

type Config struct {
	ListenAddr     string
	RedisAddr      string
	RedisPassword  string
	RedisDB        int
	RedisKeyPrefix string
	SessionTTL     time.Duration
	RequestTTL     time.Duration // New: How long to keep request payloads

	MaxBodyBytes       int64
	VerboseByDefault   bool
	RequireJSON        bool
	TrustXForwardedFor bool
}

type App struct {
	cfg   Config
	rdb   *redis.Client
	start time.Time
}

// --- Helper Functions ---

func mustEnv(key string, fallback string) string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	return v
}

func envBool(key string, fallback bool) bool {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return fallback
	}
	return b
}

func envInt(key string, fallback int) int {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	i, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return i
}

func envInt64(key string, fallback int64) int64 {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	i, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return fallback
	}
	return i
}

func envDuration(key string, fallback time.Duration) time.Duration {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return fallback
	}
	return d
}

func loadConfig() Config {
	return Config{
		ListenAddr:     mustEnv("LISTEN_ADDR", ":8080"),
		RedisAddr:      mustEnv("REDIS_ADDR", "redis:6379"),
		RedisPassword:  mustEnv("REDIS_PASSWORD", ""),
		RedisDB:        envInt("REDIS_DB", 0),
		RedisKeyPrefix: mustEnv("REDIS_KEY_PREFIX", "demo:sess:"),
		SessionTTL:     envDuration("SESSION_TTL", 24*time.Hour),
		RequestTTL:     envDuration("REQUEST_TTL", 24*time.Hour), // Defaults to 24h

		MaxBodyBytes:       envInt64("MAX_BODY_BYTES", 1<<20), // 1MB
		VerboseByDefault:   envBool("VERBOSE_BY_DEFAULT", true),
		RequireJSON:        envBool("REQUIRE_JSON", false),
		TrustXForwardedFor: envBool("TRUST_X_FORWARDED_FOR", true),
	}
}

func newRedis(cfg Config) *redis.Client {
	return redis.NewClient(&redis.Options{
		Addr:     cfg.RedisAddr,
		Password: cfg.RedisPassword,
		DB:       cfg.RedisDB,
	})
}

func clientIP(r *http.Request, trustXFF bool) string {
	if trustXFF {
		xff := strings.TrimSpace(r.Header.Get("X-Forwarded-For"))
		if xff != "" {
			parts := strings.Split(xff, ",")
			if len(parts) > 0 {
				return strings.TrimSpace(parts[0])
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

// --- Session Logic ---

type Session struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"createdAt"`
	LastSeen  time.Time `json:"lastSeen"`
	Count     int64     `json:"count"`
}

func (a *App) sessionKey(id string) string {
	return a.cfg.RedisKeyPrefix + id
}

func (a *App) getOrCreateSession(ctx context.Context, w http.ResponseWriter, r *http.Request) (Session, bool, error) {
	cookie, err := r.Cookie("sid")
	created := false

	var sid string
	if err != nil || cookie == nil || strings.TrimSpace(cookie.Value) == "" {
		sid = uuid.New().String()
		created = true
		http.SetCookie(w, &http.Cookie{
			Name:     "sid",
			Value:    sid,
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		})
	} else {
		sid = cookie.Value
	}

	key := a.sessionKey(sid)
	now := time.Now().UTC()

	pipe := a.rdb.TxPipeline()
	// If session new or missing, set createdAt
	pipe.HSetNX(ctx, key, "createdAt", now.Format(time.RFC3339Nano))
	pipe.HSet(ctx, key, "lastSeen", now.Format(time.RFC3339Nano))
	pipe.HIncrBy(ctx, key, "count", 1)
	pipe.Expire(ctx, key, a.cfg.SessionTTL)

	_, perr := pipe.Exec(ctx)
	if perr != nil {
		return Session{}, created, perr
	}

	m, gerr := a.rdb.HGetAll(ctx, key).Result()
	if gerr != nil {
		return Session{}, created, gerr
	}
	s := Session{ID: sid}
	if v := m["createdAt"]; v != "" {
		if t, e := time.Parse(time.RFC3339Nano, v); e == nil {
			s.CreatedAt = t
		}
	}
	if v := m["lastSeen"]; v != "" {
		if t, e := time.Parse(time.RFC3339Nano, v); e == nil {
			s.LastSeen = t
		}
	}
	if v := m["count"]; v != "" {
		if n, e := strconv.ParseInt(v, 10, 64); e == nil {
			s.Count = n
		}
	}
	return s, created, nil
}

// --- Handlers ---

func (a *App) handleHealth(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	redisOK := true
	if err := a.rdb.Ping(ctx).Err(); err != nil {
		redisOK = false
		log.Printf("Health check failed: Redis unreachable: %v", err)
	}

	code := http.StatusOK
	if !redisOK {
		code = http.StatusServiceUnavailable
	}

	resp := map[string]any{
		"ok":        code == http.StatusOK,
		"redisOk":   redisOK,
		"uptimeSec": int(time.Since(a.start).Seconds()),
	}
	writeJSON(w, code, resp)
}

func (a *App) handleEcho(w http.ResponseWriter, r *http.Request) {
	t0 := time.Now()
	ctx := r.Context()

	verbose := a.cfg.VerboseByDefault
	if q := strings.TrimSpace(r.URL.Query().Get("verbose")); q != "" {
		verbose = (q == "1" || strings.EqualFold(q, "true"))
	}

	if a.cfg.RequireJSON && !strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		writeJSON(w, http.StatusUnsupportedMediaType, map[string]any{
			"error": "Content-Type must be application/json",
		})
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, a.cfg.MaxBodyBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "failed reading body", "details": err.Error()})
		return
	}
	_ = r.Body.Close()

	// Get Session (Pure Redis)
	sess, sessCreated, serr := a.getOrCreateSession(ctx, w, r)
	if serr != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "redis session failure", "details": serr.Error()})
		return
	}

	// Prepare Request Data
	reqID := uuid.New().String()
	ip := clientIP(r, a.cfg.TrustXForwardedFor)
	ua := r.UserAgent()
	hash := sha256Hex(body)

	// Determine if valid JSON (for metadata)
	var payload any
	isJSON := true
	if len(strings.TrimSpace(string(body))) == 0 {
		isJSON = false
	} else if jerr := json.Unmarshal(body, &payload); jerr != nil {
		isJSON = false
	}

	// --- REDIS STORAGE (Replaces MySQL) ---
	storageT0 := time.Now()
	reqKey := fmt.Sprintf("req:%s", reqID) // New key for the request payload

	// Store fields in a Redis Hash
	payloadData := map[string]interface{}{
		"session_id":  sess.ID,
		"request_id":  reqID,
		"ip":          ip,
		"user_agent":  ua,
		"sha256":      hash,
		"is_json":     isJSON,
		"payload_raw": string(body), // Store the raw body
		"created_at":  time.Now().Format(time.RFC3339Nano),
	}

	// Use Pipeline for atomicity (Set Hash + Set Expiry)
	pipe := a.rdb.Pipeline()
	pipe.HSet(ctx, reqKey, payloadData)
	pipe.Expire(ctx, reqKey, a.cfg.RequestTTL)
	_, err = pipe.Exec(ctx)

	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "redis storage failed", "details": err.Error()})
		return
	}
	// --------------------------------------

	resp := map[string]any{
		"requestId": reqID,
		"ok":        true,
		"storage":   "redis",
	}

	if verbose {
		resp["timingsMs"] = map[string]any{
			"total":   time.Since(t0).Milliseconds(),
			"storage": time.Since(storageT0).Milliseconds(),
		}
		resp["session"] = map[string]any{
			"id":        sess.ID,
			"created":   sessCreated,
			"createdAt": sess.CreatedAt,
			"lastSeen":  sess.LastSeen,
			"count":     sess.Count,
		}
		resp["redis"] = map[string]any{
			"key": reqKey,
			"ttl": a.cfg.RequestTTL.String(),
		}
		resp["payload"] = map[string]any{
			"bytes":  len(body),
			"sha256": hash,
			"isJSON": isJSON,
		}
		resp["client"] = map[string]any{
			"ip":        ip,
			"userAgent": ua,
		}
	}

	writeJSON(w, http.StatusOK, resp)
}

func main() {
	cfg := loadConfig()

	// Initialize Redis
	rdb := newRedis(cfg)

	// No MySQL Initialization here anymore

	app := &App{cfg: cfg, rdb: rdb, start: time.Now()}

	r := chi.NewRouter()
	r.Use(chimw.RequestID)
	r.Use(chimw.RealIP)
	r.Use(chimw.Recoverer)
	r.Use(chimw.Timeout(30 * time.Second))

	r.Get("/healthz", app.handleHealth)
	r.Post("/echo", app.handleEcho)

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           r,
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Printf("Starting server on %s (Redis: %s)", cfg.ListenAddr, cfg.RedisAddr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("server: %v", err)
	}
}
