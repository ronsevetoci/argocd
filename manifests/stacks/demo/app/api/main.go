package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
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

	_ "github.com/go-sql-driver/mysql"
)

type Config struct {
	ListenAddr         string
	RedisAddr          string
	RedisPassword      string
	RedisDB            int
	RedisKeyPrefix     string
	SessionTTL         time.Duration
	MySQLDSN           string
	MySQLTable         string
	MaxBodyBytes       int64
	VerboseByDefault   bool
	RequireJSON        bool
	TrustXForwardedFor bool
}

type App struct {
	cfg   Config
	rdb   *redis.Client
	db    *sql.DB
	start time.Time
}

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
		ListenAddr:         mustEnv("LISTEN_ADDR", ":8080"),
		RedisAddr:          mustEnv("REDIS_ADDR", "redis:6379"),
		RedisPassword:      mustEnv("REDIS_PASSWORD", ""),
		RedisDB:            envInt("REDIS_DB", 0),
		RedisKeyPrefix:     mustEnv("REDIS_KEY_PREFIX", "demo:sess:"),
		SessionTTL:         envDuration("SESSION_TTL", 24*time.Hour),
		MySQLDSN:           mustEnv("MYSQL_DSN", "user:pass@tcp(mysql:3306)/demo?parseTime=true&charset=utf8mb4&collation=utf8mb4_unicode_ci"),
		MySQLTable:         mustEnv("MYSQL_TABLE", "requests"),
		MaxBodyBytes:       envInt64("MAX_BODY_BYTES", 1<<20), // 1MiB
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

func newMySQL(cfg Config) (*sql.DB, error) {
	db, err := sql.Open("mysql", cfg.MySQLDSN)
	if err != nil {
		return nil, err
	}
	db.SetConnMaxLifetime(10 * time.Minute)
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)
	return db, nil
}

func (a *App) ensureTable(ctx context.Context) error {
	// Minimal table schema: stores raw JSON payload + metadata
	stmt := fmt.Sprintf(`
CREATE TABLE IF NOT EXISTS %s (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  session_id VARCHAR(64) NOT NULL,
  request_id VARCHAR(64) NOT NULL,
  payload_json JSON NULL,
  payload_raw MEDIUMTEXT NULL,
  payload_sha256 CHAR(64) NOT NULL,
  ip VARCHAR(64) NOT NULL,
  user_agent VARCHAR(512) NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;`, a.cfg.MySQLTable)

	_, err := a.db.ExecContext(ctx, stmt)
	return err
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
			// Secure: true, // enable when behind TLS
		})
	} else {
		sid = cookie.Value
	}

	key := a.sessionKey(sid)
	now := time.Now().UTC()

	// HSET createdAt only if not exists; update lastSeen; incr count
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

	// Read back fields
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

func (a *App) handleHealth(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	redisOK := true
	if err := a.rdb.Ping(ctx).Err(); err != nil {
		redisOK = false
	}

	mysqlOK := true
	if err := a.db.PingContext(ctx); err != nil {
		mysqlOK = false
	}

	code := http.StatusOK
	if !redisOK || !mysqlOK {
		code = http.StatusServiceUnavailable
	}

	resp := map[string]any{
		"ok":        code == http.StatusOK,
		"redisOk":   redisOK,
		"mysqlOk":   mysqlOK,
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

	// Validate JSON optionally (but still store raw)
	var payload any
	isJSON := true
	if len(strings.TrimSpace(string(body))) == 0 {
		isJSON = false
	} else if jerr := json.Unmarshal(body, &payload); jerr != nil {
		isJSON = false
		payload = nil
	}

	// Session in Redis
	sess, sessCreated, serr := a.getOrCreateSession(ctx, w, r)
	if serr != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "redis session failure", "details": serr.Error()})
		return
	}

	reqID := uuid.New().String()
	ip := clientIP(r, a.cfg.TrustXForwardedFor)
	ua := r.UserAgent()
	hash := sha256Hex(body)

	// Insert into MySQL
	insertT0 := time.Now()
	insertStmt := fmt.Sprintf(
		`INSERT INTO %s (session_id, request_id, payload_json, payload_raw, payload_sha256, ip, user_agent)
         VALUES (?, ?, CAST(? AS JSON), ?, ?, ?, ?)`, a.cfg.MySQLTable,
	)

	// If payload isn't JSON, CAST(? AS JSON) will fail. So choose statement based on isJSON.
	var res sql.Result
	if isJSON {
		res, err = a.db.ExecContext(ctx, insertStmt,
			sess.ID, reqID, string(body), string(body), hash, ip, ua,
		)
	} else {
		// Store payload_json as NULL
		insertStmt2 := fmt.Sprintf(
			`INSERT INTO %s (session_id, request_id, payload_json, payload_raw, payload_sha256, ip, user_agent)
             VALUES (?, ?, NULL, ?, ?, ?, ?)`, a.cfg.MySQLTable,
		)
		res, err = a.db.ExecContext(ctx, insertStmt2,
			sess.ID, reqID, string(body), hash, ip, ua,
		)
	}
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "mysql insert failed", "details": err.Error()})
		return
	}
	insertID, _ := res.LastInsertId()

	resp := map[string]any{
		"requestId": reqID,
		"insertId":  insertID,
		"ok":        true,
	}

	if verbose {
		resp["timingsMs"] = map[string]any{
			"total": time.Since(t0).Milliseconds(),
			"mysql": time.Since(insertT0).Milliseconds(),
		}
		resp["session"] = map[string]any{
			"id":        sess.ID,
			"created":   sessCreated,
			"createdAt": sess.CreatedAt,
			"lastSeen":  sess.LastSeen,
			"count":     sess.Count,
			"ttl":       a.cfg.SessionTTL.String(),
		}
		resp["redis"] = map[string]any{
			"addr": a.cfg.RedisAddr,
			"db":   a.cfg.RedisDB,
			"key":  a.sessionKey(sess.ID),
		}
		resp["mysql"] = map[string]any{
			"table": a.cfg.MySQLTable,
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

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func main() {
	cfg := loadConfig()

	rdb := newRedis(cfg)
	db, err := newMySQL(cfg)
	if err != nil {
		log.Fatalf("mysql open: %v", err)
	}

	app := &App{cfg: cfg, rdb: rdb, db: db, start: time.Now()}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := app.ensureTable(ctx); err != nil {
		log.Fatalf("ensure table: %v", err)
	}

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
	log.Printf("listening on %s", cfg.ListenAddr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("server: %v", err)
	}
}
