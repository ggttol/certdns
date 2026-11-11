package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"certdns/internal/domain"
	"certdns/internal/issuer"
	"certdns/internal/pwhash"
	"certdns/internal/secretbox"
	"certdns/internal/store"
	"certdns/internal/web"
)

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func randomPassword() (string, error) {
	b := make([]byte, 18)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func atomicWriteSecretFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	dataDir := env("CERTDNS_DATA", "/data")
	tlsDir := env("CERTDNS_TLS_DIR", filepath.Join(dataDir, "tls"))
	listenAddr := env("CERTDNS_LISTEN", ":9080")
	hostname, err := domain.Normalize(env("CERTDNS_HOSTNAME", "cert.example.com"), false)
	if err != nil {
		log.Fatalf("invalid CERTDNS_HOSTNAME: %v", err)
	}

	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		log.Fatalf("create data dir: %v", err)
	}
	if err := os.Chmod(dataDir, 0o700); err != nil {
		log.Fatalf("chmod data dir: %v", err)
	}

	cipher, err := secretbox.LoadOrCreateKey(filepath.Join(dataDir, "secret.key"))
	if err != nil {
		log.Fatalf("load secret key: %v", err)
	}

	st, err := store.Open(filepath.Join(dataDir, "certdns.sqlite3"), cipher)
	if err != nil {
		log.Fatalf("open store: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	users, err := st.Users(ctx)
	if err != nil {
		_ = st.Close()
		log.Fatalf("query users: %v", err)
	}
	if len(users) == 0 {
		pw, err := randomPassword()
		if err != nil {
			_ = st.Close()
			log.Fatalf("generate password: %v", err)
		}
		h, err := pwhash.Hash(pw)
		if err != nil {
			_ = st.Close()
			log.Fatalf("hash password: %v", err)
		}
		if _, err := st.CreateUser(ctx, &store.User{
			Username:     "admin",
			DisplayName:  "系统管理员",
			PasswordHash: h,
			Role:         "admin",
			Enabled:      true,
		}); err != nil {
			_ = st.Close()
			log.Fatalf("create initial admin: %v", err)
		}
		pwFile := filepath.Join(dataDir, "admin-password")
		if err := atomicWriteSecretFile(pwFile, []byte(pw+"\n")); err != nil {
			_ = st.Close()
			log.Fatalf("write admin-password: %v", err)
		}
		log.Printf("initialized new admin password in %s", pwFile)
	}

	mgr := issuer.New(st, dataDir, tlsDir, hostname)
	mgr.Webhook.AllowPrivate = os.Getenv("CERTDNS_ALLOW_PRIVATE_WEBHOOK") == "1"

	if err := mgr.BackfillCertMetadata(ctx); err != nil {
		log.Printf("backfill cert metadata warning: %v", err)
	}
	if err := mgr.SyncTLS(ctx); err != nil {
		log.Printf("initial TLS sync warning: %v", err)
	}

	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		if _, err := mgr.ListZoneOwners(ctx, "", false); err != nil {
			log.Printf("initial zone cache warmup: %v", err)
		}
	}()
	go func() {
		defer wg.Done()
		mgr.RunWorker(ctx)
	}()
	go func() {
		defer wg.Done()
		mgr.RunScheduler(ctx)
	}()

	srv := &web.Server{
		Store:          st,
		Manager:        mgr,
		InsecureCookie: os.Getenv("CERTDNS_INSECURE_COOKIE") == "1",
	}
	httpSrv := &http.Server{
		Addr:              listenAddr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      90 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	go func() {
		log.Printf("certdns listening on %s (hostname=%s)", listenAddr, hostname)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("http server: %v", err)
		}
	}()

	<-ctx.Done()
	log.Printf("shutting down...")
	shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(shutCtx)
	wg.Wait()
	_ = st.Close()
}
