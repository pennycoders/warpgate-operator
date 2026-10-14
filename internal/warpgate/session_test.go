package warpgate

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// sessionServer counts logins and accepts only the cookie of the latest one.
func sessionServer(t *testing.T, loginDelay time.Duration) (*httptest.Server, *atomic.Int32, func()) {
	t.Helper()
	var logins atomic.Int32
	var mu sync.Mutex
	current := ""
	mux := http.NewServeMux()
	mux.HandleFunc("/@warpgate/api/auth/login", func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(loginDelay)
		n := logins.Add(1)
		mu.Lock()
		current = fmt.Sprintf("session-%d", n)
		value := current
		mu.Unlock()
		http.SetCookie(w, &http.Cookie{Name: "warpgate", Value: value, Path: "/"})
		w.WriteHeader(http.StatusCreated)
	})
	mux.HandleFunc("/@warpgate/admin/api/roles", func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("warpgate")
		mu.Lock()
		ok := err == nil && cookie.Value == current
		mu.Unlock()
		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode([]map[string]string{})
	})
	srv := httptest.NewServer(mux)
	expire := func() {
		mu.Lock()
		current = "expired"
		mu.Unlock()
	}
	return srv, &logins, expire
}

func TestOneLoginServesManyRequests(t *testing.T) {
	srv, logins, _ := sessionServer(t, 0)
	defer srv.Close()

	c := NewClient(Config{Host: srv.URL, Username: "admin", Password: "secret"})
	for range 5 {
		if err := c.Get("/roles", nil); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if got := logins.Load(); got != 1 {
		t.Errorf("logins = %d, want 1", got)
	}
}

func TestExpiredSessionLogsInAgainOnce(t *testing.T) {
	srv, logins, expire := sessionServer(t, 0)
	defer srv.Close()

	c := NewClient(Config{Host: srv.URL, Username: "admin", Password: "secret"})
	if err := c.Get("/roles", nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expire()
	if err := c.Get("/roles", nil); err != nil {
		t.Fatalf("request after expiry: %v", err)
	}
	if got := logins.Load(); got != 2 {
		t.Errorf("logins = %d, want 2", got)
	}
}

func TestRejectedAfterLoginAgainIsAnError(t *testing.T) {
	mux := http.NewServeMux()
	var logins atomic.Int32
	mux.HandleFunc("/@warpgate/api/auth/login", func(w http.ResponseWriter, r *http.Request) {
		logins.Add(1)
		w.WriteHeader(http.StatusCreated)
	})
	mux.HandleFunc("/@warpgate/admin/api/roles", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := NewClient(Config{Host: srv.URL, Username: "admin", Password: "secret"})
	var apiErr *APIError
	if err := c.Get("/roles", nil); !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusUnauthorized {
		t.Fatalf("err = %v, want a 401 APIError", err)
	}
	if got := logins.Load(); got != 2 {
		t.Errorf("logins = %d, want 2 (one retry, no loop)", got)
	}
}

func TestTokenAuthDoesNotLogIn(t *testing.T) {
	var logins atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/@warpgate/api/auth/login", func(w http.ResponseWriter, r *http.Request) {
		logins.Add(1)
	})
	mux.HandleFunc("/@warpgate/admin/api/roles", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := NewClient(Config{Host: srv.URL, Token: "t"})
	if err := c.Get("/roles", nil); err == nil {
		t.Fatal("expected the 401 to be returned")
	}
	if got := logins.Load(); got != 0 {
		t.Errorf("logins = %d, want 0", got)
	}
}

func TestConcurrentRequestsLogInOnce(t *testing.T) {
	srv, logins, _ := sessionServer(t, 20*time.Millisecond)
	defer srv.Close()

	c := NewClient(Config{Host: srv.URL, Username: "admin", Password: "secret"})
	var wg sync.WaitGroup
	errs := make(chan error, 20)
	for range 20 {
		wg.Go(func() {
			errs <- c.Get("/roles", nil)
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if got := logins.Load(); got != 1 {
		t.Errorf("logins = %d, want 1", got)
	}
}
