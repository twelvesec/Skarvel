package bbapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCheckWorkspacesFlagsRejectedCredentials(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, _, ok := r.BasicAuth(); ok {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"type": "error", "error": {"message": "API Token provided has no Bitbucket scopes."}}`))
			return
		}
		w.Write([]byte(`{"size": 3}`))
	}))
	defer srv.Close()

	bad := New([]string{"acme"}, Auth{User: "test@example.local", AppPassword: "pass"})
	bad.baseURL = srv.URL
	st := bad.CheckWorkspaces(context.Background())
	if len(st) != 1 || !st[0].Unauthorized || !st[0].Exists ||
		!strings.Contains(st[0].Err, "Bitbucket says: API Token provided has no Bitbucket scopes.") {
		t.Fatalf("status = %+v", st)
	}

	anon := New([]string{"acme"}, Auth{})
	anon.baseURL = srv.URL
	st = anon.CheckWorkspaces(context.Background())
	if len(st) != 1 || st[0].Unauthorized || st[0].Err != "" || st[0].Repos != 3 {
		t.Fatalf("status = %+v", st)
	}
}

func TestAuthFromEnvAccountAPIToken(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

	a := AuthFromEnv(env(map[string]string{"BITBUCKET_TOKEN": "ATATTxyz", "BITBUCKET_USER": "me@example.com"}))
	if a.Token != "" || a.User != "me@example.com" || a.AppPassword != "ATATTxyz" {
		t.Fatalf("account token not moved to basic auth: %+v", a)
	}
	a = AuthFromEnv(env(map[string]string{"BITBUCKET_TOKEN": "ATATTxyz"}))
	if a.Token != "ATATTxyz" || !IsAccountAPIToken(a.Token) {
		t.Fatalf("token without user: %+v", a)
	}
	a = AuthFromEnv(env(map[string]string{"BITBUCKET_TOKEN": "ATCTTworkspace", "BITBUCKET_USER": "me@example.com"}))
	if a.Token != "ATCTTworkspace" || a.AppPassword != "" {
		t.Fatalf("access token must stay Bearer: %+v", a)
	}
}
