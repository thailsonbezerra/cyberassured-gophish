package controllers

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	ctx "github.com/gophish/gophish/context"
	log "github.com/gophish/gophish/logger"
	"github.com/gophish/gophish/models"
	"github.com/gorilla/sessions"
)

type ssoPayload struct {
    CustomerId int64 `json:"customerInternalId"`
    Exp      int64  `json:"exp"`
}

// SSOLogin validates a JWT (HMAC or RSA depending on config). If valid,
// it creates a session for the specified user and redirects to the dashboard (/).
func (as *AdminServer) SSOLogin(w http.ResponseWriter, r *http.Request) {
    tokenStr := r.URL.Query().Get("token")
    if tokenStr == "" {
        http.Error(w, "missing token", http.StatusBadRequest)
        return
    }

    // The JWT secret is read exclusively from the environment variable
    // JWT_SECRET to avoid storing sensitive secrets in config.json.
    secret := os.Getenv("JWT_SECRET")
    if secret == "" {
        log.Error("SSO attempted but JWT_SECRET is not set in the environment")
        http.Error(w, "sso not configured", http.StatusInternalServerError)
        return
    }

    pl, err := verifyJWTToken(tokenStr, []byte(secret))
    if err != nil {
        log.Error(err)
        http.Error(w, "invalid token", http.StatusUnauthorized)
        return
    }
    if time.Now().Unix() > pl.Exp {
        http.Error(w, "token expired", http.StatusUnauthorized)
        return
    }

    u, err := models.GetUserByCustomerId(pl.CustomerId)
    if err != nil {
        log.Error(err)
        http.Error(w, "user not found", http.StatusNotFound)
        return
    }
    if u.AccountLocked {
        http.Error(w, "account locked", http.StatusForbidden)
        return
    }

    session := ctx.Get(r, "session").(*sessions.Session)
    session.Values["id"] = u.Id
    if err := session.Save(r, w); err != nil {
        log.Error(err)
        http.Error(w, "failed to save session", http.StatusInternalServerError)
        return
    }
    http.Redirect(w, r, "/", http.StatusFound)
}

// verifyJWTToken parses and validates a JWT signed with HMAC-SHA (HS256)
// and returns a ssoPayload. For RSA-signed tokens, adapt the keyfunc accordingly.
func verifyJWTToken(tokenStr string, key []byte) (*ssoPayload, error) {
    type claims struct {
        CustomerId int64 `json:"customerInternalId"`
        jwt.RegisteredClaims
    }

    parser := jwt.NewParser(jwt.WithValidMethods([]string{"HS256", "HS384", "HS512"}))
    var c claims
    tok, err := parser.ParseWithClaims(tokenStr, &c, func(t *jwt.Token) (interface{}, error) {
        // Ensure the method is HMAC; change if you want to support RS256.
        if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
        }
        return key, nil
    })
    if err != nil {
        return nil, err
    }
    if !tok.Valid {
        return nil, errors.New("invalid token")
    }

    pl := &ssoPayload{
        CustomerId: c.CustomerId,
    }
    if c.ExpiresAt != nil {
        pl.Exp = c.ExpiresAt.Unix()
    }
    return pl, nil
}

// SSOExchange validates an upstream JWT (from cyberassured) and returns a
// short-lived JWT that can be passed to the frontend SSO endpoint
// (/sso_login?token=...) to create a session. Expects a JSON POST body:
// { "token": "<upstream-jwt>", "next": "/templates" }
func (as *AdminServer) SSOExchange(w http.ResponseWriter, r *http.Request) {
    type reqBody struct {
        Token string `json:"token"`
        Next  string `json:"next"`
    }
    var rb reqBody
    decoder := json.NewDecoder(r.Body)
    if err := decoder.Decode(&rb); err != nil {
        http.Error(w, "invalid request", http.StatusBadRequest)
        return
    }
    if rb.Token == "" {
        http.Error(w, "missing token", http.StatusBadRequest)
        return
    }

    secret := os.Getenv("JWT_SECRET")
    if secret == "" {
        log.Error("SSO exchange attempted but JWT_SECRET is not set in the environment")
        http.Error(w, "sso not configured", http.StatusInternalServerError)
        return
    }

    pl, err := verifyJWTToken(rb.Token, []byte(secret))
    if err != nil {
        log.Error(err)
        http.Error(w, "invalid token", http.StatusUnauthorized)
        return
    }
    if time.Now().Unix() > pl.Exp {
        http.Error(w, "token expired", http.StatusUnauthorized)
        return
    }

    // Ensure the user exists and is allowed to login
    u, err := models.GetUserByCustomerId(pl.CustomerId)
    if err != nil {
        log.Error(err)
        http.Error(w, "user not found", http.StatusNotFound)
        return
    }
    if u.AccountLocked {
        http.Error(w, "account locked", http.StatusForbidden)
        return
    }

    // Create a short-lived token that the frontend can pass to /sso_login
    // to create a session. Include the next path so the frontend can redirect
    // after session creation.
    claims := jwt.MapClaims{
        "customerInternalId": pl.CustomerId,
        "exp":                time.Now().Add(1 * time.Minute).Unix(),
    }
    if rb.Next != "" {
        claims["next"] = rb.Next
    }
    tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    signed, err := tok.SignedString([]byte(secret))
    if err != nil {
        log.Error(err)
        http.Error(w, "failed to sign token", http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusOK)
    fmt.Fprintf(w, `{"token":"%s"}`, signed)
}
