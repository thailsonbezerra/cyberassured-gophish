package controllers

import (
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
