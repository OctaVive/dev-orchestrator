package httpapi

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strconv"
	"strings"
	"time"

	"dev-orchestrator/internal/auth"
)

func (h *handler) signChallenge(value string) string {
	mac := hmac.New(sha256.New, h.challenge[:])
	mac.Write([]byte(h.nonceName + "\n" + value))
	return hex.EncodeToString(mac.Sum(nil))
}

func (h *handler) csrfChallenge(w http.ResponseWriter, r *http.Request) {
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		h.authError(w, r, auth.ErrUnavailable)
		return
	}
	value := hex.EncodeToString(nonce[:]) + "." + strconv.FormatInt(h.now().Unix(), 10)
	value += "." + h.signChallenge(value)
	http.SetCookie(w, &http.Cookie{Name: h.nonceName, Value: value, Path: "/", Secure: true, HttpOnly: true,
		SameSite: http.SameSiteStrictMode, MaxAge: 300, Expires: h.now().Add(5 * time.Minute)})
	writeJSON(w, http.StatusOK, struct {
		CSRF string `json:"csrf_token"`
	}{auth.CSRF(value)})
}

func (h *handler) validChallenge(r *http.Request) bool {
	value, ok := oneCookie(r, h.nonceName)
	if !ok || len(value) > 160 || !validCSRFHeader(r, value) {
		return false
	}
	parts := strings.Split(value, ".")
	if len(parts) != 3 || len(parts[0]) != 64 || len(parts[2]) != 64 {
		return false
	}
	issued, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || issued > h.now().Unix() || issued <= h.now().Add(-5*time.Minute).Unix() {
		return false
	}
	return hmac.Equal([]byte(parts[2]), []byte(h.signChallenge(parts[0]+"."+parts[1])))
}

func (h *handler) clearNonce(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: h.nonceName, Value: "", Path: "/", Secure: true, HttpOnly: true,
		SameSite: http.SameSiteStrictMode, MaxAge: -1, Expires: time.Unix(1, 0)})
}
