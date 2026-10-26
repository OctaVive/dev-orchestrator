// Package auth implements PH1 password authentication and server-side sessions.
// TOTP enrollment and recovery are not implemented here (PH3).
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	_ "embed"
	"encoding/base64"
	"fmt"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

const (
	passwordMemory = 64 * 1024 // KiB
	passwordTime   = 3
	passwordLanes  = 1
)

//go:embed common-passwords.txt
var commonPasswords string

func validNewPassword(password string) bool {
	if !utf8.ValidString(password) || utf8.RuneCountInString(password) < 15 || len(password) > 1024 || strings.TrimSpace(password) == "" || strings.ContainsRune(password, 0) {
		return false
	}
	lower := strings.ToLower(password)
	for _, line := range strings.Split(commonPasswords, "\n") {
		if entry := strings.TrimSpace(line); entry != "" && !strings.HasPrefix(entry, "#") && lower == entry {
			return false
		}
	}
	return true
}

func hashPassword(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, passwordTime, passwordMemory, passwordLanes, 32)
	return fmt.Sprintf("$argon2id$v=19$m=65536,t=3,p=1$%s$%s", base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key)), nil
}

// Only the current explicitly supported PHC profile is accepted. Never trust
// DB-provided memory/time parameters enough to allocate arbitrarily from them.
func verifyPassword(encoded, password, dummy string) bool {
	parts := strings.Split(encoded, "$")
	valid := len(parts) == 6 && parts[0] == "" && parts[1] == "argon2id" && parts[2] == "v=19" && parts[3] == "m=65536,t=3,p=1"
	var salt, expected []byte
	if valid {
		var err error
		salt, err = base64.RawStdEncoding.Strict().DecodeString(parts[4])
		valid = err == nil && len(salt) == 16
		expected, err = base64.RawStdEncoding.Strict().DecodeString(parts[5])
		valid = valid && err == nil && len(expected) == 32
	}
	if !valid {
		// Malformed/unsupported hashes still perform one normal-profile KDF.
		if dummy != "" {
			_ = verifyPassword(dummy, password, "")
		}
		return false
	}
	actual := argon2.IDKey([]byte(password), salt, passwordTime, passwordMemory, passwordLanes, 32)
	return subtle.ConstantTimeCompare(actual, expected) == 1
}
