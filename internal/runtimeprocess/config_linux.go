// Package runtimeprocess loads operator-controlled process configuration. No
// execution command can select these files, identities, sockets or TLS origins.
package runtimeprocess

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"io"
	"os"
	"path/filepath"
	"strings"

	"dev-orchestrator/internal/contracts"
	"dev-orchestrator/internal/runtimeagent"
	"dev-orchestrator/internal/runtimerpc"
	"golang.org/x/sys/unix"
)

func Read(path string, private bool, limit int64) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, runtimeagent.ErrDenied
	}
	for p := filepath.Dir(path); ; p = filepath.Dir(p) {
		var st unix.Stat_t
		if unix.Lstat(p, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR || (st.Uid != 0 && st.Uid != uint32(os.Geteuid())) || st.Mode&0022 != 0 {
			return nil, runtimeagent.ErrDenied
		}
		if p == "/" {
			break
		}
	}
	f, err := os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, runtimeagent.ErrDenied
	}
	defer f.Close()
	var st unix.Stat_t
	if unix.Fstat(int(f.Fd()), &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Size < 1 || st.Size > limit || (st.Uid != 0 && st.Uid != uint32(os.Geteuid())) || st.Mode&0022 != 0 || private && st.Mode&0077 != 0 {
		return nil, runtimeagent.ErrDenied
	}
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(raw)) > limit {
		return nil, runtimeagent.ErrDenied
	}
	return raw, nil
}
func PublicKeys(encoded map[string]string) (map[string]ed25519.PublicKey, error) {
	if len(encoded) < 1 || len(encoded) > 8 {
		return nil, runtimeagent.ErrDenied
	}
	keys := map[string]ed25519.PublicKey{}
	for id, value := range encoded {
		raw, err := base64.StdEncoding.Strict().DecodeString(value)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return nil, runtimeagent.ErrDenied
		}
		keys[id] = ed25519.PublicKey(raw)
	}
	return keys, nil
}
func Certificate(certPath, keyPath string) (tls.Certificate, error) {
	cert, err := Read(certPath, false, 64<<10)
	if err != nil {
		return tls.Certificate{}, err
	}
	key, err := Read(keyPath, true, 16<<10)
	if err != nil {
		return tls.Certificate{}, err
	}
	identity, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return tls.Certificate{}, runtimeagent.ErrDenied
	}
	identity.Leaf, err = x509.ParseCertificate(identity.Certificate[0])
	if err != nil {
		return tls.Certificate{}, runtimeagent.ErrDenied
	}
	return identity, nil
}
func Roots(path string) (*x509.CertPool, error) {
	raw, err := Read(path, false, 64<<10)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(raw) {
		return nil, runtimeagent.ErrDenied
	}
	return roots, nil
}
func PrivateKey(path string) (ed25519.PrivateKey, error) {
	raw, err := Read(path, true, 16<<10)
	if err != nil {
		return nil, err
	}
	if block, _ := pem.Decode(raw); block != nil {
		value, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, runtimeagent.ErrDenied
		}
		key, ok := value.(ed25519.PrivateKey)
		if !ok {
			return nil, runtimeagent.ErrDenied
		}
		return key, nil
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(decoded) != ed25519.PrivateKeySize || !bytes.Equal(decoded, ed25519.NewKeyFromSeed(decoded[:ed25519.SeedSize])) {
		return nil, runtimeagent.ErrDenied
	}
	return ed25519.PrivateKey(decoded), nil
}

type AgentConfiguration struct {
	Origin                        string            `json:"origin"`
	ServerName                    string            `json:"server_name"`
	ControllerURI                 string            `json:"controller_uri"`
	ControllerSPKI                string            `json:"controller_spki"`
	AllowedControllerCertificates []string          `json:"allowed_controller_certificates"`
	CA                            string            `json:"ca"`
	Certificate                   string            `json:"certificate"`
	Key                           string            `json:"key"`
	InventoryKey                  string            `json:"inventory_key"`
	CommandKeys                   map[string]string `json:"command_keys"`
}

func LoadAgent(path string) (AgentConfiguration, error) {
	raw, err := Read(path, true, 64<<10)
	if err != nil {
		return AgentConfiguration{}, err
	}
	c, err := contracts.DecodeConfiguration[AgentConfiguration](bytes.NewReader(raw))
	if err != nil {
		return AgentConfiguration{}, runtimeagent.ErrDenied
	}
	return c, nil
}
func AgentTransport(path string, c AgentConfiguration) (*runtimerpc.Client, error) {
	identity, err := Certificate(c.Certificate, c.Key)
	if err != nil {
		return nil, err
	}
	roots, err := Roots(c.CA)
	if err != nil {
		return nil, err
	}
	return runtimerpc.New(runtimerpc.Config{Origin: c.Origin, ServerName: c.ServerName, ControllerURI: c.ControllerURI, ControllerSPKI: c.ControllerSPKI, Roots: roots, Identity: identity, Revocation: func(cert *x509.Certificate) error {
		current, err := LoadAgent(path)
		if err != nil || current.Origin != c.Origin || current.ControllerURI != c.ControllerURI {
			return runtimeagent.ErrDenied
		}
		sum := sha256.Sum256(cert.Raw)
		fingerprint := hex.EncodeToString(sum[:])
		if len(current.AllowedControllerCertificates) < 1 || len(current.AllowedControllerCertificates) > 8 {
			return runtimeagent.ErrDenied
		}
		for _, allowed := range current.AllowedControllerCertificates {
			if allowed == fingerprint {
				return nil
			}
		}
		return runtimeagent.ErrDenied
	}})
}
