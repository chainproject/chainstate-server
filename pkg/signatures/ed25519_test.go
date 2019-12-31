package signatures

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestED25519(t *testing.T) {
	algorithms := []SignatureAlgorithm{
		ED25519,
	}
	for _, alg := range algorithms {
		priv, pub, err := alg.GenerateKey(rand.Reader)
		require.NoError(t, err)
		data := []byte("foobar")
		sig, err := alg.Sign(bytes.NewReader(data), rand.Reader, priv)
		require.NoError(t, err)
		err = alg.Verify(bytes.NewReader(data), sig, pub)
		require.NoError(t, err)
	}
}
