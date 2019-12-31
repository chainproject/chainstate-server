package signatures

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestECDSA(t *testing.T) {
	algorithms := []SignatureAlgorithm{
		ECDSA_P224,
		ECDSA_P256,
		ECDSA_P384,
		ECDSA_P521,
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
