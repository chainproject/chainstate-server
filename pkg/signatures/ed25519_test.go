package signatures

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestED25519(t *testing.T) {
	algorithms := []SignatureAlgorithm{
		ED25519_SHA224,
		ED25519_SHA256,
		ED25519_SHA384,
		ED25519_SHA512,
		ED25519_SHA512_224,
		ED25519_SHA512_256,
		ED25519_SHA3_224,
		ED25519_SHA3_256,
		ED25519_SHA3_384,
		ED25519_SHA3_512,
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
