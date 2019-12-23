package signatures

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestECDSA(t *testing.T) {
	algorithms := []SignatureAlgorithm{
		ECDSA_P224_SHA224,
		ECDSA_P256_SHA224,
		ECDSA_P384_SHA224,
		ECDSA_P521_SHA224,
		ECDSA_P224_SHA256,
		ECDSA_P256_SHA256,
		ECDSA_P384_SHA256,
		ECDSA_P521_SHA256,
		ECDSA_P224_SHA384,
		ECDSA_P256_SHA384,
		ECDSA_P384_SHA384,
		ECDSA_P521_SHA384,
		ECDSA_P224_SHA512,
		ECDSA_P256_SHA512,
		ECDSA_P384_SHA512,
		ECDSA_P521_SHA512,
		ECDSA_P224_SHA512_224,
		ECDSA_P256_SHA512_224,
		ECDSA_P384_SHA512_224,
		ECDSA_P521_SHA512_224,
		ECDSA_P224_SHA512_256,
		ECDSA_P256_SHA512_256,
		ECDSA_P384_SHA512_256,
		ECDSA_P521_SHA512_256,
		ECDSA_P224_SHA3_224,
		ECDSA_P256_SHA3_256,
		ECDSA_P384_SHA3_384,
		ECDSA_P521_SHA3_512,
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
