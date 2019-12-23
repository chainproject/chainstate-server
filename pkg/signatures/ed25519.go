package signatures

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"hash"
	"io"

	"golang.org/x/crypto/sha3"
)

var (
	ED25519_SHA224     = register("ED25519_SHA224", NewED25519(sha256.New224()))
	ED25519_SHA256     = register("ED25519_SHA256", NewED25519(sha256.New()))
	ED25519_SHA384     = register("ED25519_SHA384", NewED25519(sha512.New384()))
	ED25519_SHA512     = register("ED25519_SHA512", NewED25519(sha512.New()))
	ED25519_SHA512_224 = register("ED25519_SHA512_224", NewED25519(sha512.New512_224()))
	ED25519_SHA512_256 = register("ED25519_SHA512_256", NewED25519(sha512.New512_256()))
	ED25519_SHA3_224   = register("ED25519_SHA3_224", NewED25519(sha3.New224()))
	ED25519_SHA3_256   = register("ED25519_SHA3_256", NewED25519(sha3.New256()))
	ED25519_SHA3_384   = register("ED25519_SHA3_384", NewED25519(sha3.New384()))
	ED25519_SHA3_512   = register("ED25519_SHA3_512", NewED25519(sha3.New512()))
)

func NewED25519(hasher hash.Hash) SignatureAlgorithm {
	return &ed25519SignatureAlgorithm{hasher}
}

type ed25519SignatureAlgorithm struct {
	hasher hash.Hash
}

func (s *ed25519SignatureAlgorithm) GenerateKey(random io.Reader) (priv []byte, pub []byte, err error) {
	pub, priv, err = ed25519.GenerateKey(random)
	if err != nil {
		return nil, nil, err
	}
	return priv, pub, nil
}

func (s *ed25519SignatureAlgorithm) Sign(data, random io.Reader, privateKey []byte) (signature []byte, err error) {
	s.hasher.Reset()
	_, err = io.Copy(s.hasher, data)
	if err != nil {
		return nil, err
	}
	digest := s.hasher.Sum(nil)
	sig := ed25519.Sign(ed25519.PrivateKey(privateKey), digest)
	return sig, nil
}

func (s *ed25519SignatureAlgorithm) Verify(data io.Reader, signature []byte, publicKey []byte) error {
	s.hasher.Reset()
	_, err := io.Copy(s.hasher, data)
	if err != nil {
		return err
	}
	digest := s.hasher.Sum(nil)
	ok := ed25519.Verify(ed25519.PublicKey(publicKey), digest, signature)
	if !ok {
		return errors.New("signature validation failed")
	}
	return nil
}
