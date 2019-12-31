package signatures

import (
	"crypto/ed25519"
	"errors"
	"io"

	"golang.org/x/crypto/sha3"
)

var (
	ED25519 = register("ED25519", NewED25519())
)

func NewED25519() SignatureAlgorithm {
	s := &ed25519SignatureAlgorithm{baseSignatureAlgorithm{}}
	s.SetHasher(sha3.New256())
	return s
}

type ed25519SignatureAlgorithm struct {
	baseSignatureAlgorithm
}

func (s *ed25519SignatureAlgorithm) GenerateKey(random io.Reader) (priv []byte, pub []byte, err error) {
	pub, priv, err = ed25519.GenerateKey(random)
	if err != nil {
		return nil, nil, err
	}
	return priv, pub, nil
}

func (s *ed25519SignatureAlgorithm) Sign(data, random io.Reader, privateKey []byte) (signature []byte, err error) {
	s.Hasher.Reset()
	_, err = io.Copy(s.Hasher, data)
	if err != nil {
		return nil, err
	}
	digest := s.Hasher.Sum(nil)
	sig := ed25519.Sign(ed25519.PrivateKey(privateKey), digest)
	return sig, nil
}

func (s *ed25519SignatureAlgorithm) Verify(data io.Reader, signature []byte, publicKey []byte) error {
	s.Hasher.Reset()
	_, err := io.Copy(s.Hasher, data)
	if err != nil {
		return err
	}
	digest := s.Hasher.Sum(nil)
	ok := ed25519.Verify(ed25519.PublicKey(publicKey), digest, signature)
	if !ok {
		return errors.New("signature validation failed")
	}
	return nil
}
