package signatures

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"io"
	"math/big"

	"golang.org/x/crypto/sha3"
)

var (
	ECDSA_P224 = register("ECDSA_P224", NewECDSA(elliptic.P224()))
	ECDSA_P256 = register("ECDSA_P256", NewECDSA(elliptic.P256()))
	ECDSA_P384 = register("ECDSA_P384", NewECDSA(elliptic.P384()))
	ECDSA_P521 = register("ECDSA_P521", NewECDSA(elliptic.P521()))
)

func NewECDSA(curve elliptic.Curve) SignatureAlgorithm {
	s := &ecdsaSignatureAlgorithm{baseSignatureAlgorithm{}, curve}
	s.SetHasher(sha3.New256())
	return s
}

type ecdsaSignatureAlgorithm struct {
	baseSignatureAlgorithm
	curve elliptic.Curve
}

func (s *ecdsaSignatureAlgorithm) GenerateKey(random io.Reader) (priv []byte, pub []byte, err error) {
	privateKey, err := ecdsa.GenerateKey(s.curve, random)
	if err != nil {
		return nil, nil, err
	}
	privateKeyX509, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, nil, err
	}
	publicKey := privateKey.Public()
	publicKeyX509, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, nil, err
	}
	return privateKeyX509, publicKeyX509, nil
}

func (s *ecdsaSignatureAlgorithm) Sign(data, random io.Reader, privateKey []byte) (signature []byte, err error) {
	priv, err := x509.ParseECPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	s.Hasher.Reset()
	_, err = io.Copy(s.Hasher, data)
	if err != nil {
		return nil, err
	}
	digest := s.Hasher.Sum(nil)
	sigR, sigS, err := ecdsa.Sign(random, priv, digest)
	if err != nil {
		return nil, err
	}
	ecdsaSig := struct {
		R, S *big.Int
	}{sigR, sigS}
	return asn1.Marshal(ecdsaSig)
}

func (s *ecdsaSignatureAlgorithm) Verify(data io.Reader, signature []byte, publicKey []byte) error {
	var sig struct {
		R, S *big.Int
	}
	_, err := asn1.Unmarshal(signature, &sig)
	if err != nil {
		return err
	}
	p, err := x509.ParsePKIXPublicKey(publicKey)
	if err != nil {
		return err
	}
	pub, ok := p.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("invalid public key type")
	}
	s.Hasher.Reset()
	_, err = io.Copy(s.Hasher, data)
	if err != nil {
		return err
	}
	digest := s.Hasher.Sum(nil)
	ok = ecdsa.Verify(pub, digest, sig.R, sig.S)
	if !ok {
		return errors.New("signature validation failed")
	}
	return nil
}
