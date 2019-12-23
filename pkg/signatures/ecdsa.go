package signatures

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"hash"
	"io"
	"math/big"

	"golang.org/x/crypto/sha3"
)

var (
	ECDSA_P224_SHA224     = register("ECDSA_P224_SHA224", NewECDSA(elliptic.P224(), sha256.New224()))
	ECDSA_P256_SHA224     = register("ECDSA_P256_SHA224", NewECDSA(elliptic.P256(), sha256.New224()))
	ECDSA_P384_SHA224     = register("ECDSA_P384_SHA224", NewECDSA(elliptic.P384(), sha256.New224()))
	ECDSA_P521_SHA224     = register("ECDSA_P521_SHA224", NewECDSA(elliptic.P521(), sha256.New224()))
	ECDSA_P224_SHA256     = register("ECDSA_P224_SHA256", NewECDSA(elliptic.P224(), sha256.New()))
	ECDSA_P256_SHA256     = register("ECDSA_P256_SHA256", NewECDSA(elliptic.P256(), sha256.New()))
	ECDSA_P384_SHA256     = register("ECDSA_P384_SHA256", NewECDSA(elliptic.P384(), sha256.New()))
	ECDSA_P521_SHA256     = register("ECDSA_P521_SHA256", NewECDSA(elliptic.P521(), sha256.New()))
	ECDSA_P224_SHA384     = register("ECDSA_P224_SHA384", NewECDSA(elliptic.P224(), sha512.New384()))
	ECDSA_P256_SHA384     = register("ECDSA_P256_SHA384", NewECDSA(elliptic.P256(), sha512.New384()))
	ECDSA_P384_SHA384     = register("ECDSA_P384_SHA384", NewECDSA(elliptic.P384(), sha512.New384()))
	ECDSA_P521_SHA384     = register("ECDSA_P521_SHA384", NewECDSA(elliptic.P521(), sha512.New384()))
	ECDSA_P224_SHA512     = register("ECDSA_P224_SHA512", NewECDSA(elliptic.P224(), sha512.New()))
	ECDSA_P256_SHA512     = register("ECDSA_P256_SHA512", NewECDSA(elliptic.P256(), sha512.New()))
	ECDSA_P384_SHA512     = register("ECDSA_P384_SHA512", NewECDSA(elliptic.P384(), sha512.New()))
	ECDSA_P521_SHA512     = register("ECDSA_P521_SHA512", NewECDSA(elliptic.P521(), sha512.New()))
	ECDSA_P224_SHA512_224 = register("ECDSA_P224_SHA512_224", NewECDSA(elliptic.P224(), sha512.New512_224()))
	ECDSA_P256_SHA512_224 = register("ECDSA_P256_SHA512_224", NewECDSA(elliptic.P256(), sha512.New512_224()))
	ECDSA_P384_SHA512_224 = register("ECDSA_P384_SHA512_224", NewECDSA(elliptic.P384(), sha512.New512_224()))
	ECDSA_P521_SHA512_224 = register("ECDSA_P521_SHA512_224", NewECDSA(elliptic.P521(), sha512.New512_224()))
	ECDSA_P224_SHA512_256 = register("ECDSA_P224_SHA512_256", NewECDSA(elliptic.P224(), sha512.New512_256()))
	ECDSA_P256_SHA512_256 = register("ECDSA_P256_SHA512_256", NewECDSA(elliptic.P256(), sha512.New512_256()))
	ECDSA_P384_SHA512_256 = register("ECDSA_P384_SHA512_256", NewECDSA(elliptic.P384(), sha512.New512_256()))
	ECDSA_P521_SHA512_256 = register("ECDSA_P521_SHA512_256", NewECDSA(elliptic.P521(), sha512.New512_256()))
	ECDSA_P224_SHA3_224   = register("ECDSA_P224_SHA3_224", NewECDSA(elliptic.P224(), sha3.New224()))
	ECDSA_P256_SHA3_256   = register("ECDSA_P256_SHA3_256", NewECDSA(elliptic.P256(), sha3.New256()))
	ECDSA_P384_SHA3_384   = register("ECDSA_P384_SHA3_384", NewECDSA(elliptic.P384(), sha3.New384()))
	ECDSA_P521_SHA3_512   = register("ECDSA_P521_SHA3_512", NewECDSA(elliptic.P521(), sha3.New512()))
)

func NewECDSA(curve elliptic.Curve, hasher hash.Hash) SignatureAlgorithm {
	return &ecdsaSignatureAlgorithm{curve, hasher}
}

type ecdsaSignatureAlgorithm struct {
	curve  elliptic.Curve
	hasher hash.Hash
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
	s.hasher.Reset()
	_, err = io.Copy(s.hasher, data)
	if err != nil {
		return nil, err
	}
	digest := s.hasher.Sum(nil)
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
	s.hasher.Reset()
	_, err = io.Copy(s.hasher, data)
	if err != nil {
		return err
	}
	digest := s.hasher.Sum(nil)
	ok = ecdsa.Verify(pub, digest, sig.R, sig.S)
	if !ok {
		return errors.New("signature validation failed")
	}
	return nil
}
