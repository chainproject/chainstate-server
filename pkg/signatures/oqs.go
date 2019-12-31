package signatures

import (
	"errors"
	"io"

	"github.com/open-quantum-safe/liboqs-go/oqs"
	"golang.org/x/crypto/sha3"
)

func NewOQS(id string) SignatureAlgorithm {
	s := &oqsSignatureAlgorithm{baseSignatureAlgorithm{}, id}
	s.SetHasher(sha3.New256())
	return s
}

type oqsSignatureAlgorithm struct {
	baseSignatureAlgorithm
	algorithmID string
}

func (s *oqsSignatureAlgorithm) GenerateKey(random io.Reader) (priv []byte, pub []byte, err error) {
	signer := oqs.Signature{}
	signer.Init(s.algorithmID, nil)
	pub, err = signer.GenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}
	priv = signer.ExportSecretKey()
	return priv, pub, nil
}

func (s *oqsSignatureAlgorithm) Sign(data, random io.Reader, privateKey []byte) (signature []byte, err error) {
	s.Hasher.Reset()
	_, err = io.Copy(s.Hasher, data)
	if err != nil {
		return nil, err
	}
	digest := s.Hasher.Sum(nil)
	signer := oqs.Signature{}
	defer signer.Clean() // clean up even in case of panic
	signer.Init(s.algorithmID, privateKey)
	signature, err = signer.Sign(digest)
	if err != nil {
		return nil, err
	}
	return signature, nil
}

func (s *oqsSignatureAlgorithm) Verify(data io.Reader, signature []byte, publicKey []byte) error {
	s.Hasher.Reset()
	_, err := io.Copy(s.Hasher, data)
	if err != nil {
		return err
	}
	digest := s.Hasher.Sum(nil)
	verifier := oqs.Signature{}
	defer verifier.Clean() // clean up even in case of panic
	verifier.Init(s.algorithmID, nil)
	isValid, err := verifier.Verify(digest, signature, publicKey)
	if err != nil {
		return err
	}
	if !isValid {
		return errors.New("signature validation failed")
	}
	return nil
}

var (
	DILITHIUM_2                  = register("DILITHIUM_2", NewOQS("DILITHIUM_2"))
	DILITHIUM_3                  = register("DILITHIUM_3", NewOQS("DILITHIUM_3"))
	DILITHIUM_4                  = register("DILITHIUM_4", NewOQS("DILITHIUM_4"))
	MQDSS_31_48                  = register("MQDSS_31_48", NewOQS("MQDSS-31-48"))
	MQDSS_31_64                  = register("MQDSS_31_64", NewOQS("MQDSS-31-64"))
	SPHINCS_HARAKA_128F_ROBUST   = register("SPHINCS_HARAKA_128F_ROBUST", NewOQS("SPHINCS+-Haraka-128f-robust"))
	SPHINCS_HARAKA_128F_SIMPLE   = register("SPHINCS_HARAKA_128F_SIMPLE", NewOQS("SPHINCS+-Haraka-128f-simple"))
	SPHINCS_HARAKA_128S_ROBUST   = register("SPHINCS_HARAKA_128S_ROBUST", NewOQS("SPHINCS+-Haraka-128s-robust"))
	SPHINCS_HARAKA_128S_SIMPLE   = register("SPHINCS_HARAKA_128S_SIMPLE", NewOQS("SPHINCS+-Haraka-128s-simple"))
	SPHINCS_HARAKA_192F_ROBUST   = register("SPHINCS_HARAKA_192F_ROBUST", NewOQS("SPHINCS+-Haraka-192f-robust"))
	SPHINCS_HARAKA_192F_SIMPLE   = register("SPHINCS_HARAKA_192F_SIMPLE", NewOQS("SPHINCS+-Haraka-192f-simple"))
	SPHINCS_HARAKA_192S_ROBUST   = register("SPHINCS_HARAKA_192S_ROBUST", NewOQS("SPHINCS+-Haraka-192s-robust"))
	SPHINCS_HARAKA_192S_SIMPLE   = register("SPHINCS_HARAKA_192S_SIMPLE", NewOQS("SPHINCS+-Haraka-192s-simple"))
	SPHINCS_HARAKA_256F_ROBUST   = register("SPHINCS_HARAKA_256F_ROBUST", NewOQS("SPHINCS+-Haraka-256f-robust"))
	SPHINCS_HARAKA_256F_SIMPLE   = register("SPHINCS_HARAKA_256F_SIMPLE", NewOQS("SPHINCS+-Haraka-256f-simple"))
	SPHINCS_HARAKA_256S_ROBUST   = register("SPHINCS_HARAKA_256S_ROBUST", NewOQS("SPHINCS+-Haraka-256s-robust"))
	SPHINCS_HARAKA_256S_SIMPLE   = register("SPHINCS_HARAKA_256S_SIMPLE", NewOQS("SPHINCS+-Haraka-256s-simple"))
	SPHINCS_SHA256_128F_ROBUST   = register("SPHINCS_SHA256_128F_ROBUST", NewOQS("SPHINCS+-SHA256-128f-robust"))
	SPHINCS_SHA256_128F_SIMPLE   = register("SPHINCS_SHA256_128F_SIMPLE", NewOQS("SPHINCS+-SHA256-128f-simple"))
	SPHINCS_SHA256_128S_ROBUST   = register("SPHINCS_SHA256_128S_ROBUST", NewOQS("SPHINCS+-SHA256-128s-robust"))
	SPHINCS_SHA256_128S_SIMPLE   = register("SPHINCS_SHA256_128S_SIMPLE", NewOQS("SPHINCS+-SHA256-128s-simple"))
	SPHINCS_SHA256_192F_ROBUST   = register("SPHINCS_SHA256_192F_ROBUST", NewOQS("SPHINCS+-SHA256-192f-robust"))
	SPHINCS_SHA256_192F_SIMPLE   = register("SPHINCS_SHA256_192F_SIMPLE", NewOQS("SPHINCS+-SHA256-192f-simple"))
	SPHINCS_SHA256_192S_ROBUST   = register("SPHINCS_SHA256_192S_ROBUST", NewOQS("SPHINCS+-SHA256-192s-robust"))
	SPHINCS_SHA256_192S_SIMPLE   = register("SPHINCS_SHA256_192S_SIMPLE", NewOQS("SPHINCS+-SHA256-192s-simple"))
	SPHINCS_SHA256_256F_ROBUST   = register("SPHINCS_SHA256_256F_ROBUST", NewOQS("SPHINCS+-SHA256-256f-robust"))
	SPHINCS_SHA256_256F_SIMPLE   = register("SPHINCS_SHA256_256F_SIMPLE", NewOQS("SPHINCS+-SHA256-256f-simple"))
	SPHINCS_SHA256_256S_ROBUST   = register("SPHINCS_SHA256_256S_ROBUST", NewOQS("SPHINCS+-SHA256-256s-robust"))
	SPHINCS_SHA256_256S_SIMPLE   = register("SPHINCS_SHA256_256S_SIMPLE", NewOQS("SPHINCS+-SHA256-256s-simple"))
	SPHINCS_SHAKE256_128F_ROBUST = register("SPHINCS_SHAKE256_128F_ROBUST", NewOQS("SPHINCS+-SHAKE256-128f-robust"))
	SPHINCS_SHAKE256_128F_SIMPLE = register("SPHINCS_SHAKE256_128F_SIMPLE", NewOQS("SPHINCS+-SHAKE256-128f-simple"))
	SPHINCS_SHAKE256_128S_ROBUST = register("SPHINCS_SHAKE256_128S_ROBUST", NewOQS("SPHINCS+-SHAKE256-128s-robust"))
	SPHINCS_SHAKE256_128S_SIMPLE = register("SPHINCS_SHAKE256_128S_SIMPLE", NewOQS("SPHINCS+-SHAKE256-128s-simple"))
	SPHINCS_SHAKE256_192F_ROBUST = register("SPHINCS_SHAKE256_192F_ROBUST", NewOQS("SPHINCS+-SHAKE256-192f-robust"))
	SPHINCS_SHAKE256_192F_SIMPLE = register("SPHINCS_SHAKE256_192F_SIMPLE", NewOQS("SPHINCS+-SHAKE256-192f-simple"))
	SPHINCS_SHAKE256_192S_ROBUST = register("SPHINCS_SHAKE256_192S_ROBUST", NewOQS("SPHINCS+-SHAKE256-192s-robust"))
	SPHINCS_SHAKE256_192S_SIMPLE = register("SPHINCS_SHAKE256_192S_SIMPLE", NewOQS("SPHINCS+-SHAKE256-192s-simple"))
	SPHINCS_SHAKE256_256F_ROBUST = register("SPHINCS_SHAKE256_256F_ROBUST", NewOQS("SPHINCS+-SHAKE256-256f-robust"))
	SPHINCS_SHAKE256_256F_SIMPLE = register("SPHINCS_SHAKE256_256F_SIMPLE", NewOQS("SPHINCS+-SHAKE256-256f-simple"))
	SPHINCS_SHAKE256_256S_ROBUST = register("SPHINCS_SHAKE256_256S_ROBUST", NewOQS("SPHINCS+-SHAKE256-256s-robust"))
	SPHINCS_SHAKE256_256S_SIMPLE = register("SPHINCS_SHAKE256_256S_SIMPLE", NewOQS("SPHINCS+-SHAKE256-256s-simple"))
	PICNIC_L1_FS                 = register("PICNIC_L1_FS", NewOQS("picnic_L1_FS"))
	PICNIC_L1_UR                 = register("PICNIC_L1_UR", NewOQS("picnic_L1_UR"))
	PICNIC_L3_FS                 = register("PICNIC_L3_FS", NewOQS("picnic_L3_FS"))
	PICNIC_L3_UR                 = register("PICNIC_L3_UR", NewOQS("picnic_L3_UR"))
	PICNIC_L5_FS                 = register("PICNIC_L5_FS", NewOQS("picnic_L5_FS"))
	PICNIC_L5_UR                 = register("PICNIC_L5_UR", NewOQS("picnic_L5_UR"))
	PICNIC2_L1_FS                = register("PICNIC2_L1_FS", NewOQS("picnic2_L1_FS"))
	PICNIC2_L3_FS                = register("PICNIC2_L3_FS", NewOQS("picnic2_L3_FS"))
	PICNIC2_L5_FS                = register("PICNIC2_L5_FS", NewOQS("picnic2_L5_FS"))
	QTESLA_P_I                   = register("QTESLA_P_I", NewOQS("qTesla-p-I"))
	QTESLA_P_III                 = register("QTESLA_P_III", NewOQS("qTesla-p-III"))
)
