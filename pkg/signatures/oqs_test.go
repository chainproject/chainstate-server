package signatures

import (
	"bytes"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOQS(t *testing.T) {
	algorithms := []SignatureAlgorithm{
		DILITHIUM_2_SHA224,
		DILITHIUM_2_SHA256,
		DILITHIUM_2_SHA512,
		DILITHIUM_2_SHA512_224,
		DILITHIUM_2_SHA512_256,
		DILITHIUM_2_SHA3_224,
		DILITHIUM_2_SHA3_256,
		DILITHIUM_2_SHA3_384,
		DILITHIUM_2_SHA3_512,
		DILITHIUM_3_SHA224,
		DILITHIUM_3_SHA256,
		DILITHIUM_3_SHA512,
		DILITHIUM_3_SHA512_224,
		DILITHIUM_3_SHA512_256,
		DILITHIUM_3_SHA3_224,
		DILITHIUM_3_SHA3_256,
		DILITHIUM_3_SHA3_384,
		DILITHIUM_3_SHA3_512,
		DILITHIUM_4_SHA224,
		DILITHIUM_4_SHA256,
		DILITHIUM_4_SHA512,
		DILITHIUM_4_SHA512_224,
		DILITHIUM_4_SHA512_256,
		DILITHIUM_4_SHA3_224,
		DILITHIUM_4_SHA3_256,
		DILITHIUM_4_SHA3_384,
		DILITHIUM_4_SHA3_512,
		MQDSS_31_48_SHA224,
		MQDSS_31_48_SHA256,
		MQDSS_31_48_SHA512,
		MQDSS_31_48_SHA512_224,
		MQDSS_31_48_SHA512_256,
		MQDSS_31_48_SHA3_224,
		MQDSS_31_48_SHA3_256,
		MQDSS_31_48_SHA3_384,
		MQDSS_31_48_SHA3_512,
		MQDSS_31_64_SHA224,
		MQDSS_31_64_SHA256,
		MQDSS_31_64_SHA512,
		MQDSS_31_64_SHA512_224,
		MQDSS_31_64_SHA512_256,
		MQDSS_31_64_SHA3_224,
		MQDSS_31_64_SHA3_256,
		MQDSS_31_64_SHA3_384,
		MQDSS_31_64_SHA3_512,
		SPHINCS_SHAKE256_256S_ROBUST_SHA3_512,
		SPHINCS_SHAKE256_256S_SIMPLE_SHA3_512,
		PICNIC_L1_FS_SHA224,
		PICNIC_L1_FS_SHA256,
		PICNIC_L1_FS_SHA512,
		PICNIC_L1_FS_SHA512_224,
		PICNIC_L1_FS_SHA512_256,
		PICNIC_L1_FS_SHA3_224,
		PICNIC_L1_FS_SHA3_256,
		PICNIC_L1_FS_SHA3_384,
		PICNIC_L1_FS_SHA3_512,
		PICNIC_L1_UR_SHA224,
		PICNIC_L1_UR_SHA256,
		PICNIC_L1_UR_SHA512,
		PICNIC_L1_UR_SHA512_224,
		PICNIC_L1_UR_SHA512_256,
		PICNIC_L1_UR_SHA3_224,
		PICNIC_L1_UR_SHA3_256,
		PICNIC_L1_UR_SHA3_384,
		PICNIC_L1_UR_SHA3_512,
		PICNIC_L3_FS_SHA224,
		PICNIC_L3_FS_SHA256,
		PICNIC_L3_FS_SHA512,
		PICNIC_L3_FS_SHA512_224,
		PICNIC_L3_FS_SHA512_256,
		PICNIC_L3_FS_SHA3_224,
		PICNIC_L3_FS_SHA3_256,
		PICNIC_L3_FS_SHA3_384,
		PICNIC_L3_FS_SHA3_512,
		PICNIC_L3_UR_SHA224,
		PICNIC_L3_UR_SHA256,
		PICNIC_L3_UR_SHA512,
		PICNIC_L3_UR_SHA512_224,
		PICNIC_L3_UR_SHA512_256,
		PICNIC_L3_UR_SHA3_224,
		PICNIC_L3_UR_SHA3_256,
		PICNIC_L3_UR_SHA3_384,
		PICNIC_L3_UR_SHA3_512,
		PICNIC_L5_FS_SHA224,
		PICNIC_L5_FS_SHA256,
		PICNIC_L5_FS_SHA512,
		PICNIC_L5_FS_SHA512_224,
		PICNIC_L5_FS_SHA512_256,
		PICNIC_L5_FS_SHA3_224,
		PICNIC_L5_FS_SHA3_256,
		PICNIC_L5_FS_SHA3_384,
		PICNIC_L5_FS_SHA3_512,
		PICNIC_L5_UR_SHA224,
		PICNIC_L5_UR_SHA256,
		PICNIC_L5_UR_SHA512,
		PICNIC_L5_UR_SHA512_224,
		PICNIC_L5_UR_SHA512_256,
		PICNIC_L5_UR_SHA3_224,
		PICNIC_L5_UR_SHA3_256,
		PICNIC_L5_UR_SHA3_384,
		PICNIC_L5_UR_SHA3_512,
		PICNIC2_L1_FS_SHA224,
		PICNIC2_L1_FS_SHA256,
		PICNIC2_L1_FS_SHA512,
		PICNIC2_L1_FS_SHA512_224,
		PICNIC2_L1_FS_SHA512_256,
		PICNIC2_L1_FS_SHA3_224,
		PICNIC2_L1_FS_SHA3_256,
		PICNIC2_L1_FS_SHA3_384,
		PICNIC2_L1_FS_SHA3_512,
		PICNIC2_L3_FS_SHA224,
		PICNIC2_L3_FS_SHA256,
		PICNIC2_L3_FS_SHA512,
		PICNIC2_L3_FS_SHA512_224,
		PICNIC2_L3_FS_SHA512_256,
		PICNIC2_L3_FS_SHA3_224,
		PICNIC2_L3_FS_SHA3_256,
		PICNIC2_L3_FS_SHA3_384,
		PICNIC2_L3_FS_SHA3_512,
		PICNIC2_L5_FS_SHA224,
		PICNIC2_L5_FS_SHA256,
		PICNIC2_L5_FS_SHA512,
		PICNIC2_L5_FS_SHA512_224,
		PICNIC2_L5_FS_SHA512_256,
		PICNIC2_L5_FS_SHA3_224,
		PICNIC2_L5_FS_SHA3_256,
		PICNIC2_L5_FS_SHA3_384,
		PICNIC2_L5_FS_SHA3_512,
		QTESLA_P_I_SHA224,
		QTESLA_P_I_SHA256,
		QTESLA_P_I_SHA512,
		QTESLA_P_I_SHA512_224,
		QTESLA_P_I_SHA512_256,
		QTESLA_P_I_SHA3_224,
		QTESLA_P_I_SHA3_256,
		QTESLA_P_I_SHA3_384,
		QTESLA_P_I_SHA3_512,
		QTESLA_P_III_SHA224,
		QTESLA_P_III_SHA256,
		QTESLA_P_III_SHA512,
		QTESLA_P_III_SHA512_224,
		QTESLA_P_III_SHA512_256,
		QTESLA_P_III_SHA3_224,
		QTESLA_P_III_SHA3_256,
		QTESLA_P_III_SHA3_384,
		QTESLA_P_III_SHA3_512,
	}

	for _, alg := range algorithms {
		random := rand.New(rand.NewSource(123))
		t.Run(alg.(*oqsSignatureAlgorithm).algorithmID, func(t *testing.T) {
			priv, pub, err := alg.GenerateKey(random)
			require.NoError(t, err)
			data := []byte("foobar")
			sig, err := alg.Sign(bytes.NewReader(data), random, priv)
			require.NoError(t, err)
			err = alg.Verify(bytes.NewReader(data), sig, pub)
			require.NoError(t, err)

		})
	}
}