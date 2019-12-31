package signatures

import (
	"bytes"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOQS(t *testing.T) {
	algorithms := []SignatureAlgorithm{
		DILITHIUM_2,
		DILITHIUM_3,
		DILITHIUM_4,
		MQDSS_31_48,
		MQDSS_31_64,
		SPHINCS_SHAKE256_256S_ROBUST,
		SPHINCS_SHAKE256_256S_SIMPLE,
		PICNIC_L1_FS,
		PICNIC_L1_UR,
		PICNIC_L3_FS,
		PICNIC_L3_UR,
		PICNIC_L5_FS,
		PICNIC_L5_UR,
		PICNIC2_L1_FS,
		PICNIC2_L3_FS,
		PICNIC2_L5_FS,
		QTESLA_P_I,
		QTESLA_P_III,
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
