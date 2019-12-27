package signatures

import (
	"errors"
	"io"
)

type SignatureAlgorithm interface {
	GenerateKey(random io.Reader) (priv []byte, pub []byte, err error)
	Sign(data, random io.Reader, privateKey []byte) (signature []byte, err error)
	Verify(data io.Reader, signature []byte, publicKey []byte) error
}

type hasher interface {
	io.Writer
	Sum([]byte) []byte
	Reset()
}

func GetByName(name string) (SignatureAlgorithm, error) {
	algorithm, ok := registry[name]
	if !ok {
		return nil, errors.New("no such algorithm")
	}
	return algorithm, nil
}

var registry = make(map[string]SignatureAlgorithm)

func register(name string, algorithm SignatureAlgorithm) SignatureAlgorithm {
	registry[name] = algorithm
	return algorithm
}
