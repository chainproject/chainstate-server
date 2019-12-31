package signatures

import (
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
)

type SignatureAlgorithm interface {
	GenerateKey(random io.Reader) (priv []byte, pub []byte, err error)
	Sign(data, random io.Reader, privateKey []byte) (signature []byte, err error)
	Verify(data io.Reader, signature []byte, publicKey []byte) error
	SetHasher(h Hasher)
}

type Hasher interface {
	io.Writer
	Sum([]byte) []byte
	Reset()
}

type baseSignatureAlgorithm struct {
	Hasher
}

func (a *baseSignatureAlgorithm) SetHasher(hasher Hasher) {
	a.Hasher = hasher
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

func SaveKeyToFile(out string, signatureAlgorithmName string, content []byte) (err error) {
	f, err := os.Create(out)
	if err != nil {
		return err
	}
	defer func() {
		if err == nil {
			err = f.Close()
		} else {
			closeError := f.Close()
			if closeError != nil {
				err = fmt.Errorf("(%v) AND (%v)", err, closeError)
			}
		}
	}()
	return SaveKey(f, signatureAlgorithmName, content)
}

func SaveKey(out io.Writer, signatureAlgorithmName string, content []byte) (err error) {
	block := &pem.Block{
		Type:  signatureAlgorithmName,
		Bytes: content,
	}
	if err = pem.Encode(out, block); err != nil {
		return err
	}
	return nil
}

func LoadKeyFromFile(file string) (keyData []byte, SignatureAlgorithmName string, err error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, "", err
	}
	return LoadKey(f)
}

func LoadKey(in io.Reader) (keyData []byte, SignatureAlgorithmName string, err error) {
	bs, err := ioutil.ReadAll(in)
	if err != nil {
		return nil, "", err
	}
	block, _ := pem.Decode(bs)
	if block == nil {
		return nil, "", errors.New("failed to decode PEM data")
	}
	return block.Bytes, block.Type, nil
}
