package gm

import (
	"errors"
	"fmt"
	"math/rand"

	"github.com/Caoyitong/fabric_whuscser001/bccsp"
	"github.com/tjfoc/gmsm/sm4"
)

func GetRandomBytes(len int) ([]byte, error) {
	if len < 0 {
		return nil, errors.New("Len must be larger than 0")
	}
	buffer := make([]byte, len)

	n, err := rand.Read(buffer)
	if err != nil {
		return nil, err
	}
	if n != len {
		return nil, fmt.Errorf("Buffer not filled. Requested [%d], got [%d]", len, n)
	}

	return buffer, nil
}

func SM4Encrypt(key, src []byte) ([]byte, error) {
	dst := make([]byte, len(src))
	sm4.EncryptBlock(key, dst, src)
	return dst, nil
}

func SM4Decrypt(key, src []byte) ([]byte, error) {
	dst := make([]byte, len(src))
	sm4.DecryptBlock(key, dst, src)
	return dst, nil
}

type gmsm4Encryptor struct{}

func (*gmsm4Encryptor) Encrypt(k bccsp.Key, plaintext []byte, opts bccsp.EncrypterOpts) (ciphertext []byte, err error) {
	return SM4Encrypt(k.(*gmsm4PrivateKey).privKey, plaintext)
}

type gmsm4Decryptor struct{}

func (*gmsm4Decryptor) Decrypt(k bccsp.Key, ciphertext []byte, opts bccsp.DecrypterOpts) (plaintext []byte, err error) {
	return SM4Decrypt(k.(*gmsm4PrivateKey).privKey, ciphertext)
}
