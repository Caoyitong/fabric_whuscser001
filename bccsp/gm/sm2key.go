package gm

import (
	"crypto/elliptic"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/Caoyitong/fabric_whuscser001/bccsp"
	"github.com/tjfoc/gmsm/sm2"
)

type gmsm2PrivateKey struct {
	privKey *sm2.PrivateKey
}

type gmsm2PublicKey struct {
	pubKey *sm2.PublicKey
}

// 将此密匙转换为其字节表示
func (k *gmsm2PrivateKey) Bytes() (raw []byte, err error) {
	return nil, errors.New("Not supported.")
}

// 返回该密匙的标识(SKI)
func (k *gmsm2PrivateKey) SKI() (ski []byte) {
	if k.privKey == nil {
		return nil
	}

	// 对公钥编组
	raw := elliptic.Marshal(k.privKey.Curve, k.privKey.PublicKey.X, k.privKey.PublicKey.Y)
	// Hash运算
	hash := sha256.New()
	hash.Write(raw)
	return hash.Sum(nil)
}

// 如果此密钥是对称密钥，则 Symmetric() 返回 true
func (k *gmsm2PrivateKey) Symmetric() bool {
	return false
}

// 如果此密钥是私钥，则 Private() 返回 true
func (k *gmsm2PrivateKey) Private() bool {
	return true
}

// PublicKey() 返回密钥对中的公钥
func (k *gmsm2PrivateKey) PublicKey() (bccsp.Key, error) {
	return &gmsm2PublicKey{&k.privKey.PublicKey}, nil
}

// 将此密匙转换为其字节表示
func (k *gmsm2PublicKey) Bytes() (raw []byte, err error) {
	raw, err = sm2.MarshalSm2PublicKey(k.pubKey)
	if err != nil {
		return nil, fmt.Errorf("Failed marshalling key [%s]", err)
	}
	return
}

// 返回该密匙的标识(SKI)
func (k *gmsm2PublicKey) SKI() (ski []byte) {
	if k.pubKey == nil {
		return nil
	}

	// 对公钥编组
	raw := elliptic.Marshal(k.pubKey.Curve, k.pubKey.X, k.pubKey.Y)

	// Hash运算
	hash := sha256.New()
	hash.Write(raw)
	return hash.Sum(nil)
}

// 如果此密钥是对称密钥，则 Symmetric() 返回 true
func (k *gmsm2PublicKey) Symmetric() bool {
	return false
}

// 如果此密钥是私钥，则 Private() 返回 true
func (k *gmsm2PublicKey) Private() bool {
	return false
}

// PublicKey() 返回密钥对中的公钥
func (k *gmsm2PublicKey) PublicKey() (bccsp.Key, error) {
	return k, nil
}
