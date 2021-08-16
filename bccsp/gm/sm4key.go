package gm

import (
	"crypto/sha256"
	"errors"

	"github.com/Caoyitong/fabric_whuscser001/bccsp"
)

//定义国密 SM4 结构体，实现 bccsp Key 的接口
type gmsm4PrivateKey struct {
	privKey    []byte
	exportable bool
}

// 将此密匙转换为其字节表示
func (k *gmsm4PrivateKey) Bytes() (raw []byte, err error) {
	if k.exportable {
		return k.privKey, nil
	}

	return nil, errors.New("Not supported")
}

// 返回该密匙的标识(SKI)
func (k *gmsm4PrivateKey) SKI() (ski []byte) {
	hash := sha256.New()
	//hash := NewSM3()
	hash.Write([]byte{0x01})
	hash.Write(k.privKey)
	return hash.Sum(nil)
}

// 如果此密钥是对称密钥，则 Symmetric() 返回 true
func (k *gmsm4PrivateKey) Symmetric() bool {
	return true
}

// 如果此密钥是私钥，则 Private() 返回 true
func (k *gmsm4PrivateKey) Private() bool {
	return true
}

// PublicKey() 返回密钥对中的公钥
func (k *gmsm4PrivateKey) PublicKey() (bccsp.Key, error) {
	return nil, errors.New("Cannot call this method on a symmetric key")
}
