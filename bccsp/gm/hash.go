package gm

import (
	"hash"

	"github.com/Caoyitong/fabric_whuscser001/bccsp"
)

//定义hasher 结构体
type hasher struct {
	hash func() hash.Hash
}

// 返回hash值
func (c *hasher) Hash(msg []byte, opts bccsp.HashOpts) (hash []byte, err error) {
	h := c.hash()
	h.Write(msg)
	return h.Sum(nil), nil
}

func (c *hasher) GetHash(opts bccsp.HashOpts) (h hash.Hash, err error) {
	return c.hash(), nil
}
