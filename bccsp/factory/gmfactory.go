package factory

import (
	"errors"
	"fmt"

	"github.com/Caoyitong/fabric_whuscser001/bccsp"
	"github.com/Caoyitong/fabric_whuscser001/bccsp/gm"
)

const (
	// GuomiBasedFactoryName is the name of the factory of the software-based BCCSP implementation
	GuomiBasedFactoryName = "GM"
)

// GMFactory is the factory of the guomi-based BCCSP.
type GMFactory struct{}

func (f *GMFactory) Name() string {
	return GuomiBasedFactoryName
}

func (f *GMFactory) Get(config *FactoryOpts) (bccsp.BCCSP, error) {
	if config == nil || config.SwOpts == nil {
		return nil, errors.New("Invalid config. It must not be nil.")
	}

	gmOpts := config.SwOpts

	var ks bccsp.KeyStore
	if gmOpts.Ephemeral == true {
		ks = gm.NewDummyKeyStore()
	} else if gmOpts.FileKeystore != nil {
		fks, err := gm.NewFileBasedKeyStore(nil, gmOpts.FileKeystore.KeyStorePath, false)
		if err != nil {
			return nil, fmt.Errorf("Failed to initialize gm software key store: %s", err)
		}
		ks = fks
	} else {
		// 默认情况调用NewDummyKeyStore()
		ks = gm.NewDummyKeyStore()
	}

	return gm.New(gmOpts.SecLevel, "GMSM3", ks)
}
