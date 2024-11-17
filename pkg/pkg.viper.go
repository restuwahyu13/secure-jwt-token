package pkg

import (
	"os"
	"strings"

	"github.com/caarlos0/env"
	vpr "github.com/spf13/viper"
)

type (
	Viper interface {
		Read(name string, config any) error
		Set(key, value string)
		Get(env string) string
	}

	viper struct{}
)

func NewViper() Viper {
	return &viper{}
}

func (p *viper) Read(name string, config any) error {
	if _, ok := os.LookupEnv("GO_ENV"); !ok {
		vpr.SetConfigFile(name)
		vpr.AutomaticEnv()

		err := vpr.ReadInConfig()
		if err != nil {
			return err
		}

		for _, v := range vpr.AllKeys() {
			os.Setenv(strings.ToUpper(v), p.Get(strings.ToUpper(v)))
		}

		if err := env.Parse(config); err != nil {
			return err
		}

	} else {
		if err := env.Parse(config); err != nil {
			return err
		}
	}

	return nil
}

func (p *viper) Set(key, value string) {
	vpr.Set(key, value)
}

func (p *viper) Get(env string) string {
	return vpr.GetString(env)
}
