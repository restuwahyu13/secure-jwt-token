package helpers

import (
	"os"
	"path"
)

type (
	File interface {
		Read(name, src string) []byte
	}

	file struct{}
)

func NewFile() File {
	return &file{}
}

func (h *file) Read(name, src string) []byte {
	cwdir, err := os.Getwd()
	if err != nil {
		panic(err)
	}

	filepath := path.Join(cwdir, src, name)

	if ok := path.IsAbs(filepath); !ok {
		panic("Invalid file source")
	}

	res, err := os.ReadFile(filepath)
	if err != nil {
		panic(err)
	}

	return res
}
