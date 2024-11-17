package helpers

import (
	"bytes"
	"io"

	"github.com/goccy/go-json"
)

type (
	Parser interface {
		Marshal(source any) ([]byte, error)
		Unmarshal(src []byte, dest any) error
		Decode(src io.Reader, dest any) error
		Encode(src io.Writer, dest any) error
	}

	parser struct{}
)

func NewParser() Parser {
	return &parser{}
}

func (h *parser) Marshal(src any) ([]byte, error) {
	return json.Marshal(src)
}

func (h *parser) Unmarshal(src []byte, dest any) error {
	decoder := json.NewDecoder(bytes.NewReader(src))

	for decoder.More() {
		if err := decoder.Decode(dest); err != nil {
			return err
		}
	}

	return nil
}

func (h *parser) Decode(src io.Reader, dest any) error {
	decoder := json.NewDecoder(src)

	for decoder.More() {
		if err := decoder.Decode(dest); err != nil {
			return err
		}
	}

	return nil
}

func (h *parser) Encode(src io.Writer, dest any) error {
	return json.NewEncoder(src).Encode(dest)
}
