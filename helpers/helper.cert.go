package helpers

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"strings"
)

const (
	PRIVPKCS1 = "RSA PRIVATE KEY"
	PRIVPKCS8 = "PRIVATE KEY"

	PUBPKCS1 = "RSA PUBLIC KEY"
	PUBPKCS8 = "PUBLIC KEY"

	CERTIFICATE = "CERTIFICATE"
)

type (
	Cert interface {
		GeneratePrivateKey(password []byte) (string, error)
		PrivateKeyRawToKey(privateKey []byte, password []byte) (*rsa.PrivateKey, error)
		PrivateKeyToRaw(publicKey *rsa.PrivateKey) string
		PublicKeyToRaw(publicKey *rsa.PublicKey) string
		PrivateKey(value string) error
		PublicKey(value string, raw bool) ([]byte, error)
	}
	cert struct{}
)

func NewCert() Cert {
	return &cert{}
}

func (h *cert) GeneratePrivateKey(password []byte) (string, error) {
	var pemBlock *pem.Block = new(pem.Block)

	rsaPrivateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return "", err
	}

	privateKeyTransform := h.PrivateKeyToRaw(rsaPrivateKey)

	if password != nil {
		encryptPemBlock, err := x509.EncryptPEMBlock(rand.Reader, "RSA PRIVATE KEY", []byte(privateKeyTransform), []byte(password), x509.PEMCipherAES256)
		if err != nil {
			return "", err
		}

		pemBlock = encryptPemBlock
	} else {
		decodePemBlock, _ := pem.Decode([]byte(privateKeyTransform))
		if pemBlock == nil {
			return "", errors.New("Invalid privateKey")
		}

		pemBlock = decodePemBlock
	}

	return string(pem.EncodeToMemory(pemBlock)), nil
}

func (h *cert) PrivateKeyRawToKey(privateKey []byte, password []byte) (*rsa.PrivateKey, error) {
	decodedPrivateKey, _ := pem.Decode(privateKey)
	if decodedPrivateKey == nil {
		return nil, errors.New("Invalid privateKey")
	}

	if x509.IsEncryptedPEMBlock(decodedPrivateKey) {
		deceryptPrivateKey, err := x509.DecryptPEMBlock(decodedPrivateKey, password)
		if err != nil {
			return nil, err
		}

		decodedPrivateKey, _ = pem.Decode(deceryptPrivateKey)
		if decodedPrivateKey == nil {
			return nil, errors.New("Invalid privateKey")
		}
	}

	rsaPrivKey, err := x509.ParsePKCS1PrivateKey(decodedPrivateKey.Bytes)
	if err != nil {
		return nil, err
	}

	return rsaPrivKey, nil
}

func (h *cert) PrivateKeyToRaw(publicKey *rsa.PrivateKey) string {
	privateKeyTransform := pem.EncodeToMemory(&pem.Block{
		Type:  PRIVPKCS1,
		Bytes: x509.MarshalPKCS1PrivateKey(publicKey),
	})

	return string(privateKeyTransform)
}

func (h *cert) PublicKeyToRaw(publicKey *rsa.PublicKey) string {
	publicKeyTransform := pem.EncodeToMemory(&pem.Block{
		Type:  PUBPKCS1,
		Bytes: x509.MarshalPKCS1PublicKey(publicKey),
	})

	return string(publicKeyTransform)
}

func (h *cert) PrivateKey(value string) error {
	var privateKey string

	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value))
	if err != nil {
		return err
	}

	pemDecoded, _ := pem.Decode([]byte(decoded))
	if pemDecoded == nil {
		return errors.New("Invalid PEM PrivateKey certificate")
	}

	if pemDecoded.Type == PRIVPKCS1 {
		privateKey = string(pem.EncodeToMemory(pemDecoded))
	} else if pemDecoded.Type == PRIVPKCS8 {
		privateKey = string(pem.EncodeToMemory(pemDecoded))
	} else if pemDecoded.Type == CERTIFICATE {
		privateKey = string(pem.EncodeToMemory(pemDecoded))
	} else {
		return errors.New("Invalid PEM PrivateKey certificate")
	}

	if privateKey == "" {
		return errors.New("Invalid PEM PrivateKey certificate")
	}

	return nil
}

func (h *cert) PublicKey(value string, rawPem bool) ([]byte, error) {
	var publicKey []byte

	externalPublicKey, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value))
	if err != nil {
		return nil, err
	}

	pemDecoded, _ := pem.Decode([]byte(externalPublicKey))
	if pemDecoded == nil {
		return nil, errors.New("Invalid PEM PublicKey certificate")
	}

	if !rawPem && pemDecoded.Type == PUBPKCS1 {
		publicKey = pem.EncodeToMemory(pemDecoded)
	} else if !rawPem && pemDecoded.Type == PUBPKCS8 {
		publicKey = pem.EncodeToMemory(pemDecoded)
	} else if !rawPem && pemDecoded.Type == CERTIFICATE {
		publicKey = pem.EncodeToMemory(pemDecoded)
	} else {
		publicKey = pemDecoded.Bytes
	}

	return publicKey, nil
}
