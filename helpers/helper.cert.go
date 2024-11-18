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
			return "", errors.New("Invalid PrivateKey")
		}

		pemBlock = decodePemBlock
	}

	return string(pem.EncodeToMemory(pemBlock)), nil
}

func (h *cert) PrivateKeyRawToKey(privateKey []byte, password []byte) (*rsa.PrivateKey, error) {
	decodePrivateKey, _ := pem.Decode(privateKey)
	if decodePrivateKey == nil {
		return nil, errors.New("Invalid PrivateKey")
	}

	if x509.IsEncryptedPEMBlock(decodePrivateKey) {
		decryptPrivateKey, err := x509.DecryptPEMBlock(decodePrivateKey, password)
		if err != nil {
			return nil, err
		}

		decodePrivateKey, _ = pem.Decode(decryptPrivateKey)
		if decodePrivateKey == nil {
			return nil, errors.New("Invalid PrivateKey")
		}
	}

	rsaPrivKey, err := x509.ParsePKCS1PrivateKey(decodePrivateKey.Bytes)
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

	decode, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value))
	if err != nil {
		return err
	}

	pemDecode, _ := pem.Decode([]byte(decode))
	if pemDecode == nil {
		return errors.New("Invalid PEM PrivateKey certificate")
	}

	if pemDecode.Type == PRIVPKCS1 {
		privateKey = string(pem.EncodeToMemory(pemDecode))
	} else if pemDecode.Type == PRIVPKCS8 {
		privateKey = string(pem.EncodeToMemory(pemDecode))
	} else if pemDecode.Type == CERTIFICATE {
		privateKey = string(pem.EncodeToMemory(pemDecode))
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

	pemDecode, _ := pem.Decode([]byte(externalPublicKey))
	if pemDecode == nil {
		return nil, errors.New("Invalid PEM PublicKey certificate")
	}

	if !rawPem && pemDecode.Type == PUBPKCS1 {
		publicKey = pem.EncodeToMemory(pemDecode)
	} else if !rawPem && pemDecode.Type == PUBPKCS8 {
		publicKey = pem.EncodeToMemory(pemDecode)
	} else if !rawPem && pemDecode.Type == CERTIFICATE {
		publicKey = pem.EncodeToMemory(pemDecode)
	} else {
		publicKey = pemDecode.Bytes
	}

	return publicKey, nil
}
