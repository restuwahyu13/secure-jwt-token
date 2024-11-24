package pkg

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"math"
	"time"

	"github.com/restuwahyu13/secure-jwt-token/configs"
	"github.com/restuwahyu13/secure-jwt-token/helpers"
)

type (
	JsonWebToken interface {
		Sign(prefix string, body any) ([]byte, error)
	}

	SecretMetadata struct {
		PrivKeyRaw string `json:"privKeyRaw"`
		CipherKey  string `json:"cipherKey"`
	}

	SignatureMetadata struct {
		PrivKey    *rsa.PrivateKey    `json:"privKey"`
		PrivKeyRaw string             `json:"privKeyRaw"`
		SigKey     string             `json:"sigKey"`
		CipherKey  string             `json:"cipherKey"`
		JweKey     JweEncryptMetadata `json:"jweKey"`
	}

	jsonWebToken struct {
		env   configs.Environtment
		redis Redis
	}
)

var (
	jso    Jose           = NewJose(context.Background())
	cipher helpers.Crypto = helpers.NewCrypto()
	cert   helpers.Cert   = helpers.NewCert()
	parser helpers.Parser = helpers.NewParser()
)

func NewJsonWebToken(env configs.Environtment, redis Redis) JsonWebToken {
	return &jsonWebToken{env: env, redis: redis}
}

func (h *jsonWebToken) createSecret(prefix string, body []byte) (*SecretMetadata, error) {
	secretMetadata := new(SecretMetadata)
	timeNow := time.Now().Format(time.UnixDate)

	cipherTextRandom := fmt.Sprintf("%s:%s:%s:%d", prefix, string(body), timeNow, h.env.JWT_EXPIRED)
	cipherTextData := hex.EncodeToString([]byte(cipherTextRandom))

	cipherSecretKey, err := cipher.SHA512Sign(cipherTextData)
	if err != nil {
		return nil, err
	}

	cipherText, err := cipher.SHA512Sign(timeNow)
	if err != nil {
		return nil, err
	}

	cipherKey, err := cipher.AES256Encrypt(cipherSecretKey, cipherText)
	if err != nil {
		return nil, err
	}

	rsaPrivateKeyPassword := []byte(cipherKey)

	privateKey, err := cert.GeneratePrivateKey(rsaPrivateKeyPassword)
	if err != nil {
		return nil, err
	}

	secretMetadata.PrivKeyRaw = privateKey
	secretMetadata.CipherKey = cipherKey

	return secretMetadata, nil
}

func (h *jsonWebToken) createSignature(prefix string, body any) (*SignatureMetadata, error) {
	var (
		signatureMetadata *SignatureMetadata = new(SignatureMetadata)
		signatureKey      string             = fmt.Sprintf("%s:credential", prefix)
		signatureField    string             = "signature_metadata"
	)

	bodyByte, err := parser.Marshal(body)
	if err != nil {
		return nil, err
	}

	secretKey, err := h.createSecret(prefix, bodyByte)
	if err != nil {
		return nil, err
	}

	rsaPrivateKey, err := cert.PrivateKeyRawToKey([]byte(secretKey.PrivKeyRaw), []byte(secretKey.CipherKey))
	if err != nil {
		return nil, err
	}

	cipherHash512 := sha512.New()
	cipherHash512.Write(bodyByte)
	cipherHash512Body := cipherHash512.Sum(nil)

	signature, err := rsa.SignPKCS1v15(rand.Reader, rsaPrivateKey, crypto.SHA512, cipherHash512Body)
	if err != nil {
		return nil, err
	}

	if err := rsa.VerifyPKCS1v15(&rsaPrivateKey.PublicKey, crypto.SHA512, cipherHash512Body, signature); err != nil {
		return nil, err
	}

	signatureOutput := hex.EncodeToString(signature)

	_, jweKey, err := jso.JweEncrypt(&rsaPrivateKey.PublicKey, signatureOutput)
	if err != nil {
		return nil, err
	}

	signatureMetadata.PrivKeyRaw = secretKey.PrivKeyRaw
	signatureMetadata.SigKey = signatureOutput
	signatureMetadata.CipherKey = secretKey.CipherKey
	signatureMetadata.JweKey = *jweKey

	signatureMetadataByte, err := parser.Marshal(signatureMetadata)
	if err != nil {
		return nil, err
	}

	jwtClaim := string(signatureMetadataByte)
	jwtExpired := time.Duration(time.Minute * time.Duration(h.env.JWT_EXPIRED))

	if err := h.redis.HSetEx(signatureKey, jwtExpired, signatureField, jwtClaim); err != nil {
		return nil, err
	}

	signatureMetadata.PrivKey = rsaPrivateKey
	return signatureMetadata, nil
}

func (h *jsonWebToken) Sign(prefix string, body any) ([]byte, error) {
	tokenKey := fmt.Sprintf("%s:token", prefix)

	tokenExist, err := h.redis.Exists(tokenKey)
	if err != nil {
		return nil, err
	}

	if tokenExist < 1 {
		signature, err := h.createSignature(prefix, body)
		if err != nil {
			return nil, err
		}

		timestamp := time.Now().Format("2006/01/02 15:04:05")
		aud := signature.SigKey[10:20]
		iss := signature.SigKey[30:40]
		sub := signature.SigKey[50:60]
		suffix := int(math.Pow(float64(h.env.JWT_EXPIRED), float64(len(aud)+len(iss)+len(sub))))

		secretKey := fmt.Sprintf("%s:%s:%s:%s:%d", aud, iss, sub, timestamp, suffix)
		secretData := hex.EncodeToString([]byte(secretKey))

		jti, err := cipher.AES256Encrypt(secretData, prefix)
		if err != nil {
			return nil, err
		}

		duration := time.Duration(time.Minute * time.Duration(h.env.JWT_EXPIRED))
		jwtIat := time.Now().UTC().Add(-duration)
		jwtExp := time.Now().Add(duration)

		tokenPayload := new(JwtSignOption)
		tokenPayload.SecretKey = signature.CipherKey
		tokenPayload.Kid = signature.JweKey.CipherText
		tokenPayload.PrivateKey = signature.PrivKey
		tokenPayload.Aud = []string{aud}
		tokenPayload.Iss = iss
		tokenPayload.Sub = sub
		tokenPayload.Jti = jti
		tokenPayload.Iat = jwtIat
		tokenPayload.Exp = jwtExp
		tokenPayload.Claim = timestamp

		tokenData, err := jso.JwtSign(tokenPayload)
		if err != nil {
			return nil, err
		}

		if err := h.redis.SetEx(tokenKey, duration, string(tokenData)); err != nil {
			return nil, err
		}

		return tokenData, nil
	} else {
		tokenData, err := h.redis.Get(tokenKey)
		if err != nil {
			return nil, err
		}

		return tokenData, nil
	}
}
