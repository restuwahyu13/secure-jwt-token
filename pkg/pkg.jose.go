package pkg

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"reflect"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

type (
	Jose interface {
		JweEncrypt(publicKey *rsa.PublicKey, plainText string) ([]byte, *JweEncryptMetadata, error)
		JweDecrypt(privateKey *rsa.PrivateKey, cipherText []byte) (string, error)
		ImportJsonWebKey(jwkKey jwk.Key) (*JwkMetadata, error)
		ExportJsonWebKey(privateKey *rsa.PrivateKey) (*JwkMetadata, error)
		JwtSign(options *JwtSignOption) ([]byte, error)
		JwtVerify(prefix string, token string, redis Redis) (*jwt.Token, error)
	}

	JwsVerify struct {
		Aud       []string `json:"aud"`
		Exp       int      `json:"exp"`
		Iat       int      `json:"iat"`
		Iss       string   `json:"iss"`
		Jti       string   `json:"jti"`
		Sub       string   `json:"sub"`
		Timestamp string   `json:"timestamp"`
	}

	JwtSignOption struct {
		PrivateKey *rsa.PrivateKey
		Claim      interface{}
		Kid        string
		SecretKey  string
		Iss        string
		Sub        string
		Aud        []string
		Exp        time.Time
		Nbf        float64
		Iat        time.Time
		Jti        string
	}

	JweEncryptMetadata struct {
		CipherText   string         `json:"ciphertext"`
		EncryptedKey string         `json:"encrypted_key"`
		Header       map[string]any `json:"header"`
		IV           string         `json:"iv"`
		Protected    string         `json:"protected"`
		Tag          string         `json:"tag"`
	}

	JwkRawMetadata struct {
		D   string `json:"d"`
		Dp  string `json:"dp"`
		Dq  string `json:"dq"`
		E   string `json:"e"`
		Kty string `json:"kty"`
		N   string `json:"n"`
		P   string `json:"p"`
		Q   string `json:"q"`
		Qi  string `json:"qi"`
	}

	JwkMetadata struct {
		KeyRaw JwkRawMetadata
		Key    jwk.Key
	}

	jose struct {
		ctx context.Context
	}
)

func NewJose(ctx context.Context) Jose {
	jwk.Configure(jwk.WithStrictKeyUsage(true))
	return &jose{ctx: ctx}
}

func (h *jose) JweEncrypt(publicKey *rsa.PublicKey, plainText string) ([]byte, *JweEncryptMetadata, error) {
	jweEncryptMetadata := new(JweEncryptMetadata)

	headers := jwe.NewHeaders()
	headers.Set("sig", plainText)
	headers.Set("alg", jwa.RSA_OAEP_512().String())
	headers.Set("enc", jwa.A256GCM().String())

	cipherText, err := jwe.Encrypt([]byte(plainText), jwe.WithKey(jwa.RSA_OAEP_512(), publicKey), jwe.WithContentEncryption(jwa.A256GCM()), jwe.WithCompact(), jwe.WithJSON(), jwe.WithProtectedHeaders(headers))
	if err != nil {
		return nil, nil, err
	}

	if err := parser.Unmarshal(cipherText, jweEncryptMetadata); err != nil {
		return nil, nil, err
	}

	return cipherText, jweEncryptMetadata, nil
}

func (h *jose) JweDecrypt(privateKey *rsa.PrivateKey, cipherText []byte) (string, error) {
	jwtKey, err := jwk.Import(privateKey)
	if err != nil {
		return "", err
	}

	jwkSet := jwk.NewSet()
	if err := jwkSet.AddKey(jwtKey); err != nil {
		return "", err
	}

	plainText, err := jwe.Decrypt(cipherText, jwe.WithKey(jwa.RSA_OAEP_512(), jwtKey), jwe.WithKeySet(jwkSet, jwe.WithRequireKid(false)))
	if err != nil {
		return "", err
	}

	return string(plainText), nil
}

func (h *jose) ImportJsonWebKey(jwkKey jwk.Key) (*JwkMetadata, error) {
	jwkRawMetadata := JwkMetadata{}

	if _, err := jwk.IsPrivateKey(jwkKey); err != nil {
		return nil, err
	}

	if err := jwk.AssignKeyID(jwkKey); err != nil {
		return nil, err
	}

	jwkKeyByte, err := parser.Marshal(&jwkKey)
	if err != nil {
		return nil, err
	}

	jwkRaw, err := jwk.ParseKey(jwkKeyByte)
	if err != nil {
		return nil, err
	}

	if err := parser.Unmarshal(jwkKeyByte, &jwkRawMetadata.KeyRaw); err != nil {
		return nil, err
	}

	jwkRawMetadata.Key = jwkRaw

	return &jwkRawMetadata, nil
}

func (h *jose) ExportJsonWebKey(privateKey *rsa.PrivateKey) (*JwkMetadata, error) {
	jwkRawMetadata := JwkMetadata{}

	jwkRaw, err := jwk.ParseKey([]byte(cert.PrivateKeyToRaw(privateKey)), jwk.WithPEM(true))
	if err != nil {
		return nil, err
	}

	jwkRawByte, err := parser.Marshal(&jwkRaw)
	if err != nil {
		return nil, err
	}

	if err := parser.Unmarshal(jwkRawByte, &jwkRawMetadata.KeyRaw); err != nil {
		return nil, err
	}

	jwkRawMetadata.Key = jwkRaw.(jwk.Key)

	return &jwkRawMetadata, nil
}

func (h *jose) JwtSign(options *JwtSignOption) ([]byte, error) {
	jwsHeader := jws.NewHeaders()
	jwsHeader.Set("alg", jwa.RS512)
	jwsHeader.Set("typ", "JWT")
	jwsHeader.Set("cty", "JWT")
	jwsHeader.Set("kid", options.Kid)
	jwsHeader.Set("b64", true)

	jwtBuilder := jwt.NewBuilder()
	jwtBuilder.Audience(options.Aud)
	jwtBuilder.Issuer(options.Iss)
	jwtBuilder.Subject(options.Sub)
	jwtBuilder.IssuedAt(options.Iat)
	jwtBuilder.Expiration(options.Exp)
	jwtBuilder.JwtID(options.Jti)
	jwtBuilder.Claim("timestamp", options.Claim)

	jwtToken, err := jwtBuilder.Build()
	if err != nil {
		return nil, err
	}

	token, err := jwt.Sign(jwtToken, jwt.WithKey(jwa.RS512(), options.PrivateKey, jws.WithProtectedHeaders(jwsHeader)))
	if err != nil {
		return nil, err
	}

	return token, nil
}

func (h *jose) JwtVerify(prefix string, token string, redis Redis) (*jwt.Token, error) {
	signatureKey := fmt.Sprintf("%s:credential", prefix)
	secretMetadataField := "certificate_metadata"
	signatureMetadataField := "signature_metadata"

	secretKey := new(SecretMetadata)
	signature := new(SignatureMetadata)

	certMetadataBytes, err := redis.HGet(signatureKey, secretMetadataField)
	if err != nil {
		return nil, err
	}

	if err := parser.Unmarshal(certMetadataBytes, secretKey); err != nil {
		return nil, err
	}

	sigMetadataBytes, err := redis.HGet(signatureKey, signatureMetadataField)
	if err != nil {
		return nil, err
	}

	if err := parser.Unmarshal(sigMetadataBytes, signature); err != nil {
		return nil, err
	}

	if reflect.DeepEqual(secretKey, SecretMetadata{}) && reflect.DeepEqual(signature, SignatureMetadata{}) {
		return nil, errors.New("Invalid secretkey or signature")
	}

	privateKey, err := cert.PrivateKeyRawToKey([]byte(signature.PrivKeyRaw), []byte(signature.CipherKey))
	if err != nil {
		return nil, err
	}

	exportJwk, err := jws.ParseString(token)
	if err != nil {
		return nil, err
	}

	jwsSignature := new(jws.Signature)
	for _, sig := range exportJwk.Signatures() {
		jwsSignature = sig
		break
	}

	jwsHeaders := jwsSignature.ProtectedHeaders()

	algorithm, ok := jwsHeaders.Algorithm()
	if !ok {
		return nil, errors.New("Invalid algorithm")
	} else if algorithm != jwa.RS512() {
		return nil, errors.New("Invalid algorithm")
	}

	kid, ok := jwsHeaders.KeyID()
	if !ok {
		return nil, errors.New("Invalid keyid")
	} else if kid != signature.JweKey.CipherText {
		return nil, errors.New("Invalid keyid")
	}

	aud := signature.SigKey[10:20]
	iss := signature.SigKey[30:40]
	sub := signature.SigKey[50:60]
	claim := "timestamp"

	jwkKey, err := jwk.Import(privateKey)
	if err != nil {
		return nil, err
	}

	_, err = jws.Verify([]byte(token), jws.WithValidateKey(true), jws.WithKey(algorithm, jwkKey), jws.WithMessage(exportJwk))
	if err != nil {
		return nil, err
	}

	jwtParse, err := jwt.Parse([]byte(token),
		jwt.WithKey(jwa.RS512(), privateKey),
		jwt.WithAudience(aud),
		jwt.WithIssuer(iss),
		jwt.WithSubject(sub),
		jwt.WithRequiredClaim(claim),
	)

	if err != nil {
		return nil, err
	}

	return &jwtParse, nil
}
