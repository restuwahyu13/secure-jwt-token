package middlewares

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"net/http"
	"strings"

	"github.com/lestrrat-go/jwx/v3/jwt"

	"github.com/restuwahyu13/secure-jwt-token/configs"
	"github.com/restuwahyu13/secure-jwt-token/helpers"
	"github.com/restuwahyu13/secure-jwt-token/pkg"
)

func Auth(w http.ResponseWriter, r *http.Request, env configs.Environtment, redis pkg.Redis) error {
	jose := pkg.NewJose(r.Context())
	crypto := helpers.NewCrypto()

	headers := r.Header.Get("Authorization")

	if !strings.Contains(headers, "Bearer") {
		return errors.New("Authorization bearer is required")
	}

	token := strings.Split(headers, "Bearer ")[1]
	if len(strings.Split(token, ".")) != 3 {
		return errors.New("Invalid format JWT token")
	}

	tokenMetadata, err := jwt.ParseRequest(r, jwt.WithHeaderKey("Authorization"), jwt.WithVerify(false))
	if err != nil {
		return err
	}

	aud, ok := tokenMetadata.Audience()
	if !ok {
		return errors.New("Invalid Audience")
	}

	iss, ok := tokenMetadata.Issuer()
	if !ok {
		return errors.New("Invalid Issuer")
	}

	sub, ok := tokenMetadata.Subject()
	if !ok {
		return errors.New("Invalid Subject")
	}

	jti, ok := tokenMetadata.JwtID()
	if !ok {
		return errors.New("Invalid JwtID")
	}

	timestamp := ""
	if err := tokenMetadata.Get("timestamp", &timestamp); err != nil {
		return err
	}

	suffix := int(math.Pow(float64(env.JWT_EXPIRED), float64(len(aud[0])+len(iss)+len(sub))))

	secretKey := fmt.Sprintf("%s:%s:%s:%s:%d", aud[0], iss, sub, timestamp, suffix)
	secretData := hex.EncodeToString([]byte(secretKey))

	key, err := crypto.AES256Decrypt(secretData, jti)
	if err != nil {
		return err
	}

	if _, err = jose.JwtVerify(key, token, redis); err != nil {
		return err
	}

	return nil
}
