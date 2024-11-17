package main

import (
	"context"
	"fmt"
	"net/http"

	"github.com/samber/lo"
	"github.com/sirupsen/logrus"

	"github.com/restuwahyu13/secure-jwt-token/configs"
	"github.com/restuwahyu13/secure-jwt-token/helpers"
	"github.com/restuwahyu13/secure-jwt-token/middlewares"
	"github.com/restuwahyu13/secure-jwt-token/pkg"
)

type (
	User struct {
		ID       string `json:"id"`
		Name     string `json:"name"`
		Username string `json:"username"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	Login struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
)

var (
	env   configs.Environtment
	users []User
)

func main() {
	ctx := context.Background()
	file := helpers.NewFile()
	parser := helpers.NewParser()

	if err := pkg.NewViper().Read(".env", &env); err != nil {
		logrus.Fatal(err)
		return
	}

	redis, err := pkg.NewRedis(ctx, 0, env.REDIS_URL)
	if err != nil {
		logrus.Fatal(err)
		return
	}

	res := file.Read("database.json", ".")
	if err := parser.Unmarshal(res, &users); err != nil {
		logrus.Fatal(err)
		return
	}

	jwt := pkg.NewJsonWebToken(env, redis)

	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Content-Type", "application/json")

		login := new(Login)

		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			w.Write([]byte("Request method not allowed"))
			return
		}

		if err := parser.Decode(r.Body, login); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(err.Error()))
			return
		}

		user, isFind := lo.Find[User](users, func(item User) bool {
			return item.Email == login.Email && item.Password == login.Password
		})

		if !isFind {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("Invalid username or password"))
			return
		}

		token, err := jwt.Sign(user.ID, user)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(err.Error()))
			return
		}

		w.Write([]byte(token))
	})

	http.HandleFunc("/profile", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Content-Type", "application/json")

		if err := middlewares.Auth(w, r, env, redis); err != nil {
			defer logrus.Error(err)
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Unauthorized token"))
			return
		}

		users, err := parser.Marshal(users)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(err.Error()))
			return
		}

		w.Write(users)
	})

	logrus.Info(fmt.Sprintf("Server is running on port %s", env.PORT))
	http.ListenAndServe(env.PORT, nil)
}
