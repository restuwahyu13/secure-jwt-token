package configs

type Environtment struct {
	ENV  string `env:"GO_ENV" envDefault:"development"`
	PORT string `env:"PORT" envDefault:":3000"`

	JWT_SECRET_KEY string `env:"JWT_SECRET_KEY,required"`
	JWT_EXPIRED    int    `env:"JWT_EXPIRED,required"`

	REDIS_URL string `env:"REDIS_URL,required"`
}
