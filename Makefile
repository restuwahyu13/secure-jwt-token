run:
	@nodemon -V -e .go -w . -x go run . --count=1 --race -V --signal SIGTERM SIGHUP SIGINT SIGQUIT SIGABRT SIGUSR1