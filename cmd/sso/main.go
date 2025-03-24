package main

import (
	"fmt"
	"sso/internal/config"
)

func main() {
	cfg := config.MustLoad()

	fmt.Println(cfg)

	// TODO : initialize log

	// TODO : initialize app

	// TODO : start grpc server
}