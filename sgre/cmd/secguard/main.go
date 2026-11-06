package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/DannyAn/secguard-clang/internal/cli"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	exitCode := cli.Execute(ctx, os.Args[1:])
	if exitCode != 0 {
		os.Exit(exitCode)
	}
}
