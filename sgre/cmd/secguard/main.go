package main

import (
	"context"
	"os"

	"github.com/kongan/secguard-lite/internal/cli"
)

func main() {
	ctx := context.Background()
	exitCode := cli.Execute(ctx, os.Args[1:])
	if exitCode != 0 {
		os.Exit(exitCode)
	}
}
