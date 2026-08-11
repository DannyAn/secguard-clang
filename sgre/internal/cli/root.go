package cli

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/log"
)

const Version = "0.1.0"

func Execute(ctx context.Context, args []string) int {
	if len(args) == 0 {
		printUsage()
		return 0
	}

	switch args[0] {
	case "--help", "-h", "help":
		printUsage()
		return 0
	case "--version", "-v", "version":
		fmt.Fprintln(os.Stdout, Version)
		return 0
	case "index":
		return runIndexCmd(ctx, args[1:])
	case "scan":
		return runScanCmd(ctx, args[1:])
	case "status":
		return runStatusCmd(ctx, args[1:])
	case "query":
		return runQueryCmd(ctx, args[1:])
	case "plan":
		return runPlanCmd(ctx, args[1:])
	case "report":
		return runReportCmd(ctx, args[1:])
	case "db":
		return runDbCmd(ctx, args[1:])
	default:
		WriteErrorJSON(fmt.Sprintf("unknown command %q; available: index, scan, status, query, plan, report, db", args[0]))
		return 1
	}
}

func printUsage() {
	fmt.Fprintln(os.Stdout, `secguard - AI-Augmented Program Security Analysis Platform

Usage:
  secguard index <path>    Index a C codebase
  secguard scan <path>     Full pipeline: index + plan all vuln types + report
  secguard status          Show index status (files, functions, staleness)
  secguard query <skill>   Run a skill query
  secguard plan <vuln>     Run convergence pipeline for a vulnerability type
  secguard report          Output all findings as JSON
  secguard db <sql>        Execute SQL query on sgre.db, return JSON

Flags:
  --db <path>    Path to sgre.db (default: ./sgre.db)
  --help         Show usage
  --version      Show version`)
}

func parseDBFlag(args []string) (string, []string) {
	dbPath := "./sgre.db"
	var remaining []string
	for i := 0; i < len(args); i++ {
		if args[i] == "--db" && i+1 < len(args) {
			dbPath = args[i+1]
			i++
		} else if strings.HasPrefix(args[i], "--db=") {
			dbPath = args[i][5:]
		} else {
			remaining = append(remaining, args[i])
		}
	}
	return dbPath, remaining
}

func openStore(ctx context.Context, dbPath string) (db.Store, error) {
	d, err := db.Open(ctx, dbPath)
	if err != nil {
		return nil, err
	}
	return db.NewStore(d), nil
}

func defaultLogger() *log.Logger {
	return log.Default()
}
