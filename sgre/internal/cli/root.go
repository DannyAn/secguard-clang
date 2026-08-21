package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/planner"
	"github.com/DannyAn/secguard-clang/internal/report"
)

// Version is the release version. It is a var (not const) so `go build
// -ldflags "-X github.com/DannyAn/secguard-clang/internal/cli.Version=<v>"`
// can inject the release version at build time; the fallback matches VERSION.
var Version = "0.3.5"

func Execute(ctx context.Context, args []string) int {
	// Sync the db layer's supported-CWE set from the planner registry so the
	// two never drift. This is the single injection point — every VulnTypeSpec
	// carries its CWE, and AllCWEs() is the authoritative set.
	db.SetSupportedCWEs(planner.AllCWEs())
	// Stamp the release version into the report layer so SARIF and markdown
	// reports carry the actual build version, not a hardcoded constant.
	report.ToolVersion = Version

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
	case "types":
		return runTypesCmd()
	case "plan":
		return runPlanCmd(ctx, args[1:])
	case "report":
		return runReportCmd(ctx, args[1:])
	case "db":
		return runDbCmd(ctx, args[1:])
	case "schema":
		return runSchemaCmd(args[1:])
	default:
		WriteErrorJSON(fmt.Sprintf("unknown command %q; available: index, scan, status, query, types, plan, report, db, schema", args[0]))
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
  secguard types           List all vulnerability types + CWE (JSON)
  secguard plan <vuln>     Run convergence pipeline for a vulnerability type
  secguard report          Output all findings as JSON
  secguard db <sql>        Execute SQL query on sgre.db, return JSON
  secguard schema [table]  Show DB schema for agent-queryable tables

Flags:
  --db <path>         Path to sgre.db (default: .codeagent/secguard-clang/.sgre/sgre.db)
  --exclude <dirs>    Comma-separated directory basenames to skip (default: deps,third_party,vendor,external,node_modules,tests,test,fuzzing,contrib,examples)
  --help              Show usage
  --version           Show version`)
}

// parseDBFlag extracts an optional --db flag. explicit reports whether the flag
// was actually present, so callers can tell "no flag given" apart from the
// legacy ./sgre.db default and substitute the canonical per-project path.
func parseDBFlag(args []string) (dbPath string, explicit bool, remaining []string) {
	dbPath = "./sgre.db"
	for i := 0; i < len(args); i++ {
		if args[i] == "--db" && i+1 < len(args) {
			dbPath = args[i+1]
			explicit = true
			i++
		} else if strings.HasPrefix(args[i], "--db=") {
			dbPath = args[i][5:]
			explicit = true
		} else {
			remaining = append(remaining, args[i])
		}
	}
	return dbPath, explicit, remaining
}

// resolveDBPath returns the DB path a command should open: the explicit --db
// value when given, otherwise the canonical location under projectRoot
// (.codeagent/secguard-clang/.sgre/sgre.db) so intermediate results never land
// as a stray sgre.db in the source tree.
func resolveDBPath(explicit bool, dbPath, projectRoot string) string {
	if explicit {
		return dbPath
	}
	return report.GetDbPath(projectRoot)
}

func openStore(ctx context.Context, dbPath string) (db.Store, error) {
	// Ensure the parent directory exists so a default canonical path
	// (.codeagent/secguard-clang/.sgre/sgre.db) opens cleanly on first use
	// rather than failing on a missing directory.
	if abs, err := filepath.Abs(dbPath); err == nil {
		if err := os.MkdirAll(filepath.Dir(abs), 0755); err != nil {
			return nil, err
		}
	}
	d, err := db.Open(ctx, dbPath)
	if err != nil {
		return nil, err
	}
	return db.NewStore(d), nil
}

func defaultLogger() *log.Logger {
	return log.Default()
}
