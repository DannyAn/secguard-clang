package main

import (
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "usage: gen_codebase <output_dir> [num_files] [funcs_per_file]\n")
		os.Exit(1)
	}
	outDir := os.Args[1]
	numFiles := 100
	funcsPerFile := 50
	if len(os.Args) >= 3 {
		fmt.Sscanf(os.Args[2], "%d", &numFiles)
	}
	if len(os.Args) >= 4 {
		fmt.Sscanf(os.Args[3], "%d", &funcsPerFile)
	}

	if err := os.MkdirAll(outDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "mkdir failed: %v\n", err)
		os.Exit(1)
	}

	totalLOC := 0
	for f := 0; f < numFiles; f++ {
		var content string
		content += fmt.Sprintf("/* generated file %d */\n\n", f)
		content += "#include <stdlib.h>\n\n"

		for i := 0; i < funcsPerFile; i++ {
			content += generateFunction(f, i)
		}

		path := filepath.Join(outDir, fmt.Sprintf("module_%d.c", f))
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			fmt.Fprintf(os.Stderr, "write failed: %v\n", err)
			os.Exit(1)
		}
		totalLOC += countLines(content)
	}

	fmt.Printf("generated %d files, %d total LOC in %s\n", numFiles, totalLOC, outDir)
}

func generateFunction(fileIdx, funcIdx int) string {
	return fmt.Sprintf(`typedef struct S%d_%d { int a; int b; } S%d_%d;

static S%d_%d *alloc_s%d_%d(int n) {
    S%d_%d *s = (S%d_%d *)malloc(sizeof(S%d_%d) * n);
    if (!s) { return NULL; }
    s->a = n;
    s->b = 0;
    return s;
}

static int use_s%d_%d(S%d_%d *s) {
    return s->a + s->b;
}

int entry_%d_%d(int n) {
    S%d_%d *s = alloc_s%d_%d(n);
    return use_s%d_%d(s);
}

`, fileIdx, funcIdx, fileIdx, funcIdx,
		fileIdx, funcIdx, fileIdx, funcIdx,
		fileIdx, funcIdx, fileIdx, funcIdx, fileIdx, funcIdx,
		fileIdx, funcIdx, fileIdx, funcIdx,
		fileIdx, funcIdx,
		fileIdx, funcIdx, fileIdx, funcIdx, fileIdx, funcIdx,
		fileIdx, funcIdx)
}

func countLines(s string) int {
	n := 0
	for _, c := range s {
		if c == '\n' {
			n++
		}
	}
	return n + 1
}
