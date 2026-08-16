package evidence

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

type CryptoMisuseDetector struct {
	store  db.Store
	parser *parser.Parser
	logger *log.Logger
}

func NewCryptoMisuseDetector(store db.Store, p *parser.Parser, logger *log.Logger) *CryptoMisuseDetector {
	return &CryptoMisuseDetector{store: store, parser: p, logger: logger}
}

func (d *CryptoMisuseDetector) Name() string { return "crypto_misuse" }

func (d *CryptoMisuseDetector) Domain() string { return "crypto" }

func (d *CryptoMisuseDetector) Capabilities() []string {
	return []string{"weak-algorithm", "weak-random", "undersized-key", "unchecked-key"}
}

var weakCryptoFunctions = map[string]string{
	"DES_set_key_unchecked": "DES key set without parity check",
	"DES_set_key":           "DES is deprecated (56-bit key)",
	"DES_ecb_encrypt":       "DES ECB mode is insecure",
	"DES_cbc_encrypt":       "DES CBC mode is weak (56-bit key)",
	"DES_ncbc_encrypt":      "DES is weak (56-bit key)",
	"RC4_set_key":           "RC4 is broken",
	"MD5":                   "MD5 is cryptographically broken",
	"MD5_Init":              "MD5 is cryptographically broken",
	"MD5_Update":            "MD5 is cryptographically broken",
	"MD5_Final":             "MD5 is cryptographically broken",
	"SHA1":                  "SHA-1 is deprecated",
	"SHA1_Init":             "SHA-1 is deprecated",
	"SHA1_Update":           "SHA-1 is deprecated",
	"SHA1_Final":            "SHA-1 is deprecated",
	"EVP_des_cbc":           "DES-CBC is weak",
	"EVP_des_ecb":           "DES-ECB is insecure",
	"EVP_rc4":               "RC4 is broken",
	"crypt":                 "crypt() uses weak hashing",
}

var weakPrngFunctions = map[string]bool{
	"rand": true, "srand": true,
}

func (d *CryptoMisuseDetector) Detect(ctx context.Context) (DetectResult, error) {
	result := DetectResult{}

	err := forEachFile(ctx, d.store, d.parser, func(file *db.File, root parser.Node, funcs []*db.Function) {
		calls := root.FindAll("call_expression")
		for _, f := range funcs {
			for _, call := range calls {
				if !funcLineRange(f, call.StartLine()) {
					continue
				}
				callName := extractCallName(call)

				if reason, ok := weakCryptoFunctions[callName]; ok {
					d.emitCryptoEvent(ctx, file, f, call, callName, reason, "weak_algorithm", &result)
				}

				if weakPrngFunctions[callName] {
					d.emitCryptoEvent(ctx, file, f, call, callName, "weak PRNG for security context", "weak_random", &result)
				}
			}
		}

		// Undersized-key scan runs once per file. For each declaration, find
		// the function whose [StartLine, EndLine] range contains the decl line,
		// so the event is attributed to the correct function (not funcs[0]).
		if len(funcs) > 0 {
			decls := root.FindAll("declaration")
			d.detectUndersizedKey(ctx, decls, file, funcs, &result)
		}
	})
	return result, err
}

func (d *CryptoMisuseDetector) emitCryptoEvent(ctx context.Context, file *db.File, f *db.Function, call parser.Node, callName, reason, category string, result *DetectResult) {
	locID, _ := d.store.InsertLocation(ctx, &db.Location{FileID: file.ID, Line: call.StartLine(), Column: call.StartColumn()})
	props, _ := json.Marshal(map[string]string{
		"function":   callName,
		"reason":     reason,
		"category":   category,
		"expression": call.Text(),
	})
	_, err := d.store.InsertEvent(ctx, &db.SecurityEvent{
		EventType:  "CRYPTO_MISUSE",
		EntityID:   f.ID,
		LocationID: locID,
		Properties: string(props),
	})
	if err == nil {
		result.EventsCreated++
	}
}

func (d *CryptoMisuseDetector) detectUndersizedKey(ctx context.Context, decls []parser.Node, file *db.File, funcs []*db.Function, result *DetectResult) {
	for _, decl := range decls {
		text := decl.Text()
		if !strings.Contains(text, "key") && !strings.Contains(text, "Key") {
			continue
		}
		for _, arrayDecl := range decl.FindAll("array_declarator") {
			for _, child := range arrayDecl.NamedChildren() {
				if child.Kind() == "number_literal" {
					size := 0
					fmt.Sscanf(child.Text(), "%d", &size)
					if size > 0 && size < 16 {
						locID, _ := d.store.InsertLocation(ctx, &db.Location{FileID: file.ID, Line: decl.StartLine(), Column: decl.StartColumn()})
						props, _ := json.Marshal(map[string]string{
							"key_size": child.Text(),
							"reason":   "key size < 16 bytes (minimum 128-bit)",
							"category": "undersized_key",
						})
						owner := funcs[0]
						for _, fn := range funcs {
							if funcLineRange(fn, decl.StartLine()) {
								owner = fn
								break
							}
						}
						d.store.InsertEvent(ctx, &db.SecurityEvent{
							EventType:  "CRYPTO_MISUSE",
							EntityID:   owner.ID,
							LocationID: locID,
							Properties: string(props),
						})
						result.EventsCreated++
					}
				}
			}
		}
	}
}
