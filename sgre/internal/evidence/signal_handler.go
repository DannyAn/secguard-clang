package evidence

import (
	"context"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// SignalHandlerDetector flags CWE-479: a signal handler (registered via
// signal(2)) that calls a non-async-signal-safe libc function (malloc, printf,
// pthread_mutex_lock, ...). The POSIX async-signal-safe list is fixed, so a
// DIRECT call to one of these inside a registered handler is a certain defect —
// no taint or flow analysis is needed. The unsafe set below is a deliberate
// subset: only functions whose unsafe-ness is unambiguous. Transitive cases
// (handler -> helper -> malloc) and sigaction registration are left out to keep
// the detector sound (no false positives) and cheap (it does nothing unless a
// signal() call exists in the file).
type SignalHandlerDetector struct {
	store  db.Store
	parser *parser.Parser
	logger *log.Logger
}

func NewSignalHandlerDetector(store db.Store, p *parser.Parser, logger *log.Logger) *SignalHandlerDetector {
	return &SignalHandlerDetector{store: store, parser: p, logger: logger}
}

func (d *SignalHandlerDetector) Name() string { return "signal_handler" }

// asyncSignalUnsafe lists well-known libc functions that are NOT in the POSIX
// async-signal-safe list. read/write/open/close/socket/send/recv/connect/fcntl/
// fork/exec*/_exit/abort ARE async-signal-safe and intentionally absent.
var asyncSignalUnsafe = map[string]bool{
	// dynamic memory
	"malloc": true, "calloc": true, "realloc": true, "free": true,
	// stdio
	"printf": true, "fprintf": true, "sprintf": true, "snprintf": true,
	"vfprintf": true, "vsprintf": true, "vsnprintf": true, "vprintf": true,
	"fopen": true, "fclose": true, "fread": true, "fwrite": true, "fgets": true,
	"fputs": true, "puts": true, "gets": true, "scanf": true, "fscanf": true,
	"sscanf": true, "fflush": true, "perror": true,
	// strings (none of these are async-signal-safe)
	"strlen": true, "strcpy": true, "strncpy": true, "strcat": true, "strncat": true,
	"strcmp": true, "strncmp": true, "strdup": true, "strtok": true, "strchr": true,
	"strstr": true, "strcasecmp": true, "strncasecmp": true,
	// threading / synchronization
	"pthread_mutex_lock": true, "pthread_mutex_unlock": true, "pthread_mutex_trylock": true,
	"pthread_rwlock_rdlock": true, "pthread_rwlock_wrlock": true,
	"pthread_cond_wait": true, "pthread_cond_signal": true, "pthread_cond_broadcast": true,
	"pthread_create": true, "pthread_join": true, "pthread_detach": true,
	"sem_wait": true, "sem_post": true, "sem_trywait": true,
	// process / exit
	"exit": true, "system": true, "popen": true,
	// environment
	"getenv": true, "setenv": true, "putenv": true, "unsetenv": true,
	// time (non-reentrant)
	"localtime": true, "gmtime": true, "strftime": true, "asctime": true,
	"ctime": true, "mktime": true,
	// logging
	"syslog": true, "vsyslog": true, "openlog": true, "closelog": true,
	// user database / network lookup / misc
	"getpwnam": true, "getpwuid": true, "gethostbyname": true, "gethostbyaddr": true,
	"getaddrinfo": true, "freeaddrinfo": true, "inet_ntoa": true, "ioctl": true,
	"usleep": true,
}

func (d *SignalHandlerDetector) Detect(ctx context.Context) (DetectResult, error) {
	result := DetectResult{}

	err := forEachFile(ctx, d.store, d.parser, d.logger, func(file *db.File, root parser.Node, funcs []*db.Function) {
		calls := root.FindAll("call_expression")

		// 1. handler names registered via signal(SIGxxx, handler). This is the
		//    only expensive step, and it is a single tree traversal; if no
		//    signal() call exists we return here without touching the bodies.
		handlers := map[string]bool{}
		for _, call := range calls {
			if extractCallName(call) != "signal" {
				continue
			}
			args := getCallArgs(call)
			if len(args) < 2 || args[1].Kind() != "identifier" {
				continue
			}
			name := args[1].Text()
			if name == "SIG_DFL" || name == "SIG_IGN" {
				continue
			}
			handlers[name] = true
		}
		if len(handlers) == 0 {
			return
		}

		// 2. a handler whose body directly calls an unsafe function is CWE-479.
		for _, fnDef := range root.FindAll("function_definition") {
			fnName := functionDefName(fnDef)
			if fnName == "" || !handlers[fnName] {
				continue
			}
			body := fnDef.FindFirst("compound_statement")
			if body == nil {
				continue
			}
			for _, c := range body.FindAll("call_expression") {
				callee := extractCallName(c)
				if !asyncSignalUnsafe[callee] {
					continue
				}
				var fnID int64
				for _, f := range funcs {
					if f.Name == fnName {
						fnID = f.ID
						break
					}
				}
				if emitEvent(ctx, d.store, d.logger, "SIGNAL_HANDLER", fnID, &db.Location{FileID: file.ID, Line: c.StartLine()}, map[string]string{
					"variable":   callee,
					"function":   fnName,
					"category":   "signal_handler_unsafe",
					"expression": c.Text(),
				}) {
					result.EventsCreated++
				}
				break
			}
		}
	})
	return result, err
}

// functionDefName returns the declared name of a function_definition node.
func functionDefName(fn parser.Node) string {
	for _, child := range fn.NamedChildren() {
		if child.Kind() == "function_declarator" {
			if id := child.FindFirst("identifier"); id != nil {
				return id.Text()
			}
		}
	}
	return ""
}
