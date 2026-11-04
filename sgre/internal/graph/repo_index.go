package graph

import (
	"sort"

	"github.com/DannyAn/secguard-clang/internal/db"
)

// RepoIndex is an immutable snapshot of the indexed functions and files for one
// scan. It is built once in the pipeline and shared read-only across every graph
// builder and detector via ctx, so the 70+ callers that previously each ran
// ListFunctions + ListFiles + per-file GetFileByID now read from one snapshot.
//
// All fields are unexported and the type is concurrency-safe for read access by
// construction (nothing mutates it after NewRepoIndex returns).
type RepoIndex struct {
	functions []*db.Function
	files     []*db.File

	funcsByID   map[int64]*db.Function
	filesByID   map[int64]*db.File
	funcsByFile map[int64][]*db.Function
	fileOrder   []int64
}

// NewRepoIndex builds an immutable index from the full function and file lists.
// Either slice may be nil (the resulting index is empty but valid), so callers
// that only need the function view can pass nil files.
func NewRepoIndex(functions []*db.Function, files []*db.File) *RepoIndex {
	ri := &RepoIndex{
		functions:   functions,
		files:       files,
		funcsByID:   make(map[int64]*db.Function, len(functions)),
		filesByID:   make(map[int64]*db.File, len(files)),
		funcsByFile: make(map[int64][]*db.Function, len(files)),
	}
	for _, f := range functions {
		if f == nil {
			continue
		}
		ri.funcsByID[f.ID] = f
		if _, seen := ri.funcsByFile[f.FileID]; !seen {
			ri.fileOrder = append(ri.fileOrder, f.FileID)
		}
		ri.funcsByFile[f.FileID] = append(ri.funcsByFile[f.FileID], f)
	}
	sort.Slice(ri.fileOrder, func(i, j int) bool { return ri.fileOrder[i] < ri.fileOrder[j] })
	for _, fl := range files {
		if fl == nil {
			continue
		}
		ri.filesByID[fl.ID] = fl
	}
	return ri
}

// Functions returns all indexed functions. The returned slice aliases the
// internal storage; callers must not mutate it.
func (ri *RepoIndex) Functions() []*db.Function { return ri.functions }

// Files returns all indexed files. The returned slice aliases the internal
// storage; callers must not mutate it.
func (ri *RepoIndex) Files() []*db.File { return ri.files }

// FuncByID returns the function with the given ID, or nil.
func (ri *RepoIndex) FuncByID(id int64) *db.Function { return ri.funcsByID[id] }

// FileByID returns the file with the given ID, or nil.
func (ri *RepoIndex) FileByID(id int64) *db.File { return ri.filesByID[id] }

// FuncsByFile returns the functions in the given file (possibly empty/nil).
func (ri *RepoIndex) FuncsByFile(fileID int64) []*db.Function { return ri.funcsByFile[fileID] }

// FileOrder returns the IDs of files that contain at least one indexed
// function, in ascending order. Iterating this and calling FuncsByFile
// reproduces the old forEachFile visitation order.
func (ri *RepoIndex) FileOrder() []int64 { return ri.fileOrder }