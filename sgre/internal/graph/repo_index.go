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
	funcsByName map[string][]*db.Function
	filesByID   map[int64]*db.File
	funcsByFile map[int64][]*db.Function
	fileOrder   []int64

	fileScopeByFile map[int64]map[string]string
	slotTargets     map[string][]string
	fileScopeOK     bool
	funcPtrOK       bool
}

// RepoFacts are the optional declaration facts shared by graph builders. The
// OK flags distinguish "loaded and empty" from "query failed": a false flag
// makes consumers fall back to their own DB query instead of silently treating
// every file/slot as empty.
type RepoFacts struct {
	FileScope       []*db.FileScopeVariable
	FuncPtrWrites   []db.FuncPtrWrite
	FileScopeOK     bool
	FuncPtrWritesOK bool
}

// NewRepoIndex builds an immutable index from the full function and file lists.
// Either slice may be nil (the resulting index is empty but valid), so callers
// that only need the function view can pass nil files.
func NewRepoIndex(functions []*db.Function, files []*db.File) *RepoIndex {
	return NewRepoIndexWithFacts(functions, files, RepoFacts{})
}

// NewRepoIndexWithFacts builds the index plus the optional file-scope and
// function-pointer facts loaded once by the pipeline.
func NewRepoIndexWithFacts(functions []*db.Function, files []*db.File, facts RepoFacts) *RepoIndex {
	ri := &RepoIndex{
		functions:   functions,
		files:       files,
		funcsByID:   make(map[int64]*db.Function, len(functions)),
		funcsByName: make(map[string][]*db.Function, len(functions)),
		filesByID:   make(map[int64]*db.File, len(files)),
		funcsByFile: make(map[int64][]*db.Function, len(files)),
	}
	for _, f := range functions {
		if f == nil {
			continue
		}
		ri.funcsByID[f.ID] = f
		ri.funcsByName[f.Name] = append(ri.funcsByName[f.Name], f)
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
	ri.fileScopeOK = facts.FileScopeOK
	if facts.FileScopeOK {
		ri.fileScopeByFile = make(map[int64]map[string]string)
		for _, v := range facts.FileScope {
			if v == nil {
				continue
			}
			m := ri.fileScopeByFile[v.FileID]
			if m == nil {
				m = make(map[string]string)
				ri.fileScopeByFile[v.FileID] = m
			}
			m[v.Name] = v.StorageClass
		}
	}
	ri.funcPtrOK = facts.FuncPtrWritesOK
	if facts.FuncPtrWritesOK {
		ri.slotTargets = make(map[string][]string)
		for _, w := range facts.FuncPtrWrites {
			ri.slotTargets[w.SlotName] = append(ri.slotTargets[w.SlotName], w.TargetName)
		}
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

// FuncsByName returns every indexed function with the given name. The returned
// slice aliases the internal storage; callers must not mutate it.
func (ri *RepoIndex) FuncsByName(name string) []*db.Function { return ri.funcsByName[name] }

// FileByID returns the file with the given ID, or nil.
func (ri *RepoIndex) FileByID(id int64) *db.File { return ri.filesByID[id] }

// FuncsByFile returns the functions in the given file (possibly empty/nil).
func (ri *RepoIndex) FuncsByFile(fileID int64) []*db.Function { return ri.funcsByFile[fileID] }

// FileScopeByFile returns file ID → (name → storage class), or nil when the
// facts were not loaded. Callers must not mutate the maps.
func (ri *RepoIndex) FileScopeByFile() map[int64]map[string]string {
	if ri == nil || !ri.fileScopeOK {
		return nil
	}
	return ri.fileScopeByFile
}

// HasFileScope reports whether the file-scope facts were loaded successfully.
func (ri *RepoIndex) HasFileScope() bool { return ri != nil && ri.fileScopeOK }

// FuncPtrTargets returns slot name → target function names, or nil when the
// facts were not loaded. Callers must not mutate the slices.
func (ri *RepoIndex) FuncPtrTargets() map[string][]string {
	if ri == nil || !ri.funcPtrOK {
		return nil
	}
	return ri.slotTargets
}

// HasFuncPtrTargets reports whether the function-pointer facts were loaded.
func (ri *RepoIndex) HasFuncPtrTargets() bool { return ri != nil && ri.funcPtrOK }

// FileOrder returns the IDs of files that contain at least one indexed
// function, in ascending order. Iterating this and calling FuncsByFile
// reproduces the old forEachFile visitation order.
func (ri *RepoIndex) FileOrder() []int64 { return ri.fileOrder }
