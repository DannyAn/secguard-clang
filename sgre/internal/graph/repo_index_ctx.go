package graph

import "context"

// repoIndexKey is the context key under which the pipeline injects the per-scan
// *RepoIndex so graph builders and detectors read functions/files from one
// shared snapshot instead of each re-querying the DB.
type repoIndexKey struct{}

// WithRepoIndex attaches ri to ctx. Passing nil ri returns ctx unchanged.
func WithRepoIndex(ctx context.Context, ri *RepoIndex) context.Context {
	if ri == nil {
		return ctx
	}
	return context.WithValue(ctx, repoIndexKey{}, ri)
}

// RepoIndexFromCtx returns the index attached by WithRepoIndex, or nil.
func RepoIndexFromCtx(ctx context.Context) *RepoIndex {
	if ctx == nil {
		return nil
	}
	ri, _ := ctx.Value(repoIndexKey{}).(*RepoIndex)
	return ri
}
