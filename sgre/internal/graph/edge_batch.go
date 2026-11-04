package graph

import (
	"context"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/log"
)

// edgeBatchWriter buffers graph edges and flushes them in one transaction,
// replacing the per-edge autocommit pattern (one write-lock + fsync per edge)
// with one transaction per batch. Each graph builder holds one and calls add
// for every edge, then flush once at the end of Build.
//
// The writer is NOT concurrency-safe; each builder runs in its own goroutine
// and owns its own instance.
type edgeBatchWriter struct {
	store    db.Store
	logger   *log.Logger
	edges    []db.GraphEdge
	maxBatch int
	flushed  int
}

// newEdgeBatchWriter creates a writer that flushes every maxBatch edges (and
// on the final flush call). maxBatch caps peak memory; 500 is a reasonable
// default that keeps the transaction short while cutting ~99% of fsyncs.
func newEdgeBatchWriter(store db.Store, logger *log.Logger, maxBatch int) *edgeBatchWriter {
	if maxBatch <= 0 {
		maxBatch = 500
	}
	return &edgeBatchWriter{store: store, logger: logger, maxBatch: maxBatch}
}

// add buffers an edge. If the buffer reaches maxBatch, it auto-flushes; an
// auto-flush error is logged (best-effort, same as the old per-edge error
// handling) and the buffer is cleared so the next add does not pile onto a
// failed transaction.
func (w *edgeBatchWriter) add(ctx context.Context, srcID, dstID int64, edgeType, properties string) {
	w.edges = append(w.edges, db.GraphEdge{
		SrcID:      srcID,
		DstID:      dstID,
		EdgeType:   edgeType,
		Properties: properties,
	})
	if len(w.edges) >= w.maxBatch {
		w.flush(ctx)
	}
}

// flush writes all buffered edges in one transaction and clears the buffer.
// On a batch failure it falls back to per-edge writes: the old semantics were
// per-edge best-effort, and dropping an entire 500-edge batch because one edge
// failed would silently remove graph facts the filters consume (lock-order /
// shared-access). Returns the number of edges actually written.
func (w *edgeBatchWriter) flush(ctx context.Context) int {
	if len(w.edges) == 0 {
		return 0
	}
	n, err := w.store.InsertGraphEdgeBatch(ctx, w.edges)
	if err != nil {
		if w.logger != nil {
			w.logger.Warn("graph: edge batch flush failed, retrying per edge", "buffered", len(w.edges), "error", err)
		}
		n = 0
		for i := range w.edges {
			if _, eerr := w.store.InsertGraphEdge(ctx, &w.edges[i]); eerr != nil {
				if w.logger != nil {
					w.logger.Warn("graph: edge insert failed", "edge_type", w.edges[i].EdgeType, "error", eerr)
				}
				continue
			}
			n++
		}
	}
	w.edges = w.edges[:0]
	w.flushed += n
	return n
}

// total returns the cumulative number of edges successfully written across all
// flushes.
func (w *edgeBatchWriter) total() int { return w.flushed }
