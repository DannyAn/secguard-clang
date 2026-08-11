package graph

import (
	"context"
	"fmt"

	"github.com/DannyAn/secguard-clang/internal/db"
)

func IsReachable(ctx context.Context, store db.Store, entryNodeID, targetNodeID int64, edgeType string) (bool, error) {
	reachable, err := store.ReachableFromEntry(ctx, entryNodeID, edgeType)
	if err != nil {
		return false, fmt.Errorf("reachability: %w", err)
	}
	for _, id := range reachable {
		if id == targetNodeID {
			return true, nil
		}
	}
	return false, nil
}

func ReachableSet(ctx context.Context, store db.Store, entryNodeID int64, edgeType string) (map[int64]bool, error) {
	reachable, err := store.ReachableFromEntry(ctx, entryNodeID, edgeType)
	if err != nil {
		return nil, fmt.Errorf("reachable set: %w", err)
	}
	set := make(map[int64]bool, len(reachable))
	for _, id := range reachable {
		set[id] = true
	}
	return set, nil
}
