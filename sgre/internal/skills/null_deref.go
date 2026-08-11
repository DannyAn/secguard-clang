package skills

import (
	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/planner"
)

type NullDerefSkill struct {
	planner *planner.Planner
}

func NewNullDerefSkill(store db.Store, logger *log.Logger) *NullDerefSkill {
	return &NullDerefSkill{planner: planner.NewPlanner(store, nil, logger)}
}
