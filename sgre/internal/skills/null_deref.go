package skills

import (
	"github.com/kongan/secguard-lite/internal/db"
	"github.com/kongan/secguard-lite/internal/log"
	"github.com/kongan/secguard-lite/internal/planner"
)

type NullDerefSkill struct {
	planner *planner.Planner
}

func NewNullDerefSkill(store db.Store, logger *log.Logger) *NullDerefSkill {
	return &NullDerefSkill{planner: planner.NewPlanner(store, nil, logger)}
}
