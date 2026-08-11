package skills

import (
	"context"
	"fmt"
)

type QueryResult struct {
	Data []byte
}

type Skill interface {
	Name() string
	Description() string
	Query(ctx context.Context) (*QueryResult, error)
}

type Registry struct {
	skills map[string]Skill
}

func NewRegistry() *Registry {
	return &Registry{skills: make(map[string]Skill)}
}

func (r *Registry) Register(s Skill) {
	r.skills[s.Name()] = s
}

func (r *Registry) Get(name string) (Skill, error) {
	s, ok := r.skills[name]
	if !ok {
		return nil, fmt.Errorf("unknown skill %q; available: %v", name, r.List())
	}
	return s, nil
}

func (r *Registry) List() []string {
	names := make([]string, 0, len(r.skills))
	for name := range r.skills {
		names = append(names, name)
	}
	return names
}
