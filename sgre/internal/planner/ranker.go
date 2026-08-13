package planner

import (
	"context"
	"encoding/json"
	"sort"

	"github.com/DannyAn/secguard-clang/internal/apikb"
	"github.com/DannyAn/secguard-clang/internal/db"
)

func confidenceValue(suspicionLevel string) float64 {
	switch suspicionLevel {
	case "confirmed":
		return 1.0
	case "suspected":
		return 0.7
	case "possible":
		return 0.5
	default:
		return 0.5
	}
}

// severityValue is kept as a thin wrapper for the planner's rank tests;
// the canonical severity tiers live in apikb.
func severityValue(apiName string) float64 {
	return apikb.SeverityValue(apiName)
}

func computeQualityScore(c Candidate, apiName string) float64 {
	severity := apikb.SeverityValue(apiName)
	confidence := confidenceValue(c.SuspicionLevel)
	if c.GuardStrength == "weak" {
		confidence *= 0.8
	}
	impactBonus := 0.0
	if apikb.IsHighImpact(apiName) {
		impactBonus = 20
	}
	score := severity*0.60 + confidence*0.25*100 + impactBonus*0.15
	return score
}

func RankCandidates(ctx context.Context, candidates []Candidate, store db.Store) []Candidate {
	if len(candidates) == 0 {
		return candidates
	}

	for i := range candidates {
		apiName := candidates[i].APIName
		if apiName == "" && store != nil && candidates[i].DerefEventID > 0 {
			event, err := store.GetEventByID(ctx, candidates[i].DerefEventID)
			if err == nil && event != nil {
				var props struct {
					Function   string `json:"function"`
					Variable   string `json:"variable"`
					Expression string `json:"expression"`
				}
				json.Unmarshal([]byte(event.Properties), &props)
				apiName = props.Function
				if apiName == "" {
					apiName = props.Variable
				}
			}
		}
		candidates[i].QualityScore = computeQualityScore(candidates[i], apiName)
	}

	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].QualityScore != candidates[j].QualityScore {
			return candidates[i].QualityScore > candidates[j].QualityScore
		}
		if candidates[i].FileID != candidates[j].FileID {
			return candidates[i].FileID < candidates[j].FileID
		}
		return candidates[i].Line < candidates[j].Line
	})

	return candidates
}
