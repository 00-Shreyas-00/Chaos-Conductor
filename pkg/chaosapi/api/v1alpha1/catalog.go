package v1alpha1

// FaultInfo describes a primitive for the control plane, the approval service and the UI.
type FaultInfo struct {
	Type        FaultType `json:"type"`
	Description string    `json:"description"`
	Risk        RiskLevel `json:"risk"`
	// Parameters documents the typed parameters and their hard API limits.
	Parameters []ParamInfo `json:"parameters"`
	// Permissions the operator needs in an opted-in target namespace.
	Permissions []string `json:"permissions"`
}

// ParamInfo documents one typed parameter.
type ParamInfo struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Min         int64  `json:"min"`
	Max         int64  `json:"max"`
	Default     *int64 `json:"default,omitempty"`
	Description string `json:"description"`
}

func i64(v int64) *int64 { return &v }

// FaultCatalog is the finite set of primitives. Adding a primitive means adding it here, to the
// FaultType enum, to the operator, and to ChaosPolicy.allowedFaults where wanted.
var FaultCatalog = []FaultInfo{
	{
		Type:        FaultPodKill,
		Description: "Deletes up to `count` Ready, controller-managed pods matching the selector, then observes recovery.",
		Risk:        RiskMedium,
		Parameters: []ParamInfo{
			{Name: "count", Type: "integer", Min: 1, Max: MaxPodKillCount, Description: "Pods to delete (policy may cap lower)."},
			{Name: "gracePeriodSeconds", Type: "integer", Min: 0, Max: MaxGracePeriodSecs, Default: i64(30), Description: "Termination grace period (0 = immediate)."},
		},
		Permissions: []string{"pods: get, list, delete"},
	},
}

var riskOrder = map[RiskLevel]int{RiskLow: 1, RiskMedium: 2, RiskHigh: 3, RiskCritical: 4}

// FaultRisk returns the risk level of a fault type; unknown types are Critical (fail closed).
func FaultRisk(t FaultType) RiskLevel {
	for _, f := range FaultCatalog {
		if f.Type == t {
			return f.Risk
		}
	}
	return RiskCritical
}

// SpecRisk is the highest risk of any fault in the spec. Killing more than one pod raises
// PodKill to High.
func SpecRisk(s *ChaosExperimentSpec) RiskLevel {
	max := RiskLow
	for _, st := range s.Steps {
		if st.Fault == nil {
			continue
		}
		r := FaultRisk(st.Fault.Type)
		if st.Fault.Type == FaultPodKill && st.Fault.PodKill != nil && st.Fault.PodKill.Count > 1 && riskOrder[r] < riskOrder[RiskHigh] {
			r = RiskHigh
		}
		if riskOrder[r] > riskOrder[max] {
			max = r
		}
	}
	return max
}

// RiskAtLeast reports whether r >= min.
func RiskAtLeast(r, min RiskLevel) bool { return riskOrder[r] >= riskOrder[min] && riskOrder[min] > 0 }
