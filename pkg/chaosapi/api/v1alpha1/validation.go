package v1alpha1

import (
	"fmt"
	"regexp"
	"slices"
	"time"

	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

// ValidateSpec re-checks, in Go, every constraint the CRD schema enforces, plus the ones a
// schema cannot express cheaply (e.g. total wait time must fit in maxDuration). The operator
// runs it before acting, so a loosened or outdated CRD schema cannot widen what executes
// (defence in depth; fail closed on anything unexpected).
func ValidateSpec(s *ChaosExperimentSpec) field.ErrorList {
	var errs field.ErrorList
	root := field.NewPath("spec")

	for _, msg := range validation.IsDNS1123Label(s.ClusterID) {
		errs = append(errs, field.Invalid(root.Child("clusterID"), s.ClusterID, msg))
	}
	if n := len(s.RequestedBy.Issuer); n < 1 || n > 512 {
		errs = append(errs, field.Invalid(root.Child("requestedBy", "issuer"), n, "must be 1-512 characters"))
	}
	if n := len(s.RequestedBy.Subject); n < 1 || n > 255 {
		errs = append(errs, field.Invalid(root.Child("requestedBy", "subject"), n, "must be 1-255 characters"))
	}

	maxDur, err := boundedDuration(s.MaxDuration, MinMaxDuration, MaxMaxDuration)
	if err != nil {
		errs = append(errs, field.Invalid(root.Child("maxDuration"), s.MaxDuration, err.Error()))
	}

	steps := root.Child("steps")
	switch {
	case len(s.Steps) == 0:
		errs = append(errs, field.Required(steps, "at least one step is required"))
	case len(s.Steps) > MaxSteps:
		errs = append(errs, field.TooMany(steps, len(s.Steps), MaxSteps))
	}

	var totalWait time.Duration
	faults := 0
	for i, st := range s.Steps {
		p := steps.Index(i)
		switch {
		case (st.Fault == nil) == (st.Wait == nil):
			errs = append(errs, field.Invalid(p, "", "each step must set exactly one of fault or wait"))
		case st.Wait != nil:
			d, err := boundedDuration(st.Wait.Duration, MinWait, MaxWait)
			if err != nil {
				errs = append(errs, field.Invalid(p.Child("wait", "duration"), st.Wait.Duration, err.Error()))
			}
			totalWait += d
		default:
			faults++
			errs = append(errs, validateFault(st.Fault, p.Child("fault"))...)
		}
	}
	crit := root.Child("successCriteria")
	if len(s.SuccessCriteria) > 10 {
		errs = append(errs, field.TooMany(crit, len(s.SuccessCriteria), 10))
	}
	for i, c := range s.SuccessCriteria {
		errs = append(errs, validateCriterion(c, crit.Index(i))...)
	}
	if len(s.Steps) > 0 && faults == 0 {
		errs = append(errs, field.Invalid(steps, len(s.Steps), "an experiment must contain at least one fault"))
	}
	if maxDur > 0 && totalWait >= maxDur {
		errs = append(errs, field.Invalid(root.Child("maxDuration"), s.MaxDuration,
			fmt.Sprintf("must exceed the total wait time of all steps (%s)", totalWait)))
	}
	return errs
}

var labelValueRe = regexp.MustCompile(`^([A-Za-z0-9]([-A-Za-z0-9_.]{0,61}[A-Za-z0-9])?)?$`)

func validateFault(f *FaultStep, p *field.Path) field.ErrorList {
	var errs field.ErrorList
	t := f.Target
	for _, msg := range validation.IsDNS1123Label(t.Namespace) {
		errs = append(errs, field.Invalid(p.Child("target", "namespace"), t.Namespace, msg))
	}
	if slices.Contains(ProtectedNamespaces, t.Namespace) {
		errs = append(errs, field.Forbidden(p.Child("target", "namespace"), "namespace "+t.Namespace+" is protected"))
	}
	sel := p.Child("target", "selector")
	if len(t.Selector) == 0 {
		errs = append(errs, field.Required(sel, "an empty selector would match every pod"))
	}
	if len(t.Selector) > 10 {
		errs = append(errs, field.TooMany(sel, len(t.Selector), 10))
	}
	for k, v := range t.Selector {
		for _, msg := range validation.IsQualifiedName(k) {
			errs = append(errs, field.Invalid(sel.Key(k), k, msg))
		}
		if len(v) > 63 || !labelValueRe.MatchString(string(v)) {
			errs = append(errs, field.Invalid(sel.Key(k), v, "invalid label value"))
		}
	}

	switch f.Type {
	case FaultPodKill:
		pk := f.PodKill
		if pk == nil {
			errs = append(errs, field.Required(p.Child("podKill"), "required for type PodKill"))
			break
		}
		if pk.Count < 1 || pk.Count > MaxPodKillCount {
			errs = append(errs, field.Invalid(p.Child("podKill", "count"), pk.Count, fmt.Sprintf("must be 1-%d", MaxPodKillCount)))
		}
		if g := pk.GracePeriodSeconds; g != nil && (*g < 0 || *g > MaxGracePeriodSecs) {
			errs = append(errs, field.Invalid(p.Child("podKill", "gracePeriodSeconds"), *g, fmt.Sprintf("must be 0-%d", MaxGracePeriodSecs)))
		}
	default:
		// Unknown fault type => reject (fail closed), even if the schema were to allow it.
		errs = append(errs, field.NotSupported(p.Child("type"), f.Type, []FaultType{FaultPodKill}))
	}
	return errs
}

var (
	numberRe       = regexp.MustCompile(`^[0-9]{1,6}(\.[0-9]{1,3})?$`)
	shortDurRe     = regexp.MustCompile(`^([0-9]{1,4}(ms|s|m)){1,3}$`)
	validOperators = []ComparisonOperator{"lt", "le", "gt", "ge", "eq"}
)

// CriterionValue parses a criterion value: durations in seconds for time metrics, numbers
// otherwise. It is used by validation and by the evaluator.
func CriterionValue(c Criterion) (float64, error) {
	switch c.Metric {
	case MetricRecoveryTime, MetricHTTPLatencyP99:
		if !shortDurRe.MatchString(c.Value) {
			return 0, fmt.Errorf("must be a duration such as 500ms or 30s")
		}
		d, err := time.ParseDuration(c.Value)
		if err != nil || d > time.Hour {
			return 0, fmt.Errorf("must be a duration up to 1h")
		}
		return d.Seconds(), nil
	default:
		if !numberRe.MatchString(c.Value) {
			return 0, fmt.Errorf("must be a number")
		}
		var f float64
		if _, err := fmt.Sscanf(c.Value, "%g", &f); err != nil {
			return 0, fmt.Errorf("must be a number")
		}
		if (c.Metric == MetricReadyRatio || c.Metric == MetricHTTPErrorRate) && f > 100 {
			return 0, fmt.Errorf("is a percentage (0-100)")
		}
		return f, nil
	}
}

func validateCriterion(c Criterion, p *field.Path) field.ErrorList {
	var errs field.ErrorList
	switch c.Metric {
	case MetricAvailableReplicas, MetricReadyRatio, MetricRecoveryTime, MetricHTTPErrorRate, MetricHTTPLatencyP99:
	default:
		errs = append(errs, field.NotSupported(p.Child("metric"), c.Metric, []MetricName{
			MetricAvailableReplicas, MetricReadyRatio, MetricRecoveryTime, MetricHTTPErrorRate, MetricHTTPLatencyP99}))
	}
	if !slices.Contains(validOperators, c.Operator) {
		errs = append(errs, field.NotSupported(p.Child("operator"), c.Operator, validOperators))
	}
	if _, err := CriterionValue(c); err != nil {
		errs = append(errs, field.Invalid(p.Child("value"), c.Value, err.Error()))
	}
	if c.Weight < 0 || c.Weight > 100 {
		errs = append(errs, field.Invalid(p.Child("weight"), c.Weight, "must be 1-100"))
	}
	if c.Target != nil {
		// Same rules as fault targets.
		errs = append(errs, validateFault(&FaultStep{Type: FaultPodKill, Target: *c.Target, PodKill: &PodKillParams{Count: 1}}, p)...)
	}
	return errs
}

var durationRe = regexp.MustCompile(`^([0-9]{1,4}(s|m|h)){1,3}$`)

func boundedDuration(s, minS, maxS string) (time.Duration, error) {
	if !durationRe.MatchString(s) {
		return 0, fmt.Errorf("must be a duration like 30s, 5m or 1h30m")
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("invalid duration")
	}
	lo, _ := time.ParseDuration(minS)
	hi, _ := time.ParseDuration(maxS)
	if d < lo || d > hi {
		return 0, fmt.Errorf("must be between %s and %s", minS, maxS)
	}
	return d, nil
}
