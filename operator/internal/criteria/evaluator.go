// Package criteria evaluates an experiment's explicit success criteria and derives the
// resilience score. Scores come only from these measurements — never from heuristics.
package criteria

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"time"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	chaosv1 "github.com/kubechaos/kubechaos/pkg/chaosapi/api/v1alpha1"
)

// Evaluator computes criterion results.
type Evaluator struct {
	Reader     client.Reader
	Prometheus *chaosv1.PrometheusProvider // nil: Prometheus metrics fail (fail closed)
	HTTP       *http.Client
	Now        func() time.Time
}

// Evaluate returns the per-criterion results, the weighted score (nil when there are no
// criteria) and the overall result.
func (e Evaluator) Evaluate(ctx context.Context, exp *chaosv1.ChaosExperiment) ([]chaosv1.CriterionResult, *int32, string) {
	if len(exp.Spec.SuccessCriteria) == 0 {
		return nil, nil, "Passed"
	}
	var results []chaosv1.CriterionResult
	var total, passed int32
	for _, c := range exp.Spec.SuccessCriteria {
		w := c.Weight
		if w < 1 {
			w = 1
		}
		res := chaosv1.CriterionResult{Metric: c.Metric, Operator: c.Operator, Expected: c.Value, Weight: w}
		observed, display, err := e.observe(ctx, exp, c)
		expected, verr := chaosv1.CriterionValue(c)
		switch {
		case err != nil:
			res.Message = truncate(err.Error(), 256)
		case verr != nil:
			res.Message = "invalid expected value"
		default:
			res.Observed = display
			res.Passed = Compare(observed, c.Operator, expected)
		}
		total += w
		if res.Passed {
			passed += w
		}
		results = append(results, res)
	}
	score := int32(math.Round(float64(passed) * 100 / float64(total)))
	result := "Passed"
	if passed != total {
		result = "Failed"
	}
	return results, &score, result
}

// Compare applies an operator. Equality uses a small tolerance for float noise.
func Compare(observed float64, op chaosv1.ComparisonOperator, expected float64) bool {
	switch op {
	case "lt":
		return observed < expected
	case "le":
		return observed <= expected
	case "gt":
		return observed > expected
	case "ge":
		return observed >= expected
	case "eq":
		return math.Abs(observed-expected) < 1e-9
	}
	return false // unknown operator: fail closed
}

func (e Evaluator) observe(ctx context.Context, exp *chaosv1.ChaosExperiment, c chaosv1.Criterion) (float64, string, error) {
	target := c.Target
	if target == nil {
		for _, st := range exp.Spec.Steps {
			if st.Fault != nil {
				t := st.Fault.Target
				target = &t
				break
			}
		}
	}
	switch c.Metric {
	case chaosv1.MetricRecoveryTime:
		var worst int64 = -1
		for _, s := range exp.Status.Steps {
			if len(s.Targets) == 0 {
				continue
			}
			if s.RecoveryMillis == nil {
				return 0, "", fmt.Errorf("a fault step has no recorded recovery")
			}
			if *s.RecoveryMillis > worst {
				worst = *s.RecoveryMillis
			}
		}
		if worst < 0 {
			return 0, "", fmt.Errorf("no fault step recorded a recovery")
		}
		return float64(worst) / 1000, (time.Duration(worst) * time.Millisecond).String(), nil

	case chaosv1.MetricAvailableReplicas, chaosv1.MetricReadyRatio:
		if target == nil {
			return 0, "", fmt.Errorf("no target")
		}
		ready, total, err := podCounts(ctx, e.Reader, *target)
		if err != nil {
			return 0, "", err
		}
		if c.Metric == chaosv1.MetricAvailableReplicas {
			return float64(ready), strconv.Itoa(ready), nil
		}
		if total == 0 {
			return 0, "", fmt.Errorf("no pods match the target")
		}
		ratio := float64(ready) * 100 / float64(total)
		return ratio, strconv.FormatFloat(ratio, 'f', 1, 64), nil

	case chaosv1.MetricHTTPErrorRate, chaosv1.MetricHTTPLatencyP99:
		if e.Prometheus == nil {
			return 0, "", fmt.Errorf("the Prometheus provider is not configured in ChaosPolicy")
		}
		if target == nil || exp.Status.StartedAt == nil {
			return 0, "", fmt.Errorf("no target or start time")
		}
		window := e.now().Sub(exp.Status.StartedAt.Time)
		q, err := BuildQuery(c.Metric, e.Prometheus.MetricFamily, *target, window)
		if err != nil {
			return 0, "", err
		}
		v, err := QueryScalar(ctx, e.httpClient(), e.Prometheus.URL, q, e.now())
		if err != nil {
			return 0, "", err
		}
		if c.Metric == chaosv1.MetricHTTPLatencyP99 {
			return v, (time.Duration(v * float64(time.Second))).Round(time.Millisecond).String(), nil
		}
		return v, strconv.FormatFloat(v, 'f', 2, 64), nil
	}
	return 0, "", fmt.Errorf("unsupported metric %q", c.Metric)
}

func podCounts(ctx context.Context, r client.Reader, t chaosv1.Target) (ready, total int, err error) {
	sel := client.MatchingLabels{}
	for k, v := range t.Selector {
		sel[k] = string(v)
	}
	var list corev1.PodList
	if err := r.List(ctx, &list, client.InNamespace(t.Namespace), sel); err != nil {
		return 0, 0, fmt.Errorf("list pods: %w", err)
	}
	for _, p := range list.Items {
		if p.DeletionTimestamp != nil {
			continue
		}
		total++
		for _, c := range p.Status.Conditions {
			if c.Type == corev1.PodReady && c.Status == corev1.ConditionTrue && p.Status.Phase == corev1.PodRunning {
				ready++
			}
		}
	}
	return ready, total, nil
}

func (e Evaluator) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

func (e Evaluator) httpClient() *http.Client {
	if e.HTTP != nil {
		return e.HTTP
	}
	return &http.Client{Timeout: 5 * time.Second}
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
