package criteria

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	chaosv1 "github.com/kubechaos/kubechaos/pkg/chaosapi/api/v1alpha1"
)

func pod(name string, ready bool) *corev1.Pod {
	s := corev1.ConditionFalse
	if ready {
		s = corev1.ConditionTrue
	}
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "demo", Name: name, Labels: map[string]string{"app": "web"}},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning, Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: s}}},
	}
}

func exp(criteria ...chaosv1.Criterion) *chaosv1.ChaosExperiment {
	rec := int64(4200)
	start := metav1.NewTime(time.Now().Add(-2 * time.Minute))
	return &chaosv1.ChaosExperiment{
		Spec: chaosv1.ChaosExperimentSpec{
			Steps: []chaosv1.Step{{Fault: &chaosv1.FaultStep{Type: chaosv1.FaultPodKill,
				Target: chaosv1.Target{Namespace: "demo", Selector: map[string]chaosv1.LabelValue{"app": "web"}}}}},
			SuccessCriteria: criteria,
		},
		Status: chaosv1.ChaosExperimentStatus{StartedAt: &start, Steps: []chaosv1.StepStatus{
			{Targets: []chaosv1.PodRef{{Name: "x"}}, RecoveryMillis: &rec},
		}},
	}
}

func TestEvaluateKubernetesCriteria(t *testing.T) {
	c := fake.NewClientBuilder().WithObjects(pod("a", true), pod("b", true), pod("c", true), pod("d", false)).Build()
	ev := Evaluator{Reader: c}
	results, score, result := ev.Evaluate(context.Background(), exp(
		chaosv1.Criterion{Metric: chaosv1.MetricAvailableReplicas, Operator: "ge", Value: "3", Weight: 2}, // 3 >= 3 pass
		chaosv1.Criterion{Metric: chaosv1.MetricRecoveryTime, Operator: "lt", Value: "30s", Weight: 1},    // 4.2s < 30s pass
		chaosv1.Criterion{Metric: chaosv1.MetricReadyRatio, Operator: "eq", Value: "100", Weight: 1},      // 75% fail
	))
	if result != "Failed" || score == nil || *score != 75 {
		t.Fatalf("result=%s score=%v results=%+v", result, score, results)
	}
	if !results[0].Passed || results[0].Observed != "3" || !results[1].Passed || results[1].Observed != "4.2s" ||
		results[2].Passed || results[2].Observed != "75.0" {
		t.Fatalf("results %+v", results)
	}
}

func TestEvaluateNoCriteria(t *testing.T) {
	r, s, res := Evaluator{}.Evaluate(context.Background(), exp())
	if r != nil || s != nil || res != "Passed" {
		t.Fatalf("%v %v %s", r, s, res)
	}
}

func TestPrometheusFailsClosedWithoutProvider(t *testing.T) {
	r, s, res := Evaluator{Reader: fake.NewClientBuilder().Build()}.Evaluate(context.Background(),
		exp(chaosv1.Criterion{Metric: chaosv1.MetricHTTPErrorRate, Operator: "lt", Value: "5"}))
	if res != "Failed" || *s != 0 || !strings.Contains(r[0].Message, "not configured") {
		t.Fatalf("%+v %v %s", r, *s, res)
	}
}

func TestBuildQueryOnlyFromTemplates(t *testing.T) {
	target := chaosv1.Target{Namespace: "payments", Selector: map[string]chaosv1.LabelValue{"app": "payment-api"}}
	q, err := BuildQuery(chaosv1.MetricHTTPErrorRate, "istio", target, 2*time.Minute)
	if err != nil || !strings.Contains(q, `destination_workload_namespace="payments"`) || !strings.Contains(q, `destination_app="payment-api"`) || !strings.Contains(q, "[120s]") {
		t.Fatalf("query %q err %v", q, err)
	}
	if q, _ := BuildQuery(chaosv1.MetricHTTPLatencyP99, "otel", target, time.Hour); !strings.Contains(q, "[900s]") {
		t.Fatalf("window must be clamped to 15m: %s", q)
	}
	if q, _ := BuildQuery(chaosv1.MetricHTTPLatencyP99, "otel", target, time.Second); !strings.Contains(q, "[30s]") {
		t.Fatalf("window must be clamped to 30s: %s", q)
	}
	injections := []chaosv1.LabelValue{`x"}) or vector(1) #`, `api",le="`, `a b`, `x{y}`, ``}
	for _, app := range injections {
		bad := chaosv1.Target{Namespace: "payments", Selector: map[string]chaosv1.LabelValue{"app": app}}
		if q, err := BuildQuery(chaosv1.MetricHTTPErrorRate, "istio", bad, time.Minute); err == nil {
			t.Errorf("app %q must be rejected, got query %s", app, q)
		}
	}
	if _, err := BuildQuery(chaosv1.MetricHTTPErrorRate, "custom-family", target, time.Minute); err == nil {
		t.Error("unknown family must be rejected")
	}
	if _, err := BuildQuery(chaosv1.MetricAvailableReplicas, "istio", target, time.Minute); err == nil {
		t.Error("non-Prometheus metric must be rejected")
	}
}

func TestQueryScalar(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.Query().Get("query")
		switch {
		case strings.Contains(gotQuery, "empty"):
			fmt.Fprint(w, `{"status":"success","data":{"resultType":"vector","result":[]}}`)
		case strings.Contains(gotQuery, "nan"):
			fmt.Fprint(w, `{"status":"success","data":{"resultType":"vector","result":[{"value":[1,"NaN"]}]}}`)
		case strings.Contains(gotQuery, "err"):
			fmt.Fprint(w, `{"status":"error","error":"bad_data"}`)
		default:
			fmt.Fprint(w, `{"status":"success","data":{"resultType":"vector","result":[{"value":[1,"2.5"]}]}}`)
		}
	}))
	defer srv.Close()
	v, err := QueryScalar(context.Background(), srv.Client(), srv.URL, "ok", time.Now())
	if err != nil || v != 2.5 {
		t.Fatalf("v=%v err=%v", v, err)
	}
	for _, q := range []string{"empty", "nan", "err"} {
		if _, err := QueryScalar(context.Background(), srv.Client(), srv.URL, q, time.Now()); err == nil {
			t.Errorf("%s must fail", q)
		}
	}
	if _, err := QueryScalar(context.Background(), srv.Client(), "file:///etc/passwd", "ok", time.Now()); err == nil {
		t.Error("non-http URL must be rejected")
	}
}

func TestPrometheusCriterionEndToEnd(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"status":"success","data":{"resultType":"vector","result":[{"value":[1,"1.25"]}]}}`)
	}))
	defer srv.Close()
	ev := Evaluator{Reader: fake.NewClientBuilder().Build(), HTTP: srv.Client(),
		Prometheus: &chaosv1.PrometheusProvider{URL: srv.URL, MetricFamily: "istio"}}
	r, s, res := ev.Evaluate(context.Background(), exp(chaosv1.Criterion{Metric: chaosv1.MetricHTTPErrorRate, Operator: "lt", Value: "5"}))
	if res != "Passed" || *s != 100 || r[0].Observed != "1.25" {
		t.Fatalf("%+v %v %s", r, *s, res)
	}
}
