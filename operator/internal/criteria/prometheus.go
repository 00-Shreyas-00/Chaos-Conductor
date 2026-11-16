package criteria

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"time"

	chaosv1 "github.com/kubechaos/kubechaos/pkg/chaosapi/api/v1alpha1"
)

// PromQL is built ONLY here, from compiled-in templates. No API, CRD or UI field carries a
// query string (D14). Template parameters come from the resolved target (namespace and the
// selector's "app" label), are checked against a strict character set, and are placed inside
// double-quoted PromQL string literals; the window is a bounded integer.

var safeLabelValue = regexp.MustCompile(`^[a-zA-Z0-9_.:/-]{1,253}$`)

const (
	minWindow = 30 * time.Second
	maxWindow = 15 * time.Minute
)

type familyTemplates struct {
	errorRate string // args: ns, app, window  -> percent of 5xx
	p99       string // args: ns, app, window  -> seconds
}

var templates = map[string]familyTemplates{
	"istio": {
		errorRate: `100 * sum(rate(istio_requests_total{reporter="destination",destination_workload_namespace=%[1]q,destination_app=%[2]q,response_code=~"5.."}[%[3]s])) / sum(rate(istio_requests_total{reporter="destination",destination_workload_namespace=%[1]q,destination_app=%[2]q}[%[3]s]))`,
		p99:       `histogram_quantile(0.99, sum by (le) (rate(istio_request_duration_milliseconds_bucket{reporter="destination",destination_workload_namespace=%[1]q,destination_app=%[2]q}[%[3]s]))) / 1000`,
	},
	"ingress-nginx": {
		errorRate: `100 * sum(rate(nginx_ingress_controller_requests{exported_namespace=%[1]q,exported_service=%[2]q,status=~"5.."}[%[3]s])) / sum(rate(nginx_ingress_controller_requests{exported_namespace=%[1]q,exported_service=%[2]q}[%[3]s]))`,
		p99:       `histogram_quantile(0.99, sum by (le) (rate(nginx_ingress_controller_request_duration_seconds_bucket{exported_namespace=%[1]q,exported_service=%[2]q}[%[3]s])))`,
	},
	"otel": {
		errorRate: `100 * sum(rate(http_server_request_duration_seconds_count{k8s_namespace_name=%[1]q,service_name=%[2]q,http_response_status_code=~"5.."}[%[3]s])) / sum(rate(http_server_request_duration_seconds_count{k8s_namespace_name=%[1]q,service_name=%[2]q}[%[3]s]))`,
		p99:       `histogram_quantile(0.99, sum by (le) (rate(http_server_request_duration_seconds_bucket{k8s_namespace_name=%[1]q,service_name=%[2]q}[%[3]s])))`,
	},
}

// BuildQuery renders the template for metric/family. HTTP metrics require the target selector
// to include an "app" label identifying the service.
func BuildQuery(metric chaosv1.MetricName, family string, t chaosv1.Target, window time.Duration) (string, error) {
	tpl, ok := templates[family]
	if !ok {
		return "", fmt.Errorf("unknown metric family %q", family)
	}
	app := string(t.Selector["app"])
	for _, v := range []string{t.Namespace, app} {
		if !safeLabelValue.MatchString(v) {
			return "", fmt.Errorf("target needs a namespace and an 'app' selector label made of [a-zA-Z0-9_.:/-] for HTTP metrics")
		}
	}
	if window < minWindow {
		window = minWindow
	}
	if window > maxWindow {
		window = maxWindow
	}
	w := strconv.Itoa(int(window.Seconds())) + "s"
	switch metric {
	case chaosv1.MetricHTTPErrorRate:
		return fmt.Sprintf(tpl.errorRate, t.Namespace, app, w), nil
	case chaosv1.MetricHTTPLatencyP99:
		return fmt.Sprintf(tpl.p99, t.Namespace, app, w), nil
	}
	return "", fmt.Errorf("metric %q is not a Prometheus metric", metric)
}

// QueryScalar runs an instant query and returns the single sample value. Empty results, NaN
// and errors are failures (a criterion that cannot be measured does not pass).
func QueryScalar(ctx context.Context, hc *http.Client, base, query string, at time.Time) (float64, error) {
	u, err := url.Parse(base)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return 0, fmt.Errorf("invalid Prometheus URL")
	}
	u = u.JoinPath("/api/v1/query")
	q := url.Values{"query": {query}, "time": {strconv.FormatInt(at.Unix(), 10)}, "timeout": {"5s"}}
	ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), nil)
	if err != nil {
		return 0, err
	}
	req.URL.RawQuery = q.Encode()
	resp, err := hc.Do(req)
	if err != nil {
		return 0, fmt.Errorf("prometheus query failed: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return 0, err
	}
	var r struct {
		Status string `json:"status"`
		Error  string `json:"error"`
		Data   struct {
			ResultType string `json:"resultType"`
			Result     []struct {
				Value [2]any `json:"value"`
			} `json:"result"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return 0, fmt.Errorf("prometheus: unparseable response (HTTP %d)", resp.StatusCode)
	}
	if r.Status != "success" {
		return 0, fmt.Errorf("prometheus: %s", truncate(r.Error, 128))
	}
	if r.Data.ResultType != "vector" || len(r.Data.Result) != 1 {
		return 0, fmt.Errorf("prometheus: expected exactly one sample, got %d", len(r.Data.Result))
	}
	s, ok := r.Data.Result[0].Value[1].(string)
	if !ok {
		return 0, fmt.Errorf("prometheus: malformed sample")
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil || v != v { // NaN (e.g. 0/0) is "no data"
		return 0, fmt.Errorf("prometheus: no data for this window")
	}
	return v, nil
}
