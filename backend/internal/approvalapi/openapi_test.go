package approvalapi

import (
	"context"
	"net/http"
	"sort"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/go-chi/chi/v5"
)

const specPath = "../../../api/openapi/approver.yaml"

// The approval service's routes and api/openapi/approver.yaml must stay in sync.
func TestRoutesMatchOpenAPI(t *testing.T) {
	doc, err := openapi3.NewLoader().LoadFromFile(specPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := doc.Validate(context.Background()); err != nil {
		t.Fatalf("invalid spec: %v", err)
	}
	documented := map[string]bool{}
	for path, item := range doc.Paths.Map() {
		for method := range item.Operations() {
			documented[strings.ToUpper(method)+" "+path] = true
		}
	}
	implemented := map[string]bool{}
	if err := chi.Walk(newEnv(t).h.(chi.Routes), func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		implemented[method+" "+strings.TrimSuffix(route, "/")] = true
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	diff := func(a, b map[string]bool) (out []string) {
		for k := range a {
			if !b[k] {
				out = append(out, k)
			}
		}
		sort.Strings(out)
		return out
	}
	if d := diff(implemented, documented); len(d) > 0 {
		t.Errorf("implemented but not documented: %v", d)
	}
	if d := diff(documented, implemented); len(d) > 0 {
		t.Errorf("documented but not implemented: %v", d)
	}
}
