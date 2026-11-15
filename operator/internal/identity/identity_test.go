package identity

import (
	"context"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestParse(t *testing.T) {
	ok := map[string]string{"clusterID": "dev-kind-01", "environment": "development"}
	id, err := Parse(ok)
	if err != nil || id.ClusterID != "dev-kind-01" || id.Environment != Development {
		t.Fatalf("valid identity rejected: %+v %v", id, err)
	}

	bad := map[string]map[string]string{
		"empty":              {},
		"missing env":        {"clusterID": "c1"},
		"missing id":         {"environment": "production"},
		"uppercase id":       {"clusterID": "Prod", "environment": "production"},
		"leading dash":       {"clusterID": "-c1", "environment": "production"},
		"too long":           {"clusterID": strings.Repeat("a", 64), "environment": "production"},
		"abbreviated env":    {"clusterID": "c1", "environment": "prod"},
		"capitalised env":    {"clusterID": "c1", "environment": "Production"},
		"unknown key (typo)": {"clusterID": "c1", "environment": "staging", "enviroment": "development"},
		"injection in id":    {"clusterID": "c1;rm -rf", "environment": "staging"},
	}
	for name, data := range bad {
		if _, err := Parse(data); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestLoad(t *testing.T) {
	ns := "kubechaos-system"
	cm := func(data map[string]string, bin map[string][]byte) *corev1.ConfigMap {
		return &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: ConfigMapName},
			Data:       data, BinaryData: bin,
		}
	}
	ctx := context.Background()

	c := fake.NewClientBuilder().WithObjects(cm(map[string]string{"clusterID": "dev-kind-01", "environment": "development"}, nil)).Build()
	if id, err := Load(ctx, c, ns); err != nil || id.ClusterID != "dev-kind-01" {
		t.Fatalf("load: %+v %v", id, err)
	}

	if _, err := Load(ctx, fake.NewClientBuilder().Build(), ns); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("missing ConfigMap must fail closed: %v", err)
	}
	if _, err := Load(ctx, c, "other-namespace"); err == nil {
		t.Fatal("identity from another namespace must not be found")
	}
	bin := fake.NewClientBuilder().WithObjects(cm(map[string]string{"clusterID": "c1", "environment": "development"},
		map[string][]byte{"x": {1}})).Build()
	if _, err := Load(ctx, bin, ns); err == nil {
		t.Fatal("binaryData must be rejected")
	}
}
