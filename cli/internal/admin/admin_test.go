package admin

import (
	"bytes"
	"context"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	chaosv1 "github.com/kubechaos/kubechaos/pkg/chaosapi/api/v1alpha1"
)

func fixture(objs ...client.Object) client.Client {
	s := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(s)
	_ = chaosv1.AddToScheme(s)
	one := int32(1)
	base := []client.Object{
		&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: operatorNamespace, Name: operatorDeployment}, Spec: appsv1.DeploymentSpec{Replicas: &one}},
		&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Namespace: "demo", Name: targetBindingName}},
		&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Namespace: "demo", Name: "unrelated"}},
	}
	return fake.NewClientBuilder().WithScheme(s).WithObjects(append(base, objs...)...).Build()
}

func run(c client.Client, args ...string) (int, string, string) {
	var out, errOut bytes.Buffer
	code := Run(context.Background(), c, args, "kubechaosctl:test", &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestEmergencyStopSoft(t *testing.T) {
	c := fixture()
	code, out, _ := run(c, "emergency-stop", "--reason", "incident 42")
	if code != 0 || !strings.Contains(out, "ChaosLock") {
		t.Fatalf("code=%d out=%s", code, out)
	}
	var locks chaosv1.ChaosLockList
	_ = c.List(context.Background(), &locks)
	if len(locks.Items) != 1 || locks.Items[0].Spec.Reason != "incident 42" || locks.Items[0].Spec.EngagedBy != "kubechaosctl:test" {
		t.Fatalf("locks %+v", locks.Items)
	}
	var dep appsv1.Deployment
	_ = c.Get(context.Background(), types.NamespacedName{Namespace: operatorNamespace, Name: operatorDeployment}, &dep)
	if *dep.Spec.Replicas != 1 {
		t.Fatal("soft stop must not scale the operator")
	}
}

func TestEmergencyStopHard(t *testing.T) {
	c := fixture()
	code, out, _ := run(c, "emergency-stop", "--reason", "runaway", "--hard")
	if code != 0 || !strings.Contains(out, "scaled to 0") || !strings.Contains(out, "namespace demo") {
		t.Fatalf("code=%d out=%s", code, out)
	}
	var dep appsv1.Deployment
	_ = c.Get(context.Background(), types.NamespacedName{Namespace: operatorNamespace, Name: operatorDeployment}, &dep)
	if *dep.Spec.Replicas != 0 {
		t.Fatal("hard stop must scale the operator to 0")
	}
	var rb rbacv1.RoleBindingList
	_ = c.List(context.Background(), &rb)
	if len(rb.Items) != 1 || rb.Items[0].Name != "unrelated" {
		t.Fatalf("only the operator's target bindings may be removed: %+v", rb.Items)
	}
}

func TestEmergencyStopRequiresReason(t *testing.T) {
	for _, args := range [][]string{{"emergency-stop"}, {"emergency-stop", "--reason", "   "}, {"emergency-stop", "--reason", strings.Repeat("x", 600)}} {
		if code, _, _ := run(fixture(), args...); code != 2 {
			t.Errorf("%v: code=%d, want 2", args, code)
		}
	}
}

func TestUnlock(t *testing.T) {
	lock := &chaosv1.ChaosLock{ObjectMeta: metav1.ObjectMeta{Name: "l1"}, Spec: chaosv1.ChaosLockSpec{Reason: "x", EngagedBy: "y"}}
	c := fixture(lock)
	if code, _, errOut := run(c, "unlock"); code != 2 || !strings.Contains(errOut, "--yes") {
		t.Fatalf("unlock without --yes must refuse: %d %s", code, errOut)
	}
	if code, out, _ := run(c, "unlock", "--yes"); code != 0 || !strings.Contains(out, "deleted ChaosLock l1") {
		t.Fatalf("code=%d out=%s", code, out)
	}
	var locks chaosv1.ChaosLockList
	_ = c.List(context.Background(), &locks)
	if len(locks.Items) != 0 {
		t.Fatal("locks remain")
	}
}

func TestStatus(t *testing.T) {
	pol := &chaosv1.ChaosPolicy{ObjectMeta: metav1.ObjectMeta{Name: "default"}, Spec: chaosv1.ChaosPolicySpec{Environment: "development", Approval: chaosv1.ApprovalPolicy{Required: "Never"}}}
	lock := &chaosv1.ChaosLock{ObjectMeta: metav1.ObjectMeta{Name: "l1"}, Spec: chaosv1.ChaosLockSpec{Reason: "incident", EngagedBy: "carol"}}
	code, out, _ := run(fixture(pol, lock), "status")
	for _, want := range []string{"ENGAGED l1 by carol", "environment=development", "operator:    replicas", "active:      0"} {
		if code != 0 || !strings.Contains(out, want) {
			t.Errorf("status output missing %q:\n%s", want, out)
		}
	}
	if code, out, _ := run(fixture(), "status"); code != 0 || !strings.Contains(out, "none installed") || !strings.Contains(out, "lock:        none") {
		t.Errorf("status without policy/lock:\n%s", out)
	}
}

func TestUnknownCommand(t *testing.T) {
	if code, _, _ := run(fixture(), "delete-everything"); code != 2 {
		t.Fatal("unknown commands must fail")
	}
}
