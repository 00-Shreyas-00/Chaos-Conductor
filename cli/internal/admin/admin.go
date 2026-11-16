// Package admin implements kubechaosctl's commands against a controller-runtime client so they
// can be tested with a fake client.
package admin

import (
	"context"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"

	chaosv1 "github.com/kubechaos/kubechaos/pkg/chaosapi/api/v1alpha1"
)

const (
	operatorNamespace  = chaosv1.ExperimentNamespace
	operatorDeployment = "kubechaos-operator"
	targetBindingName  = "kubechaos-operator-target"
)

// NewClient builds a client with the KubeChaos and core schemes.
func NewClient(cfg *rest.Config) (client.Client, error) {
	s := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(s); err != nil {
		return nil, err
	}
	if err := chaosv1.AddToScheme(s); err != nil {
		return nil, err
	}
	return client.New(cfg, client.Options{Scheme: s})
}

// Run executes one command and returns the process exit code.
func Run(ctx context.Context, c client.Client, args []string, actor string, out, errOut io.Writer) int {
	var err error
	switch args[0] {
	case "status":
		err = status(ctx, c, out)
	case "emergency-stop":
		fs := flag.NewFlagSet("emergency-stop", flag.ContinueOnError)
		fs.SetOutput(errOut)
		reason := fs.String("reason", "", "why the system is being stopped (required)")
		hard := fs.Bool("hard", false, "also scale the operator to 0 and remove its access to target namespaces")
		if fs.Parse(args[1:]) != nil {
			return 2
		}
		if strings.TrimSpace(*reason) == "" || len(*reason) > 512 {
			fmt.Fprintln(errOut, "emergency-stop: --reason is required (max 512 characters)")
			return 2
		}
		err = emergencyStop(ctx, c, *reason, actor, *hard, out)
	case "unlock":
		fs := flag.NewFlagSet("unlock", flag.ContinueOnError)
		fs.SetOutput(errOut)
		yes := fs.Bool("yes", false, "confirm removing every ChaosLock")
		if fs.Parse(args[1:]) != nil {
			return 2
		}
		if !*yes {
			fmt.Fprintln(errOut, "unlock: this re-enables chaos experiments cluster-wide; add --yes to confirm")
			return 2
		}
		err = unlock(ctx, c, out)
	default:
		fmt.Fprintf(errOut, "unknown command %q\n", args[0])
		return 2
	}
	if err != nil {
		fmt.Fprintf(errOut, "error: %v\n", err)
		return 1
	}
	return 0
}

func status(ctx context.Context, c client.Client, out io.Writer) error {
	var locks chaosv1.ChaosLockList
	if err := c.List(ctx, &locks); err != nil {
		return fmt.Errorf("list locks: %w", err)
	}
	if len(locks.Items) == 0 {
		fmt.Fprintln(out, "lock:        none (experiments may run, subject to policy)")
	}
	for _, l := range locks.Items {
		fmt.Fprintf(out, "lock:        ENGAGED %s by %s at %s: %s\n", l.Name, l.Spec.EngagedBy, l.CreationTimestamp.UTC().Format(time.RFC3339), l.Spec.Reason)
	}

	var pol chaosv1.ChaosPolicy
	switch err := c.Get(ctx, types.NamespacedName{Name: chaosv1.PolicyName}, &pol); {
	case apierrors.IsNotFound(err):
		fmt.Fprintln(out, "policy:      none installed (nothing can run)")
	case err != nil:
		return fmt.Errorf("get policy: %w", err)
	default:
		fmt.Fprintf(out, "policy:      environment=%s faults=%v namespaces=%v approval=%s\n",
			pol.Spec.Environment, pol.Spec.AllowedFaults, pol.Spec.AllowedNamespaces, pol.Spec.Approval.Required)
	}

	var dep appsv1.Deployment
	switch err := c.Get(ctx, types.NamespacedName{Namespace: operatorNamespace, Name: operatorDeployment}, &dep); {
	case apierrors.IsNotFound(err):
		fmt.Fprintln(out, "operator:    not installed")
	case err != nil:
		return fmt.Errorf("get operator: %w", err)
	default:
		want := int32(1)
		if dep.Spec.Replicas != nil {
			want = *dep.Spec.Replicas
		}
		fmt.Fprintf(out, "operator:    replicas %d/%d ready\n", dep.Status.ReadyReplicas, want)
	}

	var exps chaosv1.ChaosExperimentList
	if err := c.List(ctx, &exps, client.InNamespace(operatorNamespace)); err != nil {
		return fmt.Errorf("list experiments: %w", err)
	}
	active := 0
	for _, e := range exps.Items {
		switch e.Status.Phase {
		case chaosv1.PhaseRunning, chaosv1.PhasePending, "":
			active++
			fmt.Fprintf(out, "experiment:  %s %s (requested by %s)\n", e.Name, orDash(string(e.Status.Phase)), e.Spec.RequestedBy.Subject)
		}
	}
	fmt.Fprintf(out, "active:      %d experiment(s)\n", active)
	return nil
}

func emergencyStop(ctx context.Context, c client.Client, reason, actor string, hard bool, out io.Writer) error {
	lock := &chaosv1.ChaosLock{
		ObjectMeta: metav1.ObjectMeta{GenerateName: "emergency-stop-"},
		Spec:       chaosv1.ChaosLockSpec{Reason: reason, EngagedBy: actor},
	}
	if err := c.Create(ctx, lock); err != nil {
		return fmt.Errorf("create ChaosLock: %w", err)
	}
	fmt.Fprintf(out, "ChaosLock %s created: new experiments are rejected, running ones are being aborted\n", lock.Name)
	if !hard {
		return nil
	}
	// Hard stop: even if the operator were misbehaving, take away its ability to act.
	var dep appsv1.Deployment
	if err := c.Get(ctx, types.NamespacedName{Namespace: operatorNamespace, Name: operatorDeployment}, &dep); err == nil {
		zero := int32(0)
		patch := client.MergeFrom(dep.DeepCopy())
		dep.Spec.Replicas = &zero
		if err := c.Patch(ctx, &dep, patch); err != nil {
			return fmt.Errorf("scale operator to 0: %w", err)
		}
		fmt.Fprintln(out, "operator scaled to 0 replicas")
	} else if !apierrors.IsNotFound(err) {
		return fmt.Errorf("get operator: %w", err)
	}
	var bindings rbacv1.RoleBindingList
	if err := c.List(ctx, &bindings); err != nil {
		return fmt.Errorf("list rolebindings: %w", err)
	}
	removed := 0
	for i := range bindings.Items {
		b := &bindings.Items[i]
		if b.Name != targetBindingName {
			continue
		}
		if err := c.Delete(ctx, b); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("delete rolebinding %s/%s: %w", b.Namespace, b.Name, err)
		}
		removed++
		fmt.Fprintf(out, "removed operator access to namespace %s\n", b.Namespace)
	}
	fmt.Fprintf(out, "hard stop complete (%d target namespace(s) revoked). Restore with: helm upgrade ... (make operator-deploy) after unlock\n", removed)
	return nil
}

func unlock(ctx context.Context, c client.Client, out io.Writer) error {
	var locks chaosv1.ChaosLockList
	if err := c.List(ctx, &locks); err != nil {
		return fmt.Errorf("list locks: %w", err)
	}
	if len(locks.Items) == 0 {
		fmt.Fprintln(out, "no ChaosLock present")
		return nil
	}
	for i := range locks.Items {
		if err := c.Delete(ctx, &locks.Items[i]); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("delete ChaosLock %s: %w", locks.Items[i].Name, err)
		}
		fmt.Fprintf(out, "deleted ChaosLock %s\n", locks.Items[i].Name)
	}
	fmt.Fprintln(out, "unlocked: experiments may run again, subject to policy. Aborted experiments are not resumed.")
	return nil
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
