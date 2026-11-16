// Command kubechaosctl is the break-glass administration CLI (architecture §10). It talks
// directly to the Kubernetes API with the administrator's kubeconfig, so it works when the web
// UI, control plane, database or identity provider are unavailable.
//
//	kubechaosctl status
//	kubechaosctl emergency-stop --reason "..." [--hard]
//	kubechaosctl unlock --yes
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/user"
	"time"

	ctrl "sigs.k8s.io/controller-runtime/pkg/client/config"

	"github.com/kubechaos/kubechaos/cli/internal/admin"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, out, errOut io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(errOut, usage)
		return 2
	}
	cfg, err := ctrl.GetConfig()
	if err != nil {
		fmt.Fprintf(errOut, "kubeconfig: %v\n", err)
		return 1
	}
	cfg.UserAgent = "kubechaosctl"
	c, err := admin.NewClient(cfg)
	if err != nil {
		fmt.Fprintf(errOut, "client: %v\n", err)
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	return admin.Run(ctx, c, args, operatorName(), out, errOut)
}

func operatorName() string {
	if u, err := user.Current(); err == nil && u.Username != "" {
		return "kubechaosctl:" + u.Username
	}
	return "kubechaosctl"
}

const usage = `usage:
  kubechaosctl status
  kubechaosctl emergency-stop --reason "<why>" [--hard]
  kubechaosctl unlock --yes`
