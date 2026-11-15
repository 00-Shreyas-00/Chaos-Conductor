// Command manager runs the KubeChaos operator: the only component that acts on Kubernetes
// workloads. At this foundation stage it establishes identity, leader election and health;
// controllers for ChaosExperiment/ChaosPolicy/ChaosLock are added in later steps.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"regexp"
	"sync/atomic"
	"time"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/kubechaos/kubechaos/operator/internal/identity"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

const leaderElectionID = "kubechaos-operator.chaos.kubechaos.io"

var namespaceRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

func main() {
	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})
	log := logr.FromSlogHandler(handler).WithValues("service", "kubechaos-operator", "version", version)
	ctrl.SetLogger(log)
	if err := run(ctrl.SetupSignalHandler(), log); err != nil {
		log.Error(err, "fatal")
		os.Exit(1)
	}
}

func run(ctx context.Context, log logr.Logger) error {
	// Own namespace from the downward API; never guessed or defaulted (fail closed).
	ns := os.Getenv("KUBECHAOS_OPERATOR_NAMESPACE")
	if !namespaceRe.MatchString(ns) {
		return fmt.Errorf("KUBECHAOS_OPERATOR_NAMESPACE %q is missing or invalid", ns)
	}

	cfg, err := ctrl.GetConfig()
	if err != nil {
		return fmt.Errorf("kubernetes config: %w", err)
	}
	cfg.UserAgent = "kubechaos-operator/" + version

	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		return err
	}

	var identityLoaded atomic.Bool
	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme: scheme,
		// The cache is confined to the operator's own namespace until controllers that need
		// more are added; RBAC grants nothing cluster-wide anyway.
		Cache: cache.Options{DefaultNamespaces: map[string]cache.Config{ns: {}}},
		// Metrics stay off until they can be served authenticated (TokenReview/SAR) in a later step.
		Metrics:                       metricsserver.Options{BindAddress: "0"},
		HealthProbeBindAddress:        ":8081",
		LeaderElection:                true,
		LeaderElectionID:              leaderElectionID,
		LeaderElectionNamespace:       ns,
		LeaderElectionReleaseOnCancel: true,
	})
	if err != nil {
		return fmt.Errorf("create manager: %w", err)
	}

	// Load the cluster identity with a direct, uncached read before anything else runs.
	loadCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	id, err := identity.Load(loadCtx, mgr.GetAPIReader(), ns)
	cancel()
	if err != nil {
		return err // fail closed: no identity, no operator
	}
	identityLoaded.Store(true)
	log.Info("cluster identity loaded", "clusterID", id.ClusterID, "environment", string(id.Environment), "namespace", ns)

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		return err
	}
	if err := mgr.AddReadyzCheck("identity", func(*http.Request) error {
		if !identityLoaded.Load() {
			return errors.New("cluster identity not loaded")
		}
		return nil
	}); err != nil {
		return err
	}

	log.Info("starting manager")
	return mgr.Start(ctx)
}
