package controller

import "sigs.k8s.io/controller-runtime/pkg/controller"

// controllerOptions bounds reconciler concurrency (threat model T13: resource exhaustion).
func controllerOptions() controller.Options {
	return controller.Options{MaxConcurrentReconciles: 2}
}
