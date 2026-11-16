package experiments

import (
	"context"
	"errors"
	"testing"

	"github.com/kubechaos/kubechaos/backend/internal/clusters/clusterstest"
	chaosv1 "github.com/kubechaos/kubechaos/pkg/chaosapi/api/v1alpha1"
)

type fakeApprovals struct {
	inputs []ApprovalInput
	status map[string]ApprovalStatus
	err    error
}

func (f *fakeApprovals) Request(_ context.Context, in ApprovalInput) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	f.inputs = append(f.inputs, in)
	return "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", nil
}

func (f *fakeApprovals) Status(_ context.Context, id string) (ApprovalStatus, error) {
	if f.err != nil {
		return ApprovalStatus{}, f.err
	}
	return f.status[id], nil
}

func approvalSetup() (*Service, *MemStore, *clusterstest.Fake, *fakeApprovals) {
	s, store, conn := setup()
	conn.Pol.Spec.Approval.Required = chaosv1.ApprovalAlways
	fa := &fakeApprovals{status: map[string]ApprovalStatus{}}
	s.Approvals = fa
	return s, store, conn, fa
}

const reqID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"

func TestApprovalRequiredCreatesPendingWithoutCR(t *testing.T) {
	s, store, conn, fa := approvalSetup()
	exp, err := s.Create(context.Background(), alice(), request(1), RequestMeta{})
	if err != nil {
		t.Fatal(err)
	}
	if exp.State != StatePendingApproval || exp.ApprovalRequest != reqID || len(conn.Submitted) != 0 {
		t.Fatalf("exp %+v submitted %d", exp, len(conn.Submitted))
	}
	if len(fa.inputs) != 1 || fa.inputs[0].ExperimentID != exp.ID || fa.inputs[0].Spec.RequestedBy.Subject != "alice" ||
		fa.inputs[0].Environment != conn.Pol.Spec.Environment {
		t.Fatalf("approval input %+v", fa.inputs)
	}
	if store.Audits[0].Result != "pending approval" {
		t.Fatalf("audit %+v", store.Audits[0])
	}

	// Still pending: nothing happens.
	fa.status[reqID] = ApprovalStatus{ID: reqID, State: "Pending"}
	s.PollApprovals(context.Background())
	if len(conn.Submitted) != 0 {
		t.Fatal("pending must not submit")
	}

	// Approved: the CR is created carrying the attestation.
	fa.status[reqID] = ApprovalStatus{ID: reqID, State: "Approved", Attestation: "signed.jws.token"}
	s.PollApprovals(context.Background())
	if len(conn.Submitted) != 1 || conn.Submitted[0].Annotations[chaosv1.AnnotationApproval] != "signed.jws.token" {
		t.Fatalf("approved experiment not submitted with attestation: %+v", conn.Submitted)
	}
	got, _ := store.Get(context.Background(), exp.ID)
	if got.State != StateSubmitted {
		t.Fatalf("state %s", got.State)
	}
	s.PollApprovals(context.Background())
	if len(conn.Submitted) != 1 {
		t.Fatal("must submit exactly once")
	}
}

func TestApprovalRejectedAndExpired(t *testing.T) {
	for remote, want := range map[string]string{"Rejected": StateApprovalRejected, "Expired": StateApprovalExpired} {
		s, store, conn, fa := approvalSetup()
		exp, _ := s.Create(context.Background(), alice(), request(1), RequestMeta{})
		fa.status[reqID] = ApprovalStatus{ID: reqID, State: remote}
		s.PollApprovals(context.Background())
		got, _ := store.Get(context.Background(), exp.ID)
		if got.State != want || len(conn.Submitted) != 0 {
			t.Fatalf("%s: state %s submitted %d", remote, got.State, len(conn.Submitted))
		}
	}
}

func TestApprovalServiceDownFailsClosed(t *testing.T) {
	s, store, conn, fa := approvalSetup()
	fa.err = errors.New("connection refused")
	if _, err := s.Create(context.Background(), alice(), request(1), RequestMeta{}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("got %v", err)
	}
	exps, _ := store.List(context.Background(), 10)
	if len(conn.Submitted) != 0 || len(exps) != 1 || exps[0].State != StateSubmitFailed {
		t.Fatal("an unrequested approval must not leave a runnable experiment")
	}
}

func TestApprovedWithoutAttestationIsIgnored(t *testing.T) {
	s, _, conn, fa := approvalSetup()
	_, _ = s.Create(context.Background(), alice(), request(1), RequestMeta{})
	fa.status[reqID] = ApprovalStatus{ID: reqID, State: "Approved"}
	s.PollApprovals(context.Background())
	if len(conn.Submitted) != 0 {
		t.Fatal("no attestation, no submission")
	}
}
