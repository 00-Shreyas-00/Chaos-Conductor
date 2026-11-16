package attestation

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"

	chaosv1 "github.com/kubechaos/kubechaos/pkg/chaosapi/api/v1alpha1"
)

var now = time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)

func spec() *chaosv1.ChaosExperimentSpec {
	return &chaosv1.ChaosExperimentSpec{
		ClusterID: "prod-01", RequestedBy: chaosv1.Requester{Issuer: "https://idp", Subject: "alice"}, MaxDuration: "2m",
		Steps: []chaosv1.Step{{Fault: &chaosv1.FaultStep{Type: chaosv1.FaultPodKill,
			Target:  chaosv1.Target{Namespace: "payments", Selector: map[string]chaosv1.LabelValue{"app": "api"}},
			PodKill: &chaosv1.PodKillParams{Count: 1}}}},
	}
}

func keypair(t *testing.T) (ed25519.PrivateKey, chaosv1.TrustedKey) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv, chaosv1.TrustedKey{KID: "approver-1", PublicKey: base64.StdEncoding.EncodeToString(pub)}
}

func claims(s *chaosv1.ChaosExperimentSpec) Claims {
	return Claims{
		Claims: jwt.Claims{Issuer: Issuer, Audience: jwt.Audience{Audience("prod-01")}, ID: "jti-1",
			IssuedAt: jwt.NewNumericDate(now.Add(-time.Minute)), NotBefore: jwt.NewNumericDate(now.Add(-time.Minute)),
			Expiry: jwt.NewNumericDate(now.Add(time.Hour))},
		ClusterID: "prod-01", Environment: "production", Namespaces: []string{"payments"},
		SpecSHA256: SpecSHA256(s), Requester: s.RequestedBy, ApproverGroup: "/teams/payments/head-developers",
		Approvals: []Approval{{Issuer: "https://idp", Subject: "bob", AuthTime: now.Unix(), At: now.Unix()}},
	}
}

func expect(s *chaosv1.ChaosExperimentSpec) Expectations {
	return Expectations{ClusterID: "prod-01", Environment: "production", Spec: s, MinApprovals: 1, MaxAge: time.Hour, Now: now}
}

func TestVerifyValid(t *testing.T) {
	priv, key := keypair(t)
	s := spec()
	tok, err := Sign(priv, key.KID, claims(s))
	if err != nil {
		t.Fatal(err)
	}
	c, err := Verify(tok, []chaosv1.TrustedKey{key}, expect(s))
	if err != nil || c.ID != "jti-1" {
		t.Fatalf("valid attestation rejected: %v", err)
	}
	// cancel may change after approval
	s.Cancel = true
	if _, err := Verify(tok, []chaosv1.TrustedKey{key}, expect(s)); err != nil {
		t.Fatalf("cancel must not invalidate the attestation: %v", err)
	}
}

func TestVerifyRejects(t *testing.T) {
	priv, key := keypair(t)
	otherPriv, otherKey := keypair(t)
	otherKey.KID = "approver-1" // same kid, different key: signature must fail

	cases := map[string]struct {
		mutateClaims func(*Claims)
		mutateSpec   func(*chaosv1.ChaosExperimentSpec)
		mutateExp    func(*Expectations)
		signer       ed25519.PrivateKey
		trusted      []chaosv1.TrustedKey
		want         string
	}{
		"untrusted kid":         {trusted: []chaosv1.TrustedKey{{KID: "other", PublicKey: key.PublicKey}}, want: "untrusted"},
		"forged with other key": {signer: otherPriv, trusted: []chaosv1.TrustedKey{key}, want: "signature"},
		"key swap in policy":    {trusted: []chaosv1.TrustedKey{otherKey}, want: "signature"},
		"spec changed":          {mutateSpec: func(s *chaosv1.ChaosExperimentSpec) { s.Steps[0].Fault.PodKill.Count = 10 }, want: "differs from the approved spec"},
		"namespace swapped":     {mutateSpec: func(s *chaosv1.ChaosExperimentSpec) { s.Steps[0].Fault.Target.Namespace = "ledger" }, want: "differs"},
		"other cluster":         {mutateExp: func(e *Expectations) { e.ClusterID = "prod-02" }, want: "audience"},
		"other environment":     {mutateExp: func(e *Expectations) { e.Environment = "staging" }, want: "environment"},
		"expired":               {mutateExp: func(e *Expectations) { e.Now = now.Add(2 * time.Hour) }, want: "expired"},
		"too old for policy":    {mutateExp: func(e *Expectations) { e.MaxAge = 30 * time.Second }, want: "maxAttestationAge"},
		"self approval":         {mutateClaims: func(c *Claims) { c.Approvals[0].Subject = "alice" }, want: "own experiment"},
		"not enough approvers":  {mutateExp: func(e *Expectations) { e.MinApprovals = 2 }, want: "requires 2"},
		"duplicate approver":    {mutateClaims: func(c *Claims) { c.Approvals = append(c.Approvals, c.Approvals[0]) }, mutateExp: func(e *Expectations) { e.MinApprovals = 2 }, want: "requires 2"},
		"wrong issuer":          {mutateClaims: func(c *Claims) { c.Issuer = "control-plane" }, want: "issuer"},
		"missing jti":           {mutateClaims: func(c *Claims) { c.ID = "" }, want: "jti"},
		"missing group":         {mutateClaims: func(c *Claims) { c.ApproverGroup = "" }, want: "approver group"},
		"requester differs":     {mutateClaims: func(c *Claims) { c.Requester.Subject = "mallory" }, want: "requester"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			s := spec()
			c := claims(s)
			if tc.mutateClaims != nil {
				tc.mutateClaims(&c)
			}
			signer := priv
			if tc.signer != nil {
				signer = tc.signer
			}
			tok, err := Sign(signer, "approver-1", c)
			if err != nil {
				t.Fatal(err)
			}
			if tc.mutateSpec != nil {
				tc.mutateSpec(s)
			}
			e := expect(s)
			if tc.mutateExp != nil {
				tc.mutateExp(&e)
			}
			trusted := []chaosv1.TrustedKey{key}
			if tc.trusted != nil {
				trusted = tc.trusted
			}
			_, err = Verify(tok, trusted, e)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want error containing %q, got %v", tc.want, err)
			}
		})
	}
}

func TestVerifyRejectsGarbageAndNone(t *testing.T) {
	_, key := keypair(t)
	for _, tok := range []string{"", "not.a.jwt", "eyJhbGciOiJub25lIn0.eyJpc3MiOiJrdWJlY2hhb3MtYXBwcm92ZXIifQ."} {
		if _, err := Verify(tok, []chaosv1.TrustedKey{key}, expect(spec())); !errors.Is(err, ErrInvalid) {
			t.Errorf("%q: want ErrInvalid, got %v", tok, err)
		}
	}
}
