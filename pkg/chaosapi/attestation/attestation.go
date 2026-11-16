// Package attestation defines the approval attestation (architecture §15): a compact JWS,
// signed with Ed25519 by the approval service and verified by the operator against public keys
// that cluster administrators put in ChaosPolicy. The control plane can carry an attestation
// but cannot mint one.
package attestation

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	chaosv1 "github.com/kubechaos/kubechaos/pkg/chaosapi/api/v1alpha1"
)

// Issuer is the attestation issuer.
const Issuer = "kubechaos-approver"

// Audience returns the audience for a cluster: an attestation is only valid on its cluster.
func Audience(clusterID string) string { return "kubechaos-operator/" + clusterID }

// Approval is one human approval (step-up authenticated).
type Approval struct {
	Issuer   string `json:"iss"`
	Subject  string `json:"sub"`
	Name     string `json:"name,omitempty"`
	AuthTime int64  `json:"auth_time"`
	At       int64  `json:"at"`
}

// Claims are the attestation claims.
type Claims struct {
	jwt.Claims
	ClusterID     string            `json:"cluster_id"`
	Environment   string            `json:"environment"`
	Namespaces    []string          `json:"namespaces"`
	SpecSHA256    string            `json:"spec_sha256"`
	Requester     chaosv1.Requester `json:"requester"`
	Approvals     []Approval        `json:"approvals"`
	ApproverGroup string            `json:"approver_group"`
}

// SpecSHA256 hashes the experiment spec as approved. `cancel` is excluded (it may legitimately
// change after approval). Both sides use this exact function, so the encoding is identical.
func SpecSHA256(s *chaosv1.ChaosExperimentSpec) string {
	c := s.DeepCopy()
	c.Cancel = false
	b, _ := json.Marshal(c) // struct field order and sorted map keys: deterministic
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// TargetNamespaces returns the distinct namespaces an experiment touches.
func TargetNamespaces(s *chaosv1.ChaosExperimentSpec) []string {
	seen := map[string]bool{}
	var out []string
	add := func(ns string) {
		if !seen[ns] {
			seen[ns] = true
			out = append(out, ns)
		}
	}
	for _, st := range s.Steps {
		if st.Fault != nil {
			add(st.Fault.Target.Namespace)
		}
	}
	for _, c := range s.SuccessCriteria {
		if c.Target != nil {
			add(c.Target.Namespace)
		}
	}
	return out
}

// Sign produces the compact JWS for claims with the given key.
func Sign(priv ed25519.PrivateKey, kid string, c Claims) (string, error) {
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: priv},
		(&jose.SignerOptions{}).WithType("kubechaos-attestation+jwt").WithHeader(jose.HeaderKey("kid"), kid))
	if err != nil {
		return "", err
	}
	return jwt.Signed(signer).Claims(c).Serialize()
}

// Expectations are what the verifier knows independently of the token.
type Expectations struct {
	ClusterID    string
	Environment  string
	Spec         *chaosv1.ChaosExperimentSpec
	MinApprovals int
	MaxAge       time.Duration
	Now          time.Time
}

// Verification errors.
var (
	ErrUntrustedKey = errors.New("attestation signed by an untrusted key")
	ErrInvalid      = errors.New("invalid attestation")
)

// Verify checks signature (against trusted keys only), issuer, audience, time window, cluster,
// environment, spec hash, namespaces and the four-eyes rule. Single-use (jti) is enforced by the
// caller, which must record Claims.ID atomically.
func Verify(token string, trusted []chaosv1.TrustedKey, exp Expectations) (*Claims, error) {
	parsed, err := jwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.EdDSA})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if len(parsed.Headers) != 1 {
		return nil, fmt.Errorf("%w: exactly one signature required", ErrInvalid)
	}
	kid := parsed.Headers[0].KeyID
	var pub ed25519.PublicKey
	for _, k := range trusted {
		if k.KID == kid {
			raw, err := base64.StdEncoding.DecodeString(k.PublicKey)
			if err == nil && len(raw) == ed25519.PublicKeySize {
				pub = ed25519.PublicKey(raw)
			}
		}
	}
	if pub == nil {
		return nil, fmt.Errorf("%w (kid %q)", ErrUntrustedKey, kid)
	}
	var c Claims
	if err := parsed.Claims(pub, &c); err != nil {
		return nil, fmt.Errorf("%w: signature: %v", ErrInvalid, err)
	}
	if err := c.Claims.ValidateWithLeeway(jwt.Expected{
		Issuer: Issuer, AnyAudience: jwt.Audience{Audience(exp.ClusterID)}, Time: exp.Now,
	}, 30*time.Second); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	fail := func(format string, a ...any) (*Claims, error) {
		return nil, fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, a...))
	}
	switch {
	case c.ID == "" || len(c.ID) > 64:
		return fail("missing or oversized jti")
	case c.IssuedAt == nil || c.Expiry == nil:
		return fail("iat and exp are required")
	case exp.MaxAge > 0 && exp.Now.Sub(c.IssuedAt.Time()) > exp.MaxAge:
		return fail("older than the policy's maxAttestationAge (%s)", exp.MaxAge)
	case c.ClusterID != exp.ClusterID:
		return fail("issued for cluster %q", c.ClusterID)
	case c.Environment != exp.Environment:
		return fail("issued for environment %q", c.Environment)
	case c.SpecSHA256 != SpecSHA256(exp.Spec):
		return fail("the experiment spec differs from the approved spec")
	case c.Requester != exp.Spec.RequestedBy:
		return fail("requester differs from the approved request")
	case !sameSet(c.Namespaces, TargetNamespaces(exp.Spec)):
		return fail("namespaces differ from the approved request")
	case c.ApproverGroup == "":
		return fail("approver group missing")
	}
	distinct := map[string]bool{}
	for _, a := range c.Approvals {
		if a.Issuer == c.Requester.Issuer && a.Subject == c.Requester.Subject {
			return fail("the requester cannot approve their own experiment")
		}
		distinct[a.Issuer+"|"+a.Subject] = true
	}
	if len(distinct) < exp.MinApprovals {
		return fail("%d distinct approval(s), policy requires %d", len(distinct), exp.MinApprovals)
	}
	return &c, nil
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	m := map[string]int{}
	for _, x := range a {
		m[x]++
	}
	for _, x := range b {
		if m[x] == 0 {
			return false
		}
		m[x]--
	}
	return true
}
