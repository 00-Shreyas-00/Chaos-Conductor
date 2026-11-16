package approval

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Client is the control plane's client for the approval service's internal API.
type Client struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
}

// Status is the control plane's view of a request.
type Status struct {
	ID          string `json:"id"`
	State       string `json:"state"`
	Attestation string `json:"attestation"`
}

func (c *Client) do(ctx context.Context, method, path string, body any, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")
	hc := c.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("approval service: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode >= 300 {
		var p struct {
			Reasons []string `json:"reasons"`
		}
		_ = json.Unmarshal(raw, &p)
		return fmt.Errorf("approval service: HTTP %d %v", resp.StatusCode, p.Reasons)
	}
	return json.Unmarshal(raw, out)
}

// Request asks for approval and returns the request ID.
func (c *Client) Request(ctx context.Context, in SubmitInput) (string, error) {
	var out Status
	if err := c.do(ctx, http.MethodPost, "/internal/v1/requests", in, &out); err != nil {
		return "", err
	}
	return out.ID, nil
}

// Status returns the request's state and, once approved, the attestation.
func (c *Client) Status(ctx context.Context, id string) (Status, error) {
	var out Status
	err := c.do(ctx, http.MethodGet, "/internal/v1/requests/"+id, nil, &out)
	return out, err
}
