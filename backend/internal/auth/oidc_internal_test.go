package auth

import (
	"net/http"
	"strings"
	"testing"

	"golang.org/x/oauth2"
)

func TestSanitizeExchangeErrorDropsBody(t *testing.T) {
	re := &oauth2.RetrieveError{
		Response:  &http.Response{StatusCode: 400},
		Body:      []byte(`{"error":"invalid_grant","access_token":"LEAKED-AT","id_token":"LEAKED-IDT"}`),
		ErrorCode: "invalid_grant",
	}
	got := sanitizeExchangeError(re).Error()
	if strings.Contains(got, "LEAKED") || !strings.Contains(got, "HTTP 400 (invalid_grant)") {
		t.Fatalf("got %q", got)
	}
}
