package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name       string
		headers    http.Header
		wantAPIKey string
		wantErr    error
	}{
		{
			name:       "returns api key when header is valid",
			headers:    http.Header{"Authorization": []string{"ApiKey super-secret-key"}},
			wantAPIKey: "super-secret-key",
			wantErr:    nil,
		},
		{
			name:       "returns sentinel error when auth header missing",
			headers:    http.Header{},
			wantAPIKey: "",
			wantErr:    ErrNoAuthHeaderIncluded,
		},
		{
			name:       "returns malformed error when scheme is not ApiKey",
			headers:    http.Header{"Authorization": []string{"Bearer super-secret-key"}},
			wantAPIKey: "",
			wantErr:    errors.New("malformed authorization header"),
		},
		{
			name:       "returns malformed error when key is missing",
			headers:    http.Header{"Authorization": []string{"ApiKey"}},
			wantAPIKey: "",
			wantErr:    errors.New("malformed authorization header"),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotAPIKey, err := GetAPIKey(tc.headers)

			if tc.wantErr != nil {
				if err == nil {
					t.Fatalf("expected error %q, got nil", tc.wantErr)
				}

				if !errors.Is(err, tc.wantErr) && err.Error() != tc.wantErr.Error() {
					t.Fatalf("expected error %q, got %q", tc.wantErr, err)
				}
			} else if err != nil {
				t.Fatalf("expected no error, got %q", err)
			}

			if gotAPIKey != tc.wantAPIKey {
				t.Fatalf("expected api key %q, got %q", tc.wantAPIKey, gotAPIKey)
			}
		})
	}
}
