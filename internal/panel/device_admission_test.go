package panel

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestAcquireDeviceValidatesDecisionAndGeneration(t *testing.T) {
	const token = "0123456789abcdef0123456789abcdef"
	cases := []struct {
		name   string
		status int
		body   string
		ok     bool
	}{
		{"allowed", 200, `{"data":{"allowed":true,"lease_token":"` + token + `","ttl":60}}`, true},
		{"denied", 200, `{"data":{"allowed":false,"lease_token":"` + token + `","ttl":60}}`, false},
		{"wrong generation", 200, `{"data":{"allowed":true,"lease_token":"old-token","ttl":60}}`, false},
		{"invalid ttl", 200, `{"data":{"allowed":true,"lease_token":"` + token + `","ttl":0}}`, false},
		{"lease shorter than safety protocol", 200, `{"data":{"allowed":true,"lease_token":"` + token + `","ttl":30}}`, false},
		{"malformed", 200, `private response body`, false},
		{"unavailable", 503, `private response body`, false},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			ts, client := newTestServer(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/v2/server/device/acquire" || r.Method != http.MethodPost {
					t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
				}
				if r.URL.RawQuery != "" {
					t.Error("credentials should not enter URL")
				}
				var body map[string]interface{}
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Error(err)
				}
				if body["user_uuid"] != "user-identity" || body["ip"] != "127.0.0.2" || body["lease_token"] != token || body["report_interval"] != float64(5) || body["token"] != "test-token" {
					t.Error("reservation identity or existing auth missing")
				}
				w.WriteHeader(test.status)
				_, _ = w.Write([]byte(test.body))
			})
			defer ts.Close()
			err := client.AcquireDevice(context.Background(), "user-identity", "127.0.0.2", token, 5)
			if (err == nil) != test.ok {
				t.Fatalf("success = %v, want %v", err == nil, test.ok)
			}
			if err != nil && (strings.Contains(err.Error(), "private response") || strings.Contains(err.Error(), token) || strings.Contains(err.Error(), "user-identity")) {
				t.Error("admission error disclosed private response or identity")
			}
		})
	}
}

func TestAdmissionRequestHonorsShortParentDeadline(t *testing.T) {
	ts, client := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(time.Second):
		}
	})
	defer ts.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	started := time.Now()
	if err := client.AcquireDevice(ctx, "user", "127.0.0.2", "generation", 5); err == nil {
		t.Fatal("timed out reservation was accepted")
	}
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("caller deadline was ignored: %s", elapsed)
	}
}

func TestReleaseDeviceSendsMatchingGeneration(t *testing.T) {
	ts, client := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2/server/device/release" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		var body map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		if body["user_uuid"] != "user" || body["ip"] != "127.0.0.2" || body["lease_token"] != "generation" {
			t.Error("release identity or generation missing")
		}
		_, _ = w.Write([]byte(`{"data":true}`))
	})
	defer ts.Close()
	if err := client.ReleaseDevice(context.Background(), "user", "127.0.0.2", "generation"); err != nil {
		t.Fatal(err)
	}
}

func TestHandshakeAdmissionCapabilityIsOptional(t *testing.T) {
	for _, encoded := range []string{`{"settings":[],"websocket":{"enabled":false}}`, `{"settings":{},"device_admission":{"version":1,"heartbeat_interval":5}}`} {
		var handshake HandshakeResponse
		if err := json.Unmarshal([]byte(encoded), &handshake); err != nil {
			t.Fatal(err)
		}
		want := 0
		if strings.Contains(encoded, "device_admission") {
			want = 1
		}
		if handshake.DeviceAdmission.Version != want {
			t.Fatalf("capability version = %d; want %d", handshake.DeviceAdmission.Version, want)
		}
	}
}

func TestDeviceAdmissionNeverForwardsCredentialsOnRedirect(t *testing.T) {
	for _, status := range []int{http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var forwarded atomic.Int64
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				forwarded.Add(1)
				_, _ = w.Write([]byte(`{"data":true}`))
			}))
			defer target.Close()
			source, client := newTestServer(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Location", target.URL+"/unexpected")
				w.WriteHeader(status)
			})
			defer source.Close()
			if err := client.AcquireDevice(context.Background(), "user", "127.0.0.2", "private-generation", 5); err == nil {
				t.Error("redirected acquire should fail closed")
			}
			if err := client.ReleaseDevice(context.Background(), "user", "127.0.0.2", "private-generation"); err == nil {
				t.Error("redirected release should fail")
			}
			if forwarded.Load() != 0 {
				t.Fatal("device admission request body was forwarded to redirect target")
			}
		})
	}
}

func TestCapablePanelReportCannotAcknowledgeAfterSafetyDeadline(t *testing.T) {
	ts, client := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v2/server/handshake" {
			_, _ = w.Write([]byte(`{"device_admission":{"version":1,"heartbeat_interval":5}}`))
			return
		}
		select {
		case <-r.Context().Done():
		case <-time.After(3 * time.Second):
			_, _ = w.Write([]byte(`{"data":true}`))
		}
	})
	defer ts.Close()
	if _, err := client.Handshake(); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	err := client.Report(nil, map[int][]string{}, nil, 0, [2]uint64{}, [2]uint64{}, [2]uint64{}, nil)
	if err == nil {
		t.Fatal("late report was accepted")
	}
	if elapsed := time.Since(started); elapsed > 2500*time.Millisecond {
		t.Fatalf("capable report exceeded two-second timeout: %s", elapsed)
	}
	if client.httpClient.Timeout != 30*time.Second {
		t.Fatal("short report timeout mutated shared transport client")
	}
}

func TestRetainedReleaseRequiresNegotiatedPeerCapability(t *testing.T) {
	for _, supported := range []bool{false, true} {
		var releases atomic.Int64
		ts, client := newTestServer(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/api/v2/server/handshake" {
				_ = json.NewEncoder(w).Encode(map[string]interface{}{"device_admission": map[string]interface{}{"version": 1, "retain_ip": supported}})
				return
			}
			releases.Add(1)
			var payload map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Error(err)
			}
			if payload["retain_ip"] != true || payload["lease_token"] != "generation" || payload["user_uuid"] != "user" || payload["ip"] != "127.0.0.2" {
				t.Error("retained release did not preserve its boolean decision or generation")
			}
			_, _ = w.Write([]byte(`{"data":true}`))
		})
		if _, err := client.Handshake(); err != nil {
			ts.Close()
			t.Fatal(err)
		}
		if client.SupportsRetainedDeviceRelease() != supported {
			ts.Close()
			t.Fatal("incorrect retain capability")
		}
		err := client.ReleaseDeviceRetainingIP(context.Background(), "user", "127.0.0.2", "generation")
		if (err == nil) != supported {
			ts.Close()
			t.Fatalf("retained release success=%v want %v", err == nil, supported)
		}
		want := int64(0)
		if supported {
			want = 1
		}
		if releases.Load() != want {
			ts.Close()
			t.Fatal("unsupported peer received a destructive release request")
		}
		ts.Close()
	}
}
