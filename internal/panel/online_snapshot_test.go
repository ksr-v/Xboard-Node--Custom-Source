package panel

import (
	"encoding/json"
	"net/http"
	"reflect"
	"testing"
)

func TestReportPreservesDeviceSnapshotPresence(t *testing.T) {
	cases := []struct {
		name  string
		alive map[int][]string
		want  map[string][]string
	}{
		{name: "missing snapshot stays absent"},
		{name: "last disconnect reports empty object", alive: map[int][]string{}, want: map[string][]string{}},
		{name: "active snapshot includes IPs", alive: map[int][]string{1: {"1.1.1.1"}}, want: map[string][]string{"1": {"1.1.1.1"}}},
		{name: "explicit empty user list survives", alive: map[int][]string{1: {}}, want: map[string][]string{"1": {}}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			ts, client := newTestServer(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/v2/server/report" {
					t.Errorf("unexpected path: %s", r.URL.Path)
				}
				var payload map[string]json.RawMessage
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					t.Errorf("decode report: %v", err)
				}
				raw, present := payload["alive"]
				if present != (test.alive != nil) {
					t.Errorf("snapshot presence = %v; want %v", present, test.alive != nil)
				}
				if present {
					var devices map[string][]string
					if err := json.Unmarshal(raw, &devices); err != nil {
						t.Errorf("device snapshot is not an object: %v", err)
					}
					if !reflect.DeepEqual(devices, test.want) {
						t.Errorf("devices = %#v; want %#v", devices, test.want)
					}
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"data":true}`))
			})
			defer ts.Close()
			if err := client.Report(nil, test.alive, nil, 0, [2]uint64{}, [2]uint64{}, [2]uint64{}, nil); err != nil {
				t.Fatalf("report: %v", err)
			}
		})
	}
}
