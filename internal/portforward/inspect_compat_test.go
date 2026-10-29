package portforward

import (
	"strings"
	"testing"

	"github.com/cedar2025/xboard-node/internal/nftsnapshot"
)

func TestStandardNftJSONRepresentationsRemainCompatible(t *testing.T) {
	for name, data := range map[string]string{
		"empty":              `{"nftables":[]}`,
		"metainfo-only":      `{"nftables":[{"metainfo":{"version":"1.0.9","release_name":"Old Doc Yak #3","json_schema_version":1}}]}`,
		"compatibility-rule": `{"nftables":[{"metainfo":{"version":"1.0.6","json_schema_version":1}},{"table":{"family":"ip","name":"filter","handle":1}},{"chain":{"family":"ip","table":"filter","name":"INPUT","type":"filter","hook":"input","prio":0,"policy":"accept"}},{"rule":{"family":"ip","table":"filter","chain":"INPUT","handle":42,"expr":[{"counter":{"packets":18446744073709551615,"bytes":18446744073709551615}},{"xt":{"type":"match","name":"comment","rev":0}},{"accept":null}]}}]}`,
		"ipv6-verdict":       `{"nftables":[{"table":{"family":"ip6","name":"filter"}},{"rule":{"family":"ip6","table":"filter","chain":"INPUT","expr":[{"match":{"op":"in","left":{"ct":{"key":"state"}},"right":{"set":["related","established"]}}},{"jump":{"target":"custom"}}]}}]}`,
		"named-objects":      `{"nftables":[{"counter":{"family":"inet","table":"host","name":"named","packets":1,"bytes":1200}},{"set":{"family":"ip","table":"nat","name":"ports","type":"inet_service","elem":[17443,19443]}}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := inspect([]byte(data), "unused", "unused"); err != nil {
				t.Fatal("standard schema rejected", err)
			}
		})
	}
}

func TestOnlyIndependentlyConfirmedBlankSnapshotBecomesEmpty(t *testing.T) {
	for name, first := range map[string]string{"blank": "", "whitespace": "\n \t", "null": "null", "missing-key": "{}", "null-array": `{"nftables":null}`, "wrong-array": `{"nftables":{}}`, "malformed": "not JSON"} {
		t.Run(name, func(t *testing.T) {
			calls := 0
			data, err := nftsnapshot.Read(func(args ...string) ([]byte, error) {
				calls++
				if calls == 1 {
					return []byte(first), nil
				}
				return nil, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			_, err = inspect(data, "unused", "unused")
			blank := strings.TrimSpace(first) == "" || name == "null-array"
			if (err == nil) != blank {
				t.Fatal("unknown response treated as empty", err)
			}
			wantCalls := 1
			if blank {
				wantCalls = 2
			}
			if calls != wantCalls {
				t.Fatal("incorrect fallback query count", calls)
			}
		})
	}
}

func TestGuardNeverConcealsPopulatedNATConflict(t *testing.T) {
	want, _ := validate(node())
	data := []byte(`{"nftables":[{"table":{"family":"inet","name":"other_nat"}},{"rule":{"family":"inet","table":"other_nat","chain":"prerouting","expr":[{"redirect":{"port":17443}}]}}]}`)
	calls := 0
	got, err := nftsnapshot.Read(func(args ...string) ([]byte, error) { calls++; return data, nil })
	if err != nil {
		t.Fatal(err)
	}
	v, err := inspect(got, "unused", "unused")
	if err != nil || v.conflicts(want) == nil || calls != 1 {
		t.Fatal("populated NAT inventory bypassed", err)
	}
}
