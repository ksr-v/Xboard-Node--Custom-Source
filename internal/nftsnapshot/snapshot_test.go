package nftsnapshot

import (
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func TestGuardedEmptyRequiresIndependentSuccessfulPlainTableListing(t *testing.T) {
	for _, blank := range []string{"", " \t\r\n", `{"nftables": null}`, " { \"nftables\" : null }\n"} {
		t.Run("bytes="+strconv.Itoa(len(blank)), func(t *testing.T) {
			var calls [][]string
			got, err := Read(func(args ...string) ([]byte, error) {
				calls = append(calls, args)
				if len(calls) > 1 {
					return nil, nil
				}
				return []byte(blank), nil
			})
			if err != nil || string(got) != `{"nftables":[]}` {
				t.Fatal("independently empty inventory rejected", err)
			}
			want := [][]string{{"-j", "-nn", "list", "ruleset"}, {"list", "tables"}}
			if !reflect.DeepEqual(calls, want) {
				t.Fatal("fallback is not independently read-only", calls)
			}
		})
	}
}

func TestUnknownOrPopulatedTableListingCannotConfirmEmpty(t *testing.T) {
	for name, response := range map[string]struct {
		data string
		err  error
	}{
		"populated":             {"table inet existing\n", nil},
		"json-instead-of-plain": {`{"nftables":[]}`, nil},
		"null":                  {"null", nil},
		"warning":               {"warning: partial inventory\n", nil},
		"failure-blank":         {"", errors.New("private command diagnostic")},
		"failure-populated":     {"table ip existing\n", errors.New("private command diagnostic")},
		"oversize":              {strings.Repeat(" ", MaxOutput+1), nil},
	} {
		t.Run(name, func(t *testing.T) {
			calls := 0
			got, err := Read(func(args ...string) ([]byte, error) {
				calls++
				if calls == 1 {
					return nil, nil
				}
				return []byte(response.data), response.err
			})
			if err != ErrUnconfirmedEmpty || len(got) != 0 || calls != 2 || strings.Contains(err.Error(), "private") {
				t.Fatal("unknown inventory treated as empty", err)
			}
		})
	}
}

func TestNonblankResponsesAreNeverDiscardedOrRetried(t *testing.T) {
	for _, response := range []string{`{"nftables":[]}`, `{"nftables":[{"metainfo":{"version":"1.0.9","json_schema_version":1}}]}`, `null`, `{}`, `{"nftables":null,"other":{}}`, `{"nftables":[],"nftables":null}`, `{"nftables":{}}`, `not JSON`, `{"nftables":[{"table":{"family":"ip","name":"nat"}}]}`} {
		calls := 0
		got, err := Read(func(args ...string) ([]byte, error) { calls++; return []byte(response), nil })
		if err != nil || string(got) != response || calls != 1 {
			t.Fatal("nonblank inventory was replaced", err)
		}
	}
}

func TestInitialFailureAndOversizeNeverUseFallback(t *testing.T) {
	for _, fail := range []bool{false, true} {
		calls := 0
		sentinel := errors.New("query failed")
		got, err := Read(func(args ...string) ([]byte, error) {
			calls++
			if fail {
				return nil, sentinel
			}
			return []byte(strings.Repeat(" ", MaxOutput+1)), nil
		})
		if len(got) != 0 || calls != 1 || (fail && err != sentinel) || (!fail && err != ErrTooLarge) {
			t.Fatal("failed query retried as empty", err)
		}
	}
}
