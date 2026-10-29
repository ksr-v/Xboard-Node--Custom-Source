// Package nftsnapshot reads nftables inventory through a caller-supplied,
// read-only executor. It contains no process execution or firewall mutation.
package nftsnapshot

import (
	"bytes"
	"errors"
	"regexp"
)

// nft 0.9.0 emits this exact empty-inventory shape. Keep the recognition
// narrow: missing keys, extra keys and duplicate keys are not an empty dump.
var legacyNull = regexp.MustCompile(`^[ \t\r\n]*\{[ \t\r\n]*"nftables"[ \t\r\n]*:[ \t\r\n]*null[ \t\r\n]*\}[ \t\r\n]*$`)

const MaxOutput = 16 << 20

var (
	ErrUnconfirmedEmpty = errors.New("nftables returned an empty JSON ruleset without independent confirmation; no rules changed")
	ErrTooLarge         = errors.New("nftables ruleset exceeds the safe inventory size; no rules changed")
)

// Query executes fixed argument vectors and returns stdout only on success.
// The caller supplies its existing trusted, bounded and shell-free executor.
type Query func(args ...string) ([]byte, error)

// Read preserves every nonblank JSON response for the caller's strict parser.
// A blank response is not evidence of an empty firewall: require a separate,
// successful, plain-text table listing to be blank too before normalizing it.
// The legacy single-key {"nftables":null} shape uses the same independent
// confirmation. Bare null, {}, malformed and populated dumps never do.
func Read(query Query) ([]byte, error) {
	// Old nft uses the second -n level for service ports. A single -n still
	// serializes 53/443 as domain/https in its JSON, making ownership ambiguous.
	data, err := query("-j", "-nn", "list", "ruleset")
	if err != nil {
		return nil, err
	}
	if len(data) > MaxOutput {
		return nil, ErrTooLarge
	}
	if len(bytes.TrimSpace(data)) != 0 && !legacyNull.Match(data) {
		return data, nil
	}
	tables, err := query("list", "tables")
	if err != nil || len(tables) > MaxOutput || len(bytes.TrimSpace(tables)) != 0 {
		return nil, ErrUnconfirmedEmpty
	}
	return []byte(`{"nftables":[]}`), nil
}
