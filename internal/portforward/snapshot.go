package portforward

import (
	"bytes"
	"encoding/json"
	"io"
	"strconv"
	"strings"

	"github.com/cedar2025/xboard-node/internal/nftsnapshot"
)

// nft 1.0.6 can omit legacy table comments from JSON while retaining them in
// its text output. Recover only this owner's missing inet comment; never infer
// ownership from a table name, an empty comment, or another owner's resources.
// The full JSON body remains subject to inspect's existing strict validation.
func readSnapshot(query nftsnapshot.Query, table, marker string) ([]byte, error) {
	data, err := nftsnapshot.Read(query)
	if err != nil {
		return nil, err
	}
	prepared, identity, eligible, err := prepareLegacySnapshot(data, table, marker)
	if err != nil {
		return nil, err
	}
	if !eligible {
		return data, nil
	}
	text, err := query("-a", "-nn", "list", "table", "inet", table)
	if err != nil || len(text) > nftsnapshot.MaxOutput || !legacyTextOwner(text, table, marker, identity.handle) {
		return nil, ownedError()
	}
	// Bind the text ownership evidence to the same table generation and body.
	// Counters can advance with traffic; all other resources, handles and rule
	// expressions must remain unchanged. Return the newest complete inventory
	// so conflict checks also see changes to other tables during the extra read.
	latest, err := nftsnapshot.Read(query)
	if err != nil {
		return nil, err
	}
	prepared, current, eligible, err := prepareLegacySnapshot(latest, table, marker)
	if err != nil || !eligible || identity.handle != current.handle || !bytes.Equal(identity.body, current.body) {
		return nil, ownedError()
	}
	return prepared, nil
}

type legacyIdentity struct {
	handle uint64
	body   []byte
}

func prepareLegacySnapshot(data []byte, table, marker string) ([]byte, legacyIdentity, bool, error) {
	var doc struct {
		Entries []map[string]json.RawMessage `json:"nftables"`
	}
	if json.Unmarshal(data, &doc) != nil {
		return data, legacyIdentity{}, false, nil // retain the normal parser's error
	}
	index := -1
	var fields map[string]json.RawMessage
	for i, row := range doc.Entries {
		var t nftTable
		if raw, ok := row["table"]; ok && json.Unmarshal(raw, &t) == nil && t.Family == "inet" && t.Name == table {
			if index != -1 {
				return nil, legacyIdentity{}, false, ownedError()
			}
			index = i
			if json.Unmarshal(raw, &fields) != nil {
				return nil, legacyIdentity{}, false, ownedError()
			}
		}
	}
	if index == -1 {
		return data, legacyIdentity{}, false, nil
	}
	if _, present := fields["comment"]; present {
		return data, legacyIdentity{}, false, nil // explicit null/empty/wrong is not omission
	}
	if _, ok := object(data, "nftables"); !ok || !uniqueJSON(data) {
		return nil, legacyIdentity{}, false, ownedError()
	}
	var identity legacyIdentity
	if json.Unmarshal(fields["handle"], &identity.handle) != nil || identity.handle == 0 {
		return nil, legacyIdentity{}, false, ownedError()
	}
	fields["comment"], _ = json.Marshal(marker)
	doc.Entries[index]["table"], _ = json.Marshal(fields)
	prepared, err := json.Marshal(doc)
	if err != nil {
		return nil, legacyIdentity{}, false, ownedError()
	}
	// This checks every object in the namespace before trusting text evidence;
	// no sets, extra chains/rules, unknown fields or altered redirects qualify.
	if _, err := inspect(prepared, table, marker); err != nil {
		return nil, legacyIdentity{}, false, err
	}
	var rows []any
	for _, row := range doc.Entries {
		for kind, raw := range row {
			var loc struct{ Family, Table, Name string }
			_ = json.Unmarshal(raw, &loc)
			if loc.Family != "inet" || kind == "table" && loc.Name != table || kind != "table" && loc.Table != table {
				continue
			}
			decoder := json.NewDecoder(bytes.NewReader(raw))
			decoder.UseNumber()
			var value map[string]any
			if decoder.Decode(&value) != nil {
				return nil, legacyIdentity{}, false, ownedError()
			}
			if kind == "rule" {
				for _, expr := range value["expr"].([]any) {
					if counter, ok := expr.(map[string]any)["counter"].(map[string]any); ok {
						counter["packets"], counter["bytes"] = json.Number("0"), json.Number("0")
					}
				}
			}
			rows = append(rows, map[string]any{kind: value})
		}
	}
	identity.body, _ = json.Marshal(rows)
	return prepared, identity, true, nil
}

// Reject duplicate keys before supplementing a JSON document: unmarshalling
// into a map otherwise hides ambiguous ownership and resource declarations.
func uniqueJSON(data []byte) bool {
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	var value func(int) bool
	value = func(depth int) bool {
		if depth > 256 {
			return false
		}
		token, err := d.Token()
		if err != nil {
			return false
		}
		delim, composite := token.(json.Delim)
		if !composite {
			return true
		}
		switch delim {
		case '{':
			seen := make(map[string]bool)
			for d.More() {
				key, err := d.Token()
				name, ok := key.(string)
				if err != nil || !ok || seen[name] || !value(depth+1) {
					return false
				}
				seen[name] = true
			}
		case '[':
			for d.More() {
				if !value(depth + 1) {
					return false
				}
			}
		default:
			return false
		}
		_, err = d.Token()
		return err == nil
	}
	if !value(0) {
		return false
	}
	_, err := d.Token()
	return err == io.EOF
}

// Parse only nft's canonical text table envelope and its root-level comment.
// Strings and # handle comments cannot smuggle braces or ownership evidence.
// Nested rule content is independently checked in both JSON observations.
func legacyTextOwner(data []byte, table, marker string, handle uint64) bool {
	text := strings.TrimSpace(string(data))
	lines := strings.Split(text, "\n")
	wantHeader := []string{"table", "inet", table, "{", "#", "handle", strconv.FormatUint(handle, 10)}
	if len(lines) < 3 || strings.Join(strings.Fields(lines[0]), " ") != strings.Join(wantHeader, " ") {
		return false
	}
	depth, comments := 0, 0
	for i, line := range lines {
		line = strings.TrimSpace(line)
		if depth == 0 && i != 0 {
			return false
		}
		if depth == 1 && line != "" {
			switch {
			case line == "comment "+strconv.Quote(marker):
				comments++
			case strings.HasPrefix(line, "chain prerouting { # handle "):
				parts := strings.Fields(line)
				if len(parts) != 6 || parts[0] != "chain" || parts[1] != "prerouting" || parts[2] != "{" || parts[3] != "#" || parts[4] != "handle" {
					return false
				}
				n, err := strconv.ParseUint(parts[5], 10, 64)
				if err != nil || n == 0 {
					return false
				}
			case line == "}":
			default:
				return false
			}
		}
		quoted, escaped := false, false
		for _, c := range line {
			if c < 32 && c != '\t' {
				return false
			}
			if quoted {
				if escaped {
					escaped = false
				} else if c == '\\' {
					escaped = true
				} else if c == '"' {
					quoted = false
				}
				continue
			}
			if c == '#' {
				break
			}
			switch c {
			case '"':
				quoted = true
			case '{':
				depth++
			case '}':
				depth--
				if depth < 0 || depth == 0 && (i != len(lines)-1 || line != "}") {
					return false
				}
			}
		}
		if quoted {
			return false
		}
	}
	return depth == 0 && comments == 1
}
