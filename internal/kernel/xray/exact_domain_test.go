package xray

import (
	"reflect"
	"testing"

	"github.com/cedar2025/xboard-node/internal/model"
)

func TestStructuredDomainsExactAndExplicitMatchersRetained(t *testing.T) {
	input := []string{" api.example.com ", "full:exact.example", "domain:suffix.example", "keyword:piece", "regexp:^example[.]com$", "geosite:cn", "ext:custom.dat:tag", "ext-domain:custom.dat:tag", ""}
	rules := compileCustomRouteRule(model.CustomRouteRule{Match: model.RouteMatch{Domains: input}, Action: model.RouteAction{Type: "block"}})
	want := []string{"full:api.example.com", "full:exact.example", "domain:suffix.example", "keyword:piece", "regexp:^example[.]com$", "geosite:cn", "ext:custom.dat:tag", "ext-domain:custom.dat:tag"}
	if len(rules) != 1 || !reflect.DeepEqual(rules[0]["domain"], want) {
		t.Fatalf("compiled domains=%v; want %v", rules, want)
	}
}
