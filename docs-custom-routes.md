# Custom Routes

## Quick Example

```json
{
  "custom_route_rules": [
    {
      "name": "direct-example",
      "match": {"domain_suffixes": ["example.com"]},
      "action": {"type": "direct"}
    },
    {
      "name": "block-ads",
      "match": {"domains": ["ads.example.com"]},
      "action": {"type": "block"}
    },
    {
      "name": "route-warp",
      "match": {"ip_cidrs": ["1.1.1.0/24"], "ports": ["80", "443"]},
      "action": {"type": "route", "target": "warp-out"}
    }
  ]
}
```

## Match Conditions

| Condition | Description | Example |
|-----------|-------------|---------|
| `domains` | Exact domain match | `["api.example.com"]` |
| `domain_suffixes` | Suffix match | `["example.com"]` |
| `ip_cidrs` | IP CIDR ranges | `["10.0.0.0/8"]` |
| `ports` | Port (single or range) | `["443", "8000-9000"]` |
| `networks` | Protocol | `["tcp"]` or `["udp"]` |
| `source_cidrs` | Source IP CIDR | `["192.168.1.0/24"]` |
| `source_ports` | Source port | `["1024-65535"]` |

Each nonempty condition field is an **alternative (OR)**, and values inside a
field are also alternatives. For example, `ip_cidrs` plus `ports` matches traffic
to the CIDR **or** traffic to one of the ports. This preserves the existing panel
rule semantics in both kernels. Use an explicitly native raw `custom_routes`
rule when an AND combination is required, and check that kernel's syntax.

An unprefixed `domains` entry matches exactly that hostname, without matching its
subdomains or arbitrary substrings. `domain_suffixes` matches the hostname and
its subdomains. Existing explicit Xray prefixes (`full:`, `domain:`, `keyword:`,
`regexp:`, `geosite:`, `ext:`, `ext-domain:`) are preserved for compatibility;
these native expressions are not portable sing-box domain strings.

## Action Types

| Action | Description |
|--------|-------------|
| `{"type": "direct"}` | Direct connection, bypass proxy |
| `{"type": "block"}` | Block connection |
| `{"type": "route", "target": "tag"}` | Route to specified outbound (by tag) |

## Application Order

1. Structured `custom_route_rules` (highest priority)
2. Raw `custom_routes`
3. Built-in blocklist rules
4. Panel routes

## Kernel Compatibility

| Feature | Xray | Sing-box |
|---------|------|----------|
| All match conditions | ✅ | ✅ |
| direct / block / route | ✅ | ✅ |

## Best Practices

- **Prefer** `custom_route_rules` for local standalone structured configuration. The current independent panel does not store or emit this field; its `custom_routes` field uses the selected kernel's native format.
- **Use** `custom_routes` only: when native features are needed (e.g., load balancing)

## Applying Policy Changes

Routing and outbound changes apply together after the node receives the new
configuration. For sing-box and Xray, the node prepares the complete configuration, then
replaces only that node's embedded kernel. This handles added, edited and removed
outbounds as well as rule changes. Existing TCP and UDP flows on that node are
closed so an old connection cannot continue bypassing a newly added block or
keep using an obsolete outbound; clients reconnect under the new policy. The
node process, panel control connection and cumulative traffic counters remain.
Xray cancels the previous instance's root context immediately, including idle
VLESS TCP streams and UDP associations, instead of allowing the old routes to
continue during the previous five-minute background drain.

An invalid candidate rejected during preparation leaves the current kernel and
connections running. If starting the candidate fails after listeners close, the
node restores its last successfully applied configuration, including subsequent
user-only updates, and reports the reload error. A successful update does not
require restarting the node service. Speed/device limit changes with the same
user identities keep the existing kernel and connections; no authentication
rewrite is needed for these changes.

In sing-box, adding/removing users or changing UUIDs uses the same complete
candidate and rollback path. The frozen dependency's native `UpdateUsers`
methods replace authentication state without synchronizing with active
handlers (including SOCKS, HTTP and Naive), so they are not called by this node.
An accepted identity change closes that node's existing TCP/UDP flows and
clients reconnect with the new credentials. The process, panel channel and
cumulative traffic counters remain. This also applies to identity updates
received through `AddUsers`, `RemoveUsers`, `UpdateUsers` and `Reload`.
These user events preserve the policy actually running; they do not read and
apply edits made to a local custom-config file. Apply such file changes with a
node configuration change or a deliberate service restart.
