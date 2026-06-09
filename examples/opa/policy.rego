# OPA / Rego policy (policy-as-code, ABAC). The AuthZEN gateway evaluates `allow` once per
# tool call; tool attributes are vendored in data.json. The demo agent may execute a tool
# only when it is low-sensitivity and non-destructive — anything destructive is denied. The
# `default allow := false` line is the fail-closed pivot: an unknown tool or a missing
# attribute leaves `allow` at its default, so the gateway returns `decision: false`.
package apparitor.authz

default allow := false

allow if {
	input.subject.id == "demo-agent"
	input.action.name == "tool_call.execute"
	input.resource.type == "tool"
	tool := data.tools[input.resource.id]
	tool.sensitivity == "low"
	not tool.destructive
}
