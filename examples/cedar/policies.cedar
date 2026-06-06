// Cedar policy-as-code (ABAC). The scanner sends one authorization request per tool call;
// `forbid` always overrides `permit`, so a destructive tool is denied even if some other
// policy would allow it.

// The demo agent may execute low-sensitivity, non-destructive tools.
permit (
  principal == Agent::"demo-agent",
  action == Action::"tool_call.execute",
  resource
)
when { resource.sensitivity == "low" && resource.destructive == false };

// Destructive tools are forbidden outright, regardless of subject.
forbid (
  principal,
  action == Action::"tool_call.execute",
  resource
)
when { resource.destructive == true };
