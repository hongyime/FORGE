# Supported Targets and Scope

The supported target types are:

- URL
- Domain
- IPv4 address
- Cloud reference (`cloud_ref`)

Other identity or contact data—including usernames, email addresses, phone
numbers, names, and companies—is not a supported target type. A wildcard
configuration value does not establish authorization; every target must be in
specific scope set by a human. A new target type requires human review.

## Sources and precedence

This rule draws on `README.md`, `docs/STACK_WALKTHROUGH.md`,
`docs/forge_continuous_loop_architecture.md`, and the former `SPEC.md`. The
October 19, 2026 v2 rule limits the supported set to the four types above and
supersedes older wildcard-scope statements. `manifests/default.json` is not
proof of authorization and remains unchanged.
