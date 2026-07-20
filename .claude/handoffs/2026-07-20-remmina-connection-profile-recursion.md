# Remmina Connection Profile Recursion Handoff

Date: 2026-07-20

## Checkpoint

Remmina `.remmina` connection profiles now keep the source-aware
`remmina-config` artifact format. Remote `.remmina` URLs route into artifact
recursion, and host fields such as `server=rdp.acme.example:3389` and
`ssh_tunnel_server=bastion.acme.example` produce normalized recursive host seeds.

The change stays inside `forge/utils/artifact_connection_client.py` and its
focused test file. No `forge/engagement_orchestrator.py` edit was required.

## Why It Matters

Remmina profiles commonly appear in workstation backups and exposed config
bundles. They can contain scoped host pivots, dashboard URLs, owner emails, and
cloud references that should feed FORGE's recursive discovery chain without
opening RDP/SSH sessions or authenticating anywhere.

## Verification

- `.venv\Scripts\python.exe -m py_compile forge\utils\artifact_connection_client.py tests\phase1\test_artifact_connection_client.py`
- `.venv\Scripts\ruff.exe check forge\utils\artifact_connection_client.py tests\phase1\test_artifact_connection_client.py`
- `.venv\Scripts\python.exe -m pytest tests\phase1\test_artifact_connection_client.py -q --color=no` -> `39 passed`

## Safety Boundaries

Passive static connection-profile parsing only. No Remmina execution, RDP/SSH
connection, authentication, credential use, provider calls, live probing, scope
relaxation, proxy/IP rotation, rate-limit bypass, destructive behavior, or
report-gate change.

## Next Suggested Work

Continue with focused passive parser coverage or proof-gate hardening. Use
subagents for read-only gap discovery, but keep implementation slices small and
commit each verified checkpoint.
