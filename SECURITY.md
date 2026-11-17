# Security

Squidbrake sits between AI agents and the actions they take, so security bugs matter a lot here.

## Reporting a vulnerability

Please **don't open a public issue**. Report it privately through GitHub:
**Security → Report a vulnerability** on this repository. Include what you found, how to reproduce it,
and what an attacker could do with it. You'll get a reply within a few days.

Especially interesting:

- a way for an agent to run an action that a rule blocks or holds for approval
- approving or rejecting without an approver key, or approving your own request
- reading events, keys or settings with a key that shouldn't allow it
- secrets that end up stored unredacted
- breaking or rewriting the audit trail without the tamper check noticing

## Running it safely

- Give every person and every agent **its own key**; remove keys you no longer need (Team tab).
- Keep the admin key private. Agents get agent keys, never an admin or approver key.
- Put it behind HTTPS (`bash install.sh` does this for you) when anything outside your machine connects.
- The gateway **fails closed**: if it's unreachable, the Claude Code hook and the MCP connectors refuse to run tools.
- It guards the actions that go through it. An agent with its own unguarded shell or credentials can still act
  outside it, so connect every tool path the agent has (for Claude Code, `connect.py claude-code` covers all of them).

## Checking a release is ours

Every release on PyPI and every image on ghcr.io comes with Sigstore-signed build provenance from GitHub Actions: which
workflow built it, from which commit. To check a downloaded file or the image:

```bash
gh attestation verify squidbrake-VERSION-py3-none-any.whl --repo batrapulkit/squidbrake
gh attestation verify oci://ghcr.io/batrapulkit/squidbrake:latest --repo batrapulkit/squidbrake
```
