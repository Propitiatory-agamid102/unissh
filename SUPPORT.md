# Getting help with UniSSH

UniSSH is honest, in-progress, anonymously-maintained software. There's no support
desk and no on-call team — but there are good ways to get unstuck. Please go in this
order.

## 1. Read the docs and FAQ first

A lot of common questions are already answered:

- **Docs site:** <https://goduni.github.io/unissh/>
- **README FAQ / Troubleshooting:** <https://github.com/goduni/unissh#faq--troubleshooting>

Things covered there include the unsigned-build OS warnings ("developer cannot be
verified" / SmartScreen), a client not reaching your server, bootstrap/first-account
problems, the admin panel's `wasm not loaded` message, and `TransportRollback` after a
server restore. Each component also has its own README with platform specifics.

## 2. Questions, support & ideas → GitHub Discussions

For usage questions, self-host/setup help, "how do I…", and open-ended ideas, use
**GitHub Discussions**:

- <https://github.com/goduni/unissh/discussions>

Discussions is the **community home**. There is intentionally **no Discord or chat
server** — running one would add identity/moderation surface that doesn't fit an
anonymously-maintained project. Discussions keeps help searchable for the next person,
which is better for everyone.

## 3. Found a bug? → Open an issue

If something is broken and reproducible, open a bug report using the issue form:

- <https://github.com/goduni/unissh/issues/new/choose>

Please include your component, OS/platform, how you installed it, the commit SHA or
tag, what happened vs. what you expected, repro steps, and scrubbed logs. The form
prompts for all of this. Searching [existing issues](https://github.com/goduni/unissh/issues)
first saves everyone time.

Want to fix it yourself? See [`CONTRIBUTING.md`](CONTRIBUTING.md) — contributions of all
sizes are welcome.

## 4. Security issues → report privately, never in public

> [!CAUTION]
> **Do not** open a public issue, PR, or discussion for a suspected vulnerability —
> that discloses it before a fix exists.

Report it privately:

- Email **uni@goduni.me**, or
- Use GitHub's private ["Report a vulnerability"](https://github.com/goduni/unissh/security/advisories/new) advisory form.

The full disclosure policy, scope, and what to expect are in
[`SECURITY.md`](SECURITY.md).

---

**Quick reference**

| I want to… | Go to |
| --- | --- |
| Solve a common problem | [Docs](https://goduni.github.io/unissh/) + [README FAQ](https://github.com/goduni/unissh#faq--troubleshooting) |
| Ask a question / get setup help / share an idea | [GitHub Discussions](https://github.com/goduni/unissh/discussions) |
| Report a reproducible bug | [New issue](https://github.com/goduni/unissh/issues/new/choose) |
| Report a security vulnerability (private) | uni@goduni.me or the [advisory form](https://github.com/goduni/unissh/security/advisories/new) |
| Contribute code or docs | [`CONTRIBUTING.md`](CONTRIBUTING.md) |
