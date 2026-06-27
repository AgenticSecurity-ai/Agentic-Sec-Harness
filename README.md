# Agentic-Sec-Harness

A catalog of **self-contained OpenClaw harnesses** for AI security. Each harness is
an independently deployable unit — see the [Harnesses](#harnesses) table below, and
each harness's own `README.md` for what it does and how to deploy it.

Built on [OpenClaw](https://openclaw.ai). Designed for **self-hosting**: clone a
harness into your own OpenClaw, supply your own credentials, and run it.

## Harnesses

| Harness | Source | What it does |
| ------- | ------ | ------------ |
| [`aisec-arxiv-monitor`](harnesses/aisec-arxiv-monitor/) | arXiv (AI-security) | Posts new AI-security papers, classified and summarized, to Discord |
| [`aisec-news-monitor`](harnesses/aisec-news-monitor/) | The Hacker News (RSS) | Filters a general security-news feed to AI-security stories, summarized, to Discord |

See each harness's own `README.md` for what it watches and how to deploy it.
_(More harnesses will be added under `harnesses/`.)_

## Design principles

Every harness in this repo follows the same shape:

- **Self-contained.** Each `harnesses/<name>/` directory is a complete OpenClaw
  workspace. Use one without the others — clone or copy just that folder.
- **No secrets in the repo.** Discord tokens and model credentials live in your
  OpenClaw config / credential chain, never in a harness directory.
- **Security-first execution (profile "B2").** The LLM that reads untrusted source
  content runs as a **tool-less text transform** (`minimal` profile). A separate
  orchestrator does all privileged work (fetch / post / ledger) in deterministic
  code, so an indirect prompt injection in fetched content cannot drive actions.
- **Idempotent.** A per-harness dedup ledger (`state/seen.json`, git-ignored) means
  no reposts and no silent loss on failure.
- **Respectful of sources.** Rate limits and required attributions are enforced in
  code, not left to the operator.

## Getting started

1. **First time on this host?** Do the one-time host bootstrap (model provider +
   credentials, Discord bot + channel, operator scope):
   **[docs/HOST-SETUP.md](docs/HOST-SETUP.md)**.
2. **Then deploy a harness** — each has its own `README.md` with setup and important
   notes for running it in your own OpenClaw:
   - [aisec-arxiv-monitor/README.md](harnesses/aisec-arxiv-monitor/README.md)
   - [aisec-news-monitor/README.md](harnesses/aisec-news-monitor/README.md)

General prerequisites: an OpenClaw install with a running gateway, a configured text
model (Bedrock/Claude-class or any OpenClaw text model), a Discord bot, and Python
3.11+ on the host.

## Repository layout

```
Agentic-Sec-Harness/
├── README.md            ← this catalog
├── CLAUDE.md            ← orientation for agents working in this repo
├── LICENSE              ← AGPLv3
├── CLA.md               ← contributor license agreement
├── .gitignore
├── docs/
│   └── HOST-SETUP.md    ← one-time host bootstrap (provider + creds, Discord, scope)
└── harnesses/
    └── <name>/          ← each is a self-contained OpenClaw workspace;
                           see its own README.md for layout and setup
```

## License

Agentic-Sec-Harness is licensed under the **GNU Affero General Public License
v3.0 (AGPLv3)** — see [LICENSE](LICENSE). Network use counts as distribution: if
you run a modified version as a hosted service, you must make your modified
source available to its users under the same license.

Contributions are accepted under the **Contributor License Agreement** in
[CLA.md](CLA.md). Contributors keep ownership of their work and grant the project
the right to relicense it, which keeps a future **commercial / dual-license**
offering possible. For commercial licensing inquiries, contact the maintainer at
[takaesu235@gmail.com](mailto:takaesu235@gmail.com).
