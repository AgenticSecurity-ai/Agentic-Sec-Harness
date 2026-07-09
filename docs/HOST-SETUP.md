# Host setup — preparing OpenClaw to run a harness

A **one-time, host-wide** bootstrap. Do this once per machine; all harnesses in this
repo then reuse it. After this, follow the per-harness `README.md` to deploy each
one.

Nothing here is secret-bearing in the repo: you run these on YOUR host with YOUR
credentials. No harness directory ever contains credentials.

> The default path below assumes **AWS Bedrock (Claude)** as the model and **Discord**
> as the output channel — what these harnesses are built for. Alternatives are noted.

> **Rebuilding after a wipe?** If this host was set up before and its runtime was lost
> (e.g. a WSL reset), don't redo this by hand — see [PERSISTENCE.md](PERSISTENCE.md) for
> the durability map and [`ops/bootstrap.sh`](../ops/bootstrap.sh), which re-derives the
> deterministic parts and tells you which secret steps still need you.

---

## 0. Prerequisites

- [OpenClaw](https://openclaw.ai) installed, with the gateway running:
  ```bash
  openclaw status          # gateway should be reachable
  ```
- Python 3.11+ on the host (harness scripts are stdlib-only).
- For the default model path: the **AWS CLI** and an AWS account with **Bedrock model
  access granted** for the Claude model you intend to use.

## 1. Model provider — AWS Bedrock (default)

### 1a. Install the Bedrock provider plugin

```bash
openclaw plugins install clawhub:@openclaw/amazon-bedrock-provider
openclaw gateway restart
openclaw plugins list | grep -i bedrock     # should show: amazon-bedrock ... enabled
```

### 1b. Provide AWS credentials (the credential chain — no key stored in OpenClaw)

Bedrock uses `auth: "aws-sdk"`, meaning OpenClaw stores **no** secret and resolves
credentials at run time via the standard AWS SDK chain (env vars → `~/.aws/` → IAM
role → SSO). Set up whichever you use; the simplest is a profile:

```bash
aws configure                 # writes ~/.aws/credentials + ~/.aws/config
aws sts get-caller-identity    # verify the identity resolves
```

Pick a region where your Claude inference profile is available and use it
consistently (the provider baseUrl and `~/.aws/config` region must match):

```bash
aws bedrock list-inference-profiles --region us-west-2 \
  --query 'inferenceProfileSummaries[?contains(inferenceProfileId,`claude`)].inferenceProfileId' --output text
```

### 1c. Register the provider in OpenClaw

Replace the region and model id to match what your account has access to:

```bash
openclaw config set 'models.providers.amazon-bedrock' '{
  "baseUrl": "https://bedrock-runtime.us-west-2.amazonaws.com",
  "api": "bedrock-converse-stream",
  "auth": "aws-sdk",
  "models": [
    {"id": "us.anthropic.claude-haiku-4-5-20251001-v1:0", "name": "Claude Haiku 4.5 (Bedrock)"}
  ]
}'
openclaw gateway restart
```

The model is then referenced as `amazon-bedrock/<model-id>`, e.g.
`amazon-bedrock/us.anthropic.claude-haiku-4-5-20251001-v1:0`. You can set it as the
default (`openclaw models set <ref>`) or pass it per-agent with `agents add --model`.

> **Note on `models status`:** Bedrock will show as `missing auth` because there is
> no stored API key — that is expected with `auth: "aws-sdk"`. The real test is an
> actual turn (step 3).

### 1d. Alternative: an API-key provider (OpenAI/Anthropic/etc.)

If you don't use Bedrock, configure that provider instead and store its key in the
host auth store (never in a harness):

```bash
openclaw models auth login --provider <provider>     # OAuth/device flow, or:
openclaw models auth paste-api-key                    # paste a key
```

Then use that provider's model ref in `agents add --model`.

## 2. Discord output channel

### 2a. Add the Discord bot

```bash
openclaw channels add discord        # guided; provide the bot token
```

(Create the bot + token in the Discord Developer Portal, invite it to your server
with permission to read/send in the target channel.)

### 2b. Find the target channel id

```bash
openclaw directory groups list --channel discord
```

(Or enable Discord Developer Mode → right-click the channel → Copy Channel ID.)

### 2c. Allow the bot to post in that channel

The bot only acts in allowlisted channels. Add yours (replace the ids):

```bash
openclaw config set 'channels.discord.guilds.<guildId>.channels.<channelId>' '{"enabled": true}'
openclaw gateway restart
```

## 3. Smoke-test the model

Confirm the gateway can actually run a turn against your model:

```bash
openclaw agent --agent main --message 'Reply with exactly: OK'
```

If this returns `OK`, the provider + credentials are working.

## 4. Operator scope for cron

Registering/managing cron jobs (used by every harness) requires an operator token
with the **`operator.admin`** scope.

- On most setups your primary operator already has it. If `openclaw cron add …`
  fails with `scope upgrade pending approval` / `pairing required: device is asking
  for more scopes`, the calling device needs the scope granted.
- Grant/approve it via the Control UI (dashboard) or `openclaw devices approve`.
  On a local loopback CLI that is stuck in a self-approval loop, you can grant the
  scope directly in `~/.openclaw/devices/paired.json` (add `operator.admin` to the
  device's `scopes`/`approvedScopes`/token scopes) while the gateway is stopped, then
  restart — back up the file first.

## 5. You're ready

The host now has: a working model provider + credentials, a Discord bot + allowed
channel, and operator scope for cron. Proceed to a harness and follow its
`README.md` (register the agent, lock it to the `minimal` tool profile, edit
`config.toml`, schedule cron):

- [aisec-arxiv-monitor](../harnesses/aisec-arxiv-monitor/README.md)
