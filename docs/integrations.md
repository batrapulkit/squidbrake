# Integrations

MCP servers, agents that connect by URL, Python frameworks, any language, and the HTTP proxy.

## Other ways to send calls through it

**Any MCP server** - put Squidbrake in front of it, in any MCP client. The agent sees the app's normal tools, and
each call is checked first (with `GATEWAY_URL` and `GATEWAY_API_KEY` set in the client's MCP config):

```bash
squidbrake proxy --app linear --url https://mcp.linear.app/mcp          # a remote MCP server
squidbrake proxy --app github --url https://api.githubcopilot.com/mcp/ --header 'Authorization: Bearer ${GITHUB_TOKEN}'
squidbrake proxy --app stripe -- npx -y @stripe/mcp --tools=all          # one started by a command
```

`squidbrake connect guard` does this for the servers your agents already use, including remote ones with their own
auth headers.

**Agents that connect to MCP by URL** (ChatGPT and claude.ai connectors, Devin, n8n, cloud agents) - easiest: in the
dashboard, **Settings → Agents that connect by URL**, add the app's MCP server (its URL, and the header its auth
needs). The agent then uses `https://<your gateway>/mcp/<name>` and signs in with one of its agent keys
(`Authorization: Bearer gw_...`, or `?key=gw_...` for apps that take only a URL). Every call is checked and recorded as
that agent; the app's own token stays on the gateway and is never shown again. Hosted dashboards take servers by URL;
servers started by a command need a self-hosted gateway with `SQUIDBRAKE_MCP_COMMANDS=1`.

Apps whose MCP server signs in only through a browser (OAuth: Slack, HubSpot, Notion, Asana, ClickUp, Grafana Cloud):
choose **Sign in to the app (OAuth)**, add it, click **Connect** and sign in once. The gateway keeps the session and
refreshes it before it runs out. Apps that only let in OAuth apps registered with them (Slack, HubSpot) need your own
OAuth app's client ID and secret, with the redirect URL the dashboard shows.

Or run the proxy yourself and serve it over HTTP. The agent adds `https://your-host:9000/mcp` as its MCP server and sends the token
(`Authorization: Bearer`, `X-Squidbrake-Token`, or `?token=` for clients that take only a URL):

```bash
squidbrake proxy --app github --serve 0.0.0.0:9000 --token "$PROXY_TOKEN" -- npx -y @modelcontextprotocol/server-github
```

Each connected conversation is checked on its own, so one agent's chain never mixes with another's. A caller can
name its conversation with an `X-Squidbrake-Session` header. Put HTTPS in front of it (Caddy, a tunnel) before
exposing it.

**Python agent frameworks** - OpenAI Agents SDK, LangChain / LangGraph, CrewAI, PydanticAI, smolagents, Google ADK:
put all of an agent's tools behind it in one line. A call Squidbrake stops doesn't run, and the model gets a
"NOT RUN: ..." message as the tool's result:

```python
from squidbrake.client import Gateway          # pip install squidbrake (or drop client.py into your project)
gw = Gateway("https://gateway.example.com", api_key="...", source="support-agent", session_id=run_id)

agent = Agent(name="support", tools=gw.guard_tools([lookup_order, refund, send_email]))   # OpenAI Agents SDK
graph = create_react_agent(llm, gw.guard_tools(tools))                                      # LangGraph
```

Or one function at a time (raises `Denied` when it's stopped):

```python
@gw.guard(name="shell.exec")
def shell_exec(command: str): ...
```

**Any language** - two HTTP calls (header `X-Gateway-Key: <secret>`):

```
POST /v1/events               {"name": "shell.exec", "input": {...}, "source": "...", "session_id": "..."}
  -> {"event_id": "...", "decision": "allow" | "deny", "reason": "...", "rule_id": ...}
POST /v1/events/{id}/result   {"output": ..., "error": null, "duration_ms": 12}
```

Record an action that already happened in one call by including `output`/`error` in the first POST.

**HTTP proxy** - no code changes: define `upstreams` in `rules.yaml`, then point the client at
`http://gateway:8080/proxy/<upstream>/...`. Optional headers: `X-Gateway-Source`, `X-Gateway-Session`.
Denied requests get `403`; every response carries `X-Gateway-Event-Id`.

## Notifications: Telegram Bot

Approval requests and plain text notifications can be delivered directly to Telegram with an **Open** button:

1. Open Telegram and talk to [@BotFather](https://t.me/BotFather).
2. Send `/newbot` and follow the prompts to name your bot and choose a username. Copy the API token provided.
3. Start a conversation with your new bot (or invite it to a group/channel). Send any test message to it.
4. Obtain your numeric chat ID by querying `https://api.telegram.org/bot<YOUR_BOT_TOKEN>/getUpdates` and inspecting the `message.chat.id` field.
5. Set the environment variables on the Squidbrake server:
   ```bash
   TELEGRAM_BOT_TOKEN="123456789:ABCdefGhIJKlmNoPQRsTUVwxyZ"
   TELEGRAM_CHAT_ID="987654321"
   ```
   Or configure `telegram_bot_token` and `telegram_chat_id` in dashboard Settings.

