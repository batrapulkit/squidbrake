# The same agent tool calls through three guards, each as a Claude Code PreToolUse hook would see them.
# Build from the repo root:  docker build -f bench/compare/Dockerfile -t squidbrake-compare .
FROM node:22-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends python3 python3-venv xz-utils git curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# destructive_command_guard (dcg), a pinned release, checked against its published sha256
ARG DCG_VERSION=v0.15.2
RUN cd /tmp && curl -fsSLO "https://github.com/Dicklesworthstone/destructive_command_guard/releases/download/${DCG_VERSION}/dcg-x86_64-unknown-linux-musl.tar.xz" \
    && curl -fsSLO "https://github.com/Dicklesworthstone/destructive_command_guard/releases/download/${DCG_VERSION}/dcg-x86_64-unknown-linux-musl.tar.xz.sha256" \
    && sha256sum -c dcg-x86_64-unknown-linux-musl.tar.xz.sha256 \
    && tar -xJf dcg-x86_64-unknown-linux-musl.tar.xz && install "$(find /tmp -name dcg -type f | head -1)" /usr/local/bin/dcg \
    && rm -rf /tmp/dcg* && dcg --version

# Microsoft Agent Governance Toolkit: its Claude Code plugin (hook + default policy), pinned commit
ARG AGT_COMMIT=c3e8229dfb19c697468cfb790495d7174ef8bc45
ENV AGT_COMMIT=${AGT_COMMIT}
RUN git init /opt/agt && cd /opt/agt && git remote add origin https://github.com/microsoft/agent-governance-toolkit \
    && git sparse-checkout set agent-governance-claude-code && git fetch --depth 1 origin ${AGT_COMMIT} \
    && git checkout -q FETCH_HEAD && cd agent-governance-claude-code && npm ci --omit=dev --ignore-scripts --no-audit --no-fund

# Squidbrake, from this checkout (the decision engine and the incident scenarios CI already replays)
WORKDIR /sb
COPY requirements.txt .
RUN python3 -m venv /venv && /venv/bin/pip install -q --no-cache-dir -r requirements.txt
COPY server.py commands.py taint.py verify.py pilot.py rules.yaml dashboard.html approve.html ./
COPY squidbrake/__init__.py squidbrake/__init__.py
COPY incidents/ incidents/
COPY bench/compare/compare.py ./
CMD ["/venv/bin/python", "compare.py"]
