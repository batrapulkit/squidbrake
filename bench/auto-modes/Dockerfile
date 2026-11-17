# A throwaway machine with three terminal coding agents and Squidbrake from PyPI.
# See README.md next to this file. Nothing from your computer goes in: API keys are passed when you run it.
FROM node:22-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends python3 python3-venv pipx git curl \
    && rm -rf /var/lib/apt/lists/*
RUN npm install -g @anthropic-ai/claude-code @openai/codex @google/gemini-cli

# Claude Code refuses --dangerously-skip-permissions as root, and agents behave differently as root anyway
RUN useradd -m bench
USER bench
WORKDIR /home/bench
ENV PATH=/home/bench/.local/bin:$PATH

ARG SQUIDBRAKE_VERSION=
RUN pipx install "squidbrake${SQUIDBRAKE_VERSION:+==$SQUIDBRAKE_VERSION}"

COPY --chown=bench run.sh mock_model.py /home/bench/
CMD ["bash", "/home/bench/run.sh"]
