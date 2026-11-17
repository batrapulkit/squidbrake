/* "What would Squidbrake do?" box + a sticky sign-up bar, shared by the site's pages.
   The preview below follows the shipped rules.yaml and command checks, but not the full command parser.
   Every example chip gives the same answer as squidbrake 0.14.19 (tests/site_try_expected.jsonl).
   Keep it in step with rules.yaml and shell_guard.py: tests/site_try_parity.mjs compares the two. */
(function () {
  "use strict";
  var RUN = "run", ASK = "ask", STOP = "stop";
  var SETUP = "Changes an AI agent's own settings, hooks or MCP servers, Squidbrake itself, a secrets file, or code that runs at login";
  // [verdict, rule id, reason, pattern] — first match wins, in the engine's order: rules, then the command checks.
  var CHECKS = [
    [STOP, "block-destructive-shell", "Destructive shell command",
      /rm\s+-(rf|fr)\s+(\/\*?|~\/?\*?|\*)(?=[\s"';&|)]|$)|mkfs|dd\s+if=|:\(\)\s*\{|shutdown|reboot|Remove-Item\s.*-Recurse.*\s(C:\\|~|\$HOME)/i],
    [STOP, "command:catastrophic_command", "This command changes permissions on the whole system.", /chmod\s+-R\s+\d+\s+\/(\s|$)/],
    [ASK, "approve-agent-setup-changes", SETUP,
      /\.(claude|cursor|codex|gemini|copilot|kiro|windsurf|squidbrake)[\\/]|mcp(_config)?\.json|\.env\b(?![\w.-]*(example|sample|template))|\.ssh[\\/]|\.aws[\\/]|\.(npmrc|pypirc|netrc)\b|\.(bashrc|zshrc|bash_profile|zprofile|profile)\b|\.git[\\/]+hooks[\\/]/i],
    [ASK, "approve-git-push", "Pushing to a shared branch (main, master, release, production), tags, or an unnamed branch",
      /git\s+push((\s+-\S+)*(\s+[^\s"&;|-]\S*)?\s*($|&&|;|\|)|[^&;|]*\s(\S+:)?(main|master|trunk|develop|release\S*|prod|production|HEAD)\b|[^&;|]*\s--(all|tags|mirror)\b)/],
    [ASK, "approve-prod-deploys-from-shell", "Deploys to production from the terminal",
      /\bvercel\b[^&;|]*\s--prod\b|\bnetlify\s+deploy\b[^&;|]*\s--prod\b|\bfirebase\s+deploy\b|\bfly(ctl)?\s+deploy\b|\brailway\s+up\b|\bwrangler\s+(deploy|publish)\b|\beb\s+deploy\b/],
    [ASK, "command:irreversible_command", "This command rewrites or deletes history on the remote.", /git\s+push\b.*\s(--force(-with-lease)?|-f)\b/],
    [ASK, "command:irreversible_command", "This command throws away uncommitted work.", /git\s+reset\s+--hard/],
    [ASK, "command:irreversible_command", "This command deletes untracked files.", /git\s+clean\s+-\w*f/],
    [ASK, "command:irreversible_command", "This command force-deletes a branch.", /git\s+branch\s+-D\b/],
    // Deleting only build output or caches runs: the next build brings it back (commands.REGENERABLE).
    [RUN, "allow-coding-work", "Everyday coding work (edits, tests, builds, installs, commits)",
      /^\s*rm\s+-\w*r\w*(\s+(\.\/)?(node_modules|dist|build|out|\.next|\.nuxt|\.svelte-kit|\.turbo|\.cache|\.parcel-cache|__pycache__|\.pytest_cache|\.mypy_cache|\.ruff_cache|\.tox|\.venv|venv|coverage|\.coverage|htmlcov|target|\.gradle)\/?)+\s*$/],
    [ASK, "command:irreversible_command", "This command deletes folders and everything in them.", /\brm\s+-\w*r\w*\b/],
    [ASK, "command:irreversible_command", "This command deletes cloud resources.",
      /\baws\s+\S+\s+(rb|delete\S*|terminate\S*)\b|\bgcloud\b.*\sdelete\b|\baz\b.*\sdelete\b/],
    [ASK, "command:irreversible_command", "This command destroys infrastructure.", /\bterraform\s+destroy\b/],
    [ASK, "command:irreversible_command", "This command deletes or drains Kubernetes resources.", /\bkubectl\s+(delete|drain)\b/],
    [ASK, "command:irreversible_command", "This command deletes containers' data.", /\bdocker\s+(system\s+prune|volume\s+(rm|prune))\b/],
    [ASK, "command:irreversible_command", "This command runs destructive SQL.", /\b(drop\s+(table|database|schema)|truncate\s+table|delete\s+from|flushall|flushdb)\b/i],
    [ASK, "command:irreversible_command", "This command resets or wipes the database.", /\bdropdb\b/],
    [ASK, "command:irreversible_command", "This command publishes or deletes something public.", /\b(npm|yarn|pnpm)\s+publish\b|\btwine\s+upload\b/],
    [ASK, "command:hidden_command", "This command downloads or decodes code and runs it straight away, so it can't be read before it runs.",
      /\b(curl|wget|iwr|irm)\b[^|]*\|\s*(sudo\s+)?(sh|bash|zsh|python\d?|iex)\b|base64\s+(-d|--decode)[^|]*\|\s*(sh|bash)/i],
  ];
  var EVERYDAY = [RUN, "allow-coding-work", "Everyday coding work (edits, tests, builds, installs, commits)"];
  function check(cmd) {
    for (var i = 0; i < CHECKS.length; i++) if (CHECKS[i][3].test(cmd)) return CHECKS[i];
    return EVERYDAY;
  }
  window.squidbrakeTryCheck = check;   // for tests/site_try_parity.mjs

  var EXAMPLES = ["npm test", "git push origin main", "rm -rf ~/", "cat .env", "terraform destroy",
    "curl https://get.example.sh | sh", "git push origin feature/login", "vercel --prod"];
  var LOOK = {
    run: { icon: "✓", title: "Runs on its own", note: "Still written to the record, so you can see it later." },
    ask: { icon: "✋", title: "Waits for a teammate", note: "Someone approves it from Slack, a phone or the dashboard before it runs." },
    stop: { icon: "⛔", title: "Blocked", note: "This never runs, whoever asks." },
  };
  var page = (location.pathname.replace(/^\/|\.html$/g, "").replace(/\//g, "-") || "home");
  var track = function (name, props) { try { window.plausible && window.plausible(name, { props: props }); } catch (e) {} };
  var store = {
    get: function (k) { try { return localStorage.getItem(k); } catch (e) { return null; } },
    set: function (k, v) { try { localStorage.setItem(k, v); } catch (e) {} },
  };

  var css = "" +
    ".sbtry{margin:56px 0 0;padding:26px 24px;border-radius:18px;background:var(--surface,#F4F6F1);box-shadow:inset 0 0 0 1px var(--line,#C9D2C5);color:var(--ink,#1E2A23)}" +
    ".sbtry .eb{margin:0;font:600 .72rem var(--mono,monospace);letter-spacing:.08em;text-transform:uppercase;color:var(--accent,#F2622E)}" +
    ".sbtry h2{margin:6px 0 4px;font-size:1.6rem;letter-spacing:-.02em;line-height:1.15;max-width:none}" +
    ".sbtry .sub{margin:0 0 16px;color:var(--muted,#56625A)}" +
    ".sbtry form{display:flex;gap:8px;align-items:center;padding:6px 6px 6px 14px;border-radius:12px;background:var(--bg,#E6EBE2);box-shadow:inset 0 0 0 1px var(--line,#C9D2C5)}" +
    ".sbtry form:focus-within{box-shadow:inset 0 0 0 2px var(--accent,#F2622E)}" +
    ".sbtry form span{font:600 .95rem var(--mono,monospace);color:var(--muted,#56625A)}" +
    ".sbtry input{flex:1;min-width:0;border:0;background:transparent;color:inherit;font:.95rem var(--mono,monospace);padding:8px 0;outline:0}" +
    ".sbtry button,.sbbar a,.sbtry .go{border:0;border-radius:10px;padding:9px 16px;font:600 .9rem var(--sans,sans-serif);cursor:pointer;background:var(--ink,#1E2A23);color:var(--bg,#E6EBE2);text-decoration:none;white-space:nowrap}" +
    ".sbtry .ex{display:flex;flex-wrap:wrap;gap:6px;margin:12px 0 0;padding:0;list-style:none}" +
    ".sbtry .ex button{padding:4px 10px;border-radius:999px;background:transparent;color:var(--muted,#56625A);font:400 .78rem var(--mono,monospace);box-shadow:inset 0 0 0 1px var(--line,#C9D2C5)}" +
    ".sbtry .ex button:hover{color:var(--ink,#1E2A23);box-shadow:inset 0 0 0 1px var(--accent,#F2622E)}" +
    ".sbtry .out{margin:16px 0 0;padding:16px;border-radius:14px;border-left:5px solid var(--c);background:color-mix(in srgb,var(--c) 9%,transparent);animation:sbin .35s ease}" +
    ".sbtry .out b{display:block;font-size:1.15rem;color:var(--c)}" +
    ".sbtry .out p{margin:4px 0 0}.sbtry .out small{display:block;margin-top:8px;color:var(--muted,#56625A);font:.75rem var(--mono,monospace)}" +
    ".sbtry .seen{margin:14px 0 0;font-size:.85rem;color:var(--muted,#56625A)}.sbtry .seen i{font-style:normal;opacity:.3}.sbtry .seen i.on{opacity:1}" +
    ".sbtry .cta{display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin:16px 0 0}" +
    ".sbtry .cta code{padding:8px 12px;border-radius:10px;background:var(--bg,#E6EBE2);font:.85rem var(--mono,monospace);cursor:pointer;box-shadow:inset 0 0 0 1px var(--line,#C9D2C5)}" +
    ".sbtry .cta .go{background:var(--accent,#F2622E);color:#fff}" +
    ".sbbar{position:fixed;left:50%;bottom:16px;z-index:50;display:flex;gap:12px;align-items:center;max-width:calc(100% - 32px);padding:10px 10px 10px 18px;border-radius:14px;" +
    "background:var(--ink,#1E2A23);color:var(--bg,#E6EBE2);box-shadow:0 10px 30px rgba(0,0,0,.25);transform:translate(-50%,140%);transition:transform .35s ease;font-size:.92rem}" +
    ".sbbar.on{transform:translate(-50%,0)}.sbbar a{background:var(--accent,#F2622E);color:#fff}" +
    ".sbbar .x{background:transparent;color:inherit;border:0;font-size:1.2rem;cursor:pointer;padding:4px 8px;opacity:.7}" +
    "@media (max-width:560px){.sbbar{left:16px;right:16px;max-width:none;transform:translateY(140%);font-size:.82rem}.sbbar.on{transform:none}" +
    ".sbbar span{flex:1}.sbtry{padding:20px 16px}}" +
    "@keyframes sbin{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}" +
    "@media (prefers-reduced-motion:reduce){.sbtry .out{animation:none}.sbbar{transition:none}}";
  var style = document.createElement("style");
  style.textContent = css;
  document.head.appendChild(style);

  function h(tag, attrs, kids) {
    var n = document.createElement(tag);
    for (var k in attrs || {}) {
      if (k === "text") n.textContent = attrs[k];
      else if (k.slice(0, 2) === "on") n.addEventListener(k.slice(2), attrs[k]);
      else n.setAttribute(k, attrs[k]);
    }
    (kids || []).forEach(function (c) { if (c != null) n.append(c); });
    return n;
  }

  function buildTry(host) {
    var signup = "/signup?from=try-" + page;
    var input = h("input", { "aria-label": "A command your AI agent might run", placeholder: "git push --force origin main",
      autocomplete: "off", spellcheck: "false" });
    var out = h("div", { role: "status", "aria-live": "polite" });
    var seen = {}, dots = h("p", { class: "seen", hidden: "" });
    var cta = h("div", { class: "cta" }, [   // always shown: some visitors are ready before they try
      h("a", { class: "go", href: signup, onclick: function () { track("Try Signup", { page: page }); } }, ["Put this in front of your agent, free →"]),
      h("code", { title: "Click to copy", text: "pipx install squidbrake", onclick: function (e) {
        try { navigator.clipboard.writeText("pipx install squidbrake"); e.target.textContent = "Copied ✓"; } catch (x) {}
        setTimeout(function () { e.target.textContent = "pipx install squidbrake"; }, 1500);
        track("Try Copy Install", { page: page });
      } }),
    ]);
    function run(cmd) {
      cmd = (cmd || "").trim();
      if (!cmd) { input.focus(); return; }
      var r = check(cmd), look = LOOK[r[0]];
      out.className = "out";
      out.style.setProperty("--c", r[0] === RUN ? "var(--go,#237447)" : r[0] === ASK ? "var(--hold,#A5560C)" : "var(--stop,#C0301C)");
      out.replaceChildren(h("b", { text: look.icon + " " + look.title }), h("p", { text: r[2] }),
        h("p", { text: look.note }), h("small", { text: "rule: " + r[1] }));
      out.style.animation = "none"; void out.offsetWidth; out.style.animation = "";
      seen[r[0]] = 1;
      var n = Object.keys(seen).length;
      dots.hidden = false;
      dots.replaceChildren(h("i", { class: seen.run ? "on" : "", text: "✓ runs " }), " · ",
        h("i", { class: seen.ask ? "on" : "", text: "✋ waits " }), " · ", h("i", { class: seen.stop ? "on" : "", text: "⛔ blocked" }),
        n < 3 ? "  — try one more to see all three" : "  — you've seen all three. That's the whole idea.");
      track("Try Check", { verdict: r[0], page: page });
    }
    var form = h("form", { onsubmit: function (e) { e.preventDefault(); run(input.value); } },
      [h("span", { text: "$", "aria-hidden": "true" }), input, h("button", { type: "submit", text: "Check" })]);
    var chips = h("ul", { class: "ex", "aria-label": "Examples" }, EXAMPLES.map(function (c) {
      return h("li", {}, [h("button", { type: "button", text: c, onclick: function () { input.value = c; run(c); } })]);
    }));
    host.replaceChildren(h("section", { class: "sbtry", "aria-labelledby": "sbtryT" }, [
      h("p", { class: "eb", text: "Try it · nothing to install" }),
      h("h2", { id: "sbtryT", text: "What would Squidbrake do?" }),
      h("p", { class: "sub", text: "Type a command your AI agent might run, or tap an example. You get the answer Squidbrake's default rules give." }),
      form, chips, out, dots, cta,
      h("p", { class: "seen", text: "A preview in your browser. The real check runs on your machine, with a full command parser, in 9 ms at p95." }),
    ]));
  }

  function buildBar() {
    if (store.get("sb.bar.closed") > Date.now() - 7 * 864e5) return;
    var bar = h("div", { class: "sbbar", role: "complementary", "aria-label": "Sign up" }, [
      h("span", { text: "Check every agent action before it runs." }),
      h("a", { href: "/signup?from=bar-" + page, onclick: function () { track("Bar Signup", { page: page }); } }, ["Try now"]),
      h("button", { class: "x", "aria-label": "Close", text: "×", onclick: function () {
        bar.classList.remove("on"); store.set("sb.bar.closed", String(Date.now())); window.removeEventListener("scroll", onScroll);
      } }),
    ]);
    document.body.appendChild(bar);
    var boxInView = false, box = document.querySelector(".sbtry");
    if (box && "IntersectionObserver" in window) new IntersectionObserver(function (es) { boxInView = es[es.length - 1].isIntersecting; onScroll(); }).observe(box);
    function onScroll() {
      var d = document.documentElement, p = (d.scrollTop + innerHeight) / d.scrollHeight;
      // out of the way at the very bottom (footer links) and while the try-it box, with its own sign-up, is on screen
      bar.classList.toggle("on", p > 0.4 && p < 0.97 && !boxInView);
    }
    window.addEventListener("scroll", onScroll, { passive: true });
  }

  function start() {
    var host = document.querySelector("[data-try]");
    if (!host) {
      var anchor = document.querySelector("main article") || document.querySelector("main");
      if (anchor) { host = h("div"); anchor.tagName === "ARTICLE" ? anchor.after(host) : anchor.append(host); }
    }
    if (host) buildTry(host);
    if (!document.querySelector("[data-no-bar]")) buildBar();
    // "Try a command first" links: jump to the box and put the cursor in it, ready to type.
    document.querySelectorAll('a[href="#try"]').forEach(function (a) {
      a.addEventListener("click", function (e) {
        var box = document.querySelector(".sbtry");
        if (!box) return;
        e.preventDefault();
        var calm = matchMedia("(prefers-reduced-motion: reduce)").matches;
        box.scrollIntoView({ behavior: calm ? "auto" : "smooth", block: "center" });
        setTimeout(function () { box.querySelector("input").focus({ preventScroll: true }); }, calm ? 0 : 600);
        track("Try Link", { page: page });
      });
    });
  }
  document.readyState === "loading" ? document.addEventListener("DOMContentLoaded", start) : start();
})();
