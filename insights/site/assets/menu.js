// The phone menu. On narrow screens each page's own CSS hides the header links (all but "Try now"); this adds a
// Menu button next to what's left, which opens every link of that nav as a panel. On wide screens, where nothing is
// hidden, it adds nothing. One file for every page, so the pages keep their own header markup and breakpoints.
(function () {
  "use strict";
  // the site pages: header > nav · the home page: .nav-links (hero and the bar that follows you) · /signup: nav .links
  var NAVS = "header > nav[aria-label='Site'], header > nav[aria-label='Docs'], nav.nav-links, body > .wrap > nav .links";
  var css = document.createElement("style");
  css.textContent =
    ".sbm-btn{display:none;align-items:center;gap:7px;min-height:40px;padding:0 12px;margin-left:4px;border:1px solid currentColor;" +
    "border-radius:999px;background:none;color:inherit;font-family:inherit;font-size:.9rem;font-weight:500;line-height:1;cursor:pointer;opacity:.85;order:99;flex:none;white-space:nowrap;-webkit-tap-highlight-color:transparent}" +
    ".sbm-btn.on{display:inline-flex}.sbm-btn i{display:grid;gap:3px;width:14px}.sbm-btn i b{display:block;height:1.5px;background:currentColor;border-radius:2px}" +
    ".sbm-btn:focus-visible{outline:2px solid #F2622E;outline-offset:2px}" +
    ".sbm-panel{position:fixed;inset:0;z-index:1000;display:none}.sbm-panel.open{display:block}" +
    ".sbm-panel .sbm-shade{position:absolute;inset:0;background:rgba(10,14,12,.45)}" +
    ".sbm-panel .sbm-sheet{position:absolute;top:8px;left:8px;right:8px;max-height:calc(100% - 16px);overflow:auto;padding:8px 8px 12px;" +
    "border-radius:16px;background:var(--surface,#F4F6F1);color:var(--ink,#1E2A23);box-shadow:0 24px 60px rgba(0,0,0,.35),inset 0 0 0 1px var(--line,#C9D2C5)}" +
    ".sbm-top{display:flex;justify-content:space-between;align-items:center;padding:6px 8px 6px 12px;font:500 .78rem var(--mono,ui-monospace,monospace);" +
    "letter-spacing:.08em;text-transform:uppercase;color:var(--muted,#56625A)}" +
    ".sbm-x{min-width:44px;min-height:44px;border:0;background:none;color:inherit;font-size:1.5rem;line-height:1;cursor:pointer}" +
    ".sbm-sheet a{display:flex;align-items:center;min-height:48px;padding:0 12px;border-radius:10px;color:inherit;text-decoration:none;" +
    "font:500 1.08rem var(--sans,system-ui,sans-serif)}.sbm-sheet a:active,.sbm-sheet a:focus-visible{background:var(--soft,rgba(127,127,127,.14));outline:none}" +
    ".sbm-sheet a.sbm-cta{justify-content:center;margin-top:8px;background:#F2622E;color:#1E2A23;font-weight:600}" +
    "html.sbm-lock{overflow:hidden}" +
    "@media (max-width:380px){.sbm-btn{padding:0 12px}.sbm-btn span{display:none}}";   // the smallest phones: the icon alone
  document.head.appendChild(css);

  var panel, sheet, lastBtn;
  function close() {
    if (!panel || !panel.classList.contains("open")) return;
    panel.classList.remove("open"); document.documentElement.classList.remove("sbm-lock");
    if (lastBtn) { lastBtn.setAttribute("aria-expanded", "false"); lastBtn.focus(); }
  }
  function open(nav, btn) {
    if (!panel) {
      panel = document.createElement("div"); panel.className = "sbm-panel"; panel.id = "sbm-panel";
      panel.innerHTML = '<div class="sbm-shade"></div><div class="sbm-sheet" role="dialog" aria-modal="true" aria-label="Menu">' +
        '<div class="sbm-top"><span>Menu</span><button type="button" class="sbm-x" aria-label="Close menu">×</button></div><div class="sbm-list"></div></div>';
      document.body.appendChild(panel); sheet = panel.querySelector(".sbm-sheet");
      panel.querySelector(".sbm-shade").addEventListener("click", close);
      panel.querySelector(".sbm-x").addEventListener("click", close);
      panel.addEventListener("click", function (e) { if (e.target.closest && e.target.closest(".sbm-list a")) close(); });
      document.addEventListener("keydown", function (e) {
        if (!panel.classList.contains("open")) return;
        if (e.key === "Escape") return close();
        if (e.key === "Tab") {   // keep focus inside the panel
          var f = sheet.querySelectorAll("a,button"), a = f[0], z = f[f.length - 1];
          if (e.shiftKey && document.activeElement === a) { e.preventDefault(); z.focus(); }
          else if (!e.shiftKey && document.activeElement === z) { e.preventDefault(); a.focus(); }
        }
      });
    }
    var list = panel.querySelector(".sbm-list"); list.textContent = "";
    var links = links_(nav), cta = null;
    links.forEach(function (a) {
      var c = a.cloneNode(true); c.className = ""; c.removeAttribute("style"); c.removeAttribute("aria-current");
      // a link the page wired up itself (e.g. "Book a demo" opens a form): a copy has no listener, so pass the tap on
      if (Object.keys(a.dataset).length) c.addEventListener("click", function (e) { e.preventDefault(); close(); a.click(); });
      if (/\/signup/.test(a.getAttribute("href") || "")) { c.className = "sbm-cta"; cta = c; return; }
      list.appendChild(c);
    });
    if (cta) list.appendChild(cta);
    lastBtn = btn; btn.setAttribute("aria-expanded", "true");
    panel.classList.add("open"); document.documentElement.classList.add("sbm-lock");
    var first = list.querySelector("a"); if (first) first.focus();
  }
  function links_(nav) { return Array.prototype.slice.call(nav.querySelectorAll("a")).filter(function (a) { return !a.classList.contains("sbm-btn"); }); }
  function hidden(a) { return getComputedStyle(a).display === "none"; }

  var navs = Array.prototype.slice.call(document.querySelectorAll(NAVS));
  navs.forEach(function (nav) {
    var btn = document.createElement("button");
    btn.type = "button"; btn.className = "sbm-btn"; btn.setAttribute("aria-haspopup", "dialog");
    btn.setAttribute("aria-expanded", "false"); btn.setAttribute("aria-controls", "sbm-panel");
    btn.setAttribute("aria-label", "Menu");
    btn.innerHTML = '<i aria-hidden="true"><b></b><b></b><b></b></i><span>Menu</span>';
    btn.addEventListener("click", function () { open(nav, btn); });
    nav.insertBefore(btn, nav.firstChild);   // first in the markup (pages hide a:not(:last-child)), last on screen (order)
    nav._sbmBtn = btn;
  });
  function sync() {
    navs.forEach(function (nav) { nav._sbmBtn.classList.toggle("on", links_(nav).some(hidden)); });
    if (panel && panel.classList.contains("open") && !(lastBtn && lastBtn.classList.contains("on"))) close();
  }
  sync();
  window.addEventListener("resize", sync);
})();
