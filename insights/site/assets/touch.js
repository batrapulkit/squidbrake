/* Where a visitor first came from, kept in this browser only until they sign up or ask for a demo, which sends it
   (app.py, _attribution): the link's utm tags and ?from= word, the site that sent them (no query string) and the
   first page they opened. A later visit replaces it only when the kept one says nothing about where they came from.
   No cookies, nothing sent on its own. */
(function () {
  "use strict";
  var KEY = "sb_first_touch";
  function read() { try { return JSON.parse(localStorage.getItem(KEY) || "null"); } catch (e) { return null; } }
  window.sbFirstTouch = read;
  try {
    var q = new URLSearchParams(location.search), t = {};
    ["utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content"].forEach(function (k) {
      var v = q.get(k); if (v) t[k] = v.slice(0, 150);
    });
    var from = q.get("from") || q.get("ref");
    if (from) t.from = from.toLowerCase().replace(/[^a-z0-9-]/g, "").slice(0, 30);
    if (document.referrer) {
      var r = new URL(document.referrer);
      if (r.host !== location.host) t.referrer = r.origin + r.pathname;
    }
    var had = read(), says = function (x) { return x && (x.utm_source || x.from || x.referrer); };
    if (had && (says(had) || !says(t))) return;
    t.landing = location.pathname;
    t.first_seen = new Date().toISOString();
    localStorage.setItem(KEY, JSON.stringify(t));
  } catch (e) {}
})();
