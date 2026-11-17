// Book a call: Calendly opens on this page (its popup), with the name and email from the demo form when they're
// filled in; when a time is booked, squidbrake.com saves it and sends you a message. If Calendly can't load, the
// link opens as before.
(function () {
  let widget;
  const load = () => widget ||= new Promise((ok, fail) => {
    const css = document.createElement("link");
    css.rel = "stylesheet"; css.href = "https://assets.calendly.com/assets/external/widget.css";
    document.head.append(css);
    const js = document.createElement("script");
    js.src = "https://assets.calendly.com/assets/external/widget.js";
    js.onload = ok; js.onerror = fail;
    document.head.append(js);
  });
  const val = (id) => (document.getElementById(id)?.value || "").trim();

  document.addEventListener("click", async (e) => {
    const a = e.target.closest('a[href^="https://calendly.com/"]');
    if (!a || e.metaKey || e.ctrlKey) return;
    e.preventDefault();
    try {
      await load();
      const prefill = { name: val("wlName"), email: val("wlEmail") };
      window.Calendly.initPopupWidget({ url: a.href, prefill: prefill.email ? prefill : {} });
    } catch { window.open(a.href, "_blank", "noopener"); }
  });

  addEventListener("message", (e) => {
    if (e.origin !== "https://calendly.com" || !e.data || e.data.event !== "calendly.event_scheduled") return;
    const p = e.data.payload || {};
    fetch("/v1/booking", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({
      event: p.event?.uri || "", invitee: p.invitee?.uri || "", page: location.pathname,
      name: val("wlName"), email: val("wlEmail"), company: val("wlCompany") }) }).catch(() => {});
  });
})();
