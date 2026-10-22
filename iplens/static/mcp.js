// MCP server status: while it is starting (or on Settings → MCP server), poll
// /mcp/status and update the header badge and the status table in place.
(function () {
  "use strict";
  var badge = document.getElementById("mcp-badge");
  var section = document.getElementById("mcp");
  var state = document.getElementById("mcp-state");
  var source = section || badge;
  if (!source) return;
  var url = source.getAttribute("data-status-url");
  var CLASSES = { running: "ok", starting: "warn", error: "err" };

  function paint(el, s, text) {
    el.classList.remove("ok", "warn", "err");
    if (CLASSES[s.state]) el.classList.add(CLASSES[s.state]);
    el.textContent = text;
  }

  function update(s) {
    if (badge) {
      paint(badge, s, "MCP " + s.state + (s.remote && s.state !== "stopped" ? " · remote" : ""));
      badge.title = "MCP server: " + s.state + (s.url ? " · " + s.url : "") +
        (s.last_error ? " · " + s.last_error : "");
    }
    if (state) paint(state, s, s.state);
    if (section) {
      section.querySelectorAll("[data-mcp-field]").forEach(function (el) {
        var v = s[el.getAttribute("data-mcp-field")];
        el.textContent = v === null || v === undefined || v === "" ? "—" : v;
      });
    }
    return s.state;
  }

  function poll() {
    fetch(url, { headers: { Accept: "application/json" }, credentials: "same-origin" })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (s) {
        if (!s) return;
        var st = update(s);
        // Keep polling while starting; on the Settings page also for uptime / crashes.
        if (st === "starting" || (section && st !== "stopped")) setTimeout(poll, st === "starting" ? 1000 : 5000);
      })
      .catch(function () {});
  }

  var initial = (badge && badge.getAttribute("data-state")) || (state && state.textContent);
  if (initial === "starting" || (section && initial !== "stopped")) setTimeout(poll, 1000);
})();
