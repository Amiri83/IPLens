// IP List live filter: typing in Search or changing a filter reloads only the results
// (GET /ips/rows with the form's fields) and keeps the URL in sync; one clear (x) control.
(function () {
  "use strict";
  var form = document.getElementById("ip-filter");
  var results = document.getElementById("ip-results");
  var q = document.getElementById("q");
  var clear = document.getElementById("q-clear");
  if (!form || !results || !q || !window.fetch) return;
  var DELAY_MS = 200;
  var timer = null;
  var pending = null;

  function params() {
    var out = new URLSearchParams();
    new FormData(form).forEach(function (value, key) {
      if (value !== "") out.append(key, value);
    });
    return out.toString();
  }

  function refresh() {
    clearTimeout(timer);
    clear.hidden = q.value === "";
    var query = params();
    if (pending) pending.abort();
    pending = window.AbortController ? new AbortController() : null;
    fetch(form.dataset.rowsUrl + (query ? "?" + query : ""), {
      headers: { Accept: "text/html" },
      signal: pending ? pending.signal : undefined,
    })
      .then(function (resp) {
        if (!resp.ok) throw new Error("HTTP " + resp.status);
        return resp.text();
      })
      .then(function (html) {
        results.innerHTML = html;
        history.replaceState(null, "", form.action + (query ? "?" + query : ""));
      })
      .catch(function (err) {
        if (err.name !== "AbortError") form.submit(); // fall back to a full page load
      });
  }

  function later() {
    clearTimeout(timer);
    timer = setTimeout(refresh, DELAY_MS);
  }

  form.addEventListener("input", function (ev) {
    if (ev.target.tagName === "INPUT") later();
  });
  form.addEventListener("change", function (ev) {
    // The VPC dropdown reloads the page itself (the subnet choices depend on it).
    if (ev.target.tagName === "SELECT" && ev.target.id !== "vpc") refresh();
  });
  form.addEventListener("submit", function (ev) {
    if (ev.submitter && ev.submitter.hasAttribute("formaction")) return; // Export to Excel
    ev.preventDefault();
    refresh();
  });
  clear.addEventListener("click", function () {
    q.value = "";
    refresh();
    q.focus();
  });
  q.addEventListener("keydown", function (ev) {
    if (ev.key === "Escape" && q.value !== "") {
      ev.preventDefault();
      clear.click();
    }
  });
})();
