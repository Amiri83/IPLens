/* IPLens background jobs: Refresh, the Extended view service crawl and Terraform sync.
   Forms marked data-job are posted with background=1; the server starts the job (one per
   account) and this script polls its state into the modal: current step, done / total,
   elapsed time, the live log tail and a Cancel button. A reload re-attaches to the
   account's running job; a job started from this tab and finished while the page was
   reloading is shown once more with its result. Without JavaScript the forms post
   normally and the job runs to the end before the page is redrawn.
   Hide is remembered by the server (session), so the box stays hidden on every page and
   tab while a small badge ("Discovery running…" for a Refresh) shows the job is still
   going; the badge reopens it. A Refresh also lists its resource types with their
   status and elapsed time against the per-resource timeout, the overall limit, and at
   the end the skipped ones with a "Retry skipped" button (a new Refresh of just those
   resource types, plus VPCs, subnets and ENIs). */
(function () {
  "use strict";

  const POLL_MS = 1000;
  const WATCH_KEY = "iplens-job-watch";  // sessionStorage: job started from this tab
  const modal = document.getElementById("job-modal");
  if (!modal) return;
  const $ = (id) => document.getElementById(id);
  const title = $("job-title");
  const stepEl = $("job-step");
  const bar = $("job-progress");
  const counts = $("job-counts");
  const elapsed = $("job-elapsed");
  const stateEl = $("job-state");
  const messages = $("job-messages");
  const logEl = $("job-log");
  const cancelBtn = $("job-cancel");
  const hideBtn = $("job-hide");
  const closeBtn = $("job-close");
  const badge = $("job-badge");
  const limitsEl = $("job-limits");
  const resourcesBox = $("job-resources-box");
  const resourcesEl = $("job-resources");
  const skippedBox = $("job-skipped");
  const skippedList = $("job-skipped-list");
  const retryBtn = $("job-retry");
  const csrf = modal.dataset.csrf;
  let jobId = null;
  let timer = null;
  let running = false;
  let skippedNames = [];  // resource types the last rendered Refresh skipped

  const url = (template, id) => template.replace("__ID__", encodeURIComponent(id));

  function fmtElapsed(s) {
    const m = Math.floor(s / 60);
    return m ? `${m}m ${s % 60}s` : `${s}s`;
  }

  function stateLabel(job) {
    if (job.running) return job.cancel_requested ? "cancelling (after the current step)" : "running";
    return { done: "finished", cancelled: "cancelled", error: "failed" }[job.state] || job.state;
  }

  function renderMessages(list) {
    messages.replaceChildren(...(list || []).map((m) => {
      const li = document.createElement("li");
      li.className = "flash " + (m.category || "");
      li.append(m.text);
      if (m.link_url) {
        const a = document.createElement("a");
        a.href = m.link_url;
        a.textContent = m.link_text || m.link_url;
        li.append(" ", a);
      }
      return li;
    }));
  }

  function fmtMinutes(s) {
    return `${Math.round(s / 60)} min`;
  }

  function renderLimits(job) {
    const limits = job.limits || {};
    limitsEl.hidden = !limits.resource;
    if (!limits.resource) return;
    const a = document.createElement("a");
    a.href = modal.dataset.settingsUrl;
    a.textContent = "change in Settings";
    limitsEl.replaceChildren(
      `Each resource times out after ${limits.resource}s; total limit ${fmtMinutes(limits.overall)} — `,
      a,
    );
  }

  function renderResources(job) {
    const items = job.items || [];
    resourcesBox.hidden = items.length === 0;
    resourcesEl.replaceChildren(...items.map((r) => {
      const tr = document.createElement("tr");
      tr.className = "res-" + r.status;
      const name = document.createElement("td");
      name.className = "mono";
      name.textContent = r.name;
      const status = document.createElement("td");
      status.textContent = r.reason ? `${r.status} (${r.reason})` : r.status;
      const time = document.createElement("td");
      time.textContent = r.status === "pending" ? "–" : `${r.elapsed}s / ${r.timeout}s`;
      tr.append(name, status, time);
      return tr;
    }));
    const skipped = items.filter((r) => r.status === "skipped");
    skippedNames = skipped.map((r) => r.name);
    skippedBox.hidden = running || skipped.length === 0;
    skippedList.replaceChildren(...skipped.map((r) => {
      const li = document.createElement("li");
      li.textContent = `${r.name}: ${r.reason || "skipped"}`;
      return li;
    }));
    retryBtn.hidden = job.kind !== "refresh";
  }

  function badgeText(job) {
    const progress = `${job.step} (${job.done}/${job.total || "?"})`;
    if (job.kind === "refresh") return `Discovery running… ${progress}`;
    return `${job.label}: ${progress}`;
  }

  function render(job) {
    running = Boolean(job.running);
    title.textContent = job.label + (running ? "…" : "");
    stepEl.textContent = job.step || "";
    bar.max = Math.max(job.total || 0, 1);
    bar.value = Math.min(job.done || 0, bar.max);
    if (!job.total && running) bar.removeAttribute("value");  // indeterminate
    counts.textContent = job.total ? `${job.done} / ${job.total}` : "–";
    const overall = (job.limits || {}).overall;
    elapsed.textContent = fmtElapsed(job.elapsed || 0) + (overall ? ` / ${fmtMinutes(overall)}` : "");
    stateEl.textContent = stateLabel(job);
    renderLimits(job);
    renderResources(job);
    const atBottom = logEl.scrollTop + logEl.clientHeight >= logEl.scrollHeight - 4;
    logEl.textContent = (job.log || []).join("\n");
    if (atBottom) logEl.scrollTop = logEl.scrollHeight;
    renderMessages(job.messages);
    cancelBtn.hidden = !running;
    cancelBtn.disabled = Boolean(job.cancel_requested);
    hideBtn.hidden = !running;
    closeBtn.hidden = running;
    badge.textContent = running ? badgeText(job) : "";
    if (!running) {
      badge.hidden = true;
      sessionStorage.removeItem(WATCH_KEY);
    }
  }

  function open() {
    modal.hidden = false;
    badge.hidden = true;
  }

  function hide() {
    modal.hidden = true;
    badge.hidden = !running;
  }

  // User actions: remembered server-side so other pages and tabs follow. keepalive lets
  // the request finish when the user navigates away right after clicking.
  function userHide() {
    hide();
    if (jobId) post(url(modal.dataset.hideUrl, jobId), {}, { keepalive: true }).catch(() => {});
  }

  function userOpen() {
    open();
    if (jobId) post(url(modal.dataset.showUrl, jobId), {}, { keepalive: true }).catch(() => {});
  }

  function poll() {
    clearTimeout(timer);
    if (!jobId) return;
    fetch(url(modal.dataset.statusUrl, jobId), { credentials: "same-origin" })
      .then((r) => {
        if (!r.ok) throw new Error("HTTP " + r.status);
        return r.json();
      })
      .then((d) => {
        render(d.job);
        if (d.job.running) timer = setTimeout(poll, POLL_MS);
      })
      .catch((err) => {
        stateEl.textContent = `lost contact with IPLens (${err.message}); retrying…`;
        timer = setTimeout(poll, POLL_MS * 3);
      });
  }

  function attach(job, show) {
    jobId = job.id;
    render(job);
    if (show) open(); else hide();
    if (job.running) timer = setTimeout(poll, POLL_MS);
  }

  // An array field is sent once per value (e.g. only=a&only=b).
  function post(target, fields, options) {
    const body = new URLSearchParams({ csrf_token: csrf });
    Object.entries(fields).forEach(([key, value]) => {
      [].concat(value).forEach((v) => body.append(key, v));
    });
    return fetch(target, { method: "POST", body: body, credentials: "same-origin", ...options });
  }

  cancelBtn.addEventListener("click", () => {
    if (!jobId) return;
    cancelBtn.disabled = true;
    post(url(modal.dataset.cancelUrl, jobId), {}).then(poll).catch(poll);
  });
  hideBtn.addEventListener("click", userHide);
  badge.addEventListener("click", userOpen);
  closeBtn.addEventListener("click", () => window.location.reload());
  document.addEventListener("keydown", (evt) => {
    if (evt.key === "Escape" && !modal.hidden && running) userHide();
  });

  // Post a job-starting form in the background and follow the job in the modal.
  function startJob(action, fields, buttons) {
    fields.background = "1";
    buttons.forEach((b) => { b.disabled = true; });
    post(action, fields)
      .then((r) => r.json().then((d) => ({ status: r.status, d: d })))
      .then(({ status, d }) => {
        if (d.job) {
          if (d.ok) sessionStorage.setItem(WATCH_KEY, d.job.id);
          attach(d.job, true);
          if (!d.ok) {  // another job of this account is running: follow that one
            renderMessages([{ category: "error", text: d.error }]);
          }
          return;
        }
        jobId = null;
        title.textContent = "Not started";
        stepEl.textContent = "";
        logEl.textContent = "";
        renderMessages([{ category: "error", text: d.error || `HTTP ${status}` }]);
        running = false;
        cancelBtn.hidden = true;
        hideBtn.hidden = true;
        closeBtn.hidden = false;
        open();
      })
      .catch((err) => {
        renderMessages([{ category: "error", text: `Could not start the job (${err.message}).` }]);
        open();
      })
      .finally(() => buttons.forEach((b) => { b.disabled = false; }));
  }

  // Forms that start a job: posted in the background, followed in the modal.
  document.querySelectorAll("form[data-job]").forEach((form) => {
    form.addEventListener("submit", (evt) => {
      evt.preventDefault();
      const fields = Object.fromEntries(new FormData(form).entries());
      startJob(form.action, fields, form.querySelectorAll("button"));
    });
  });

  // "Retry skipped": a new Refresh of the active account that collects only the skipped
  // resource types (plus VPCs, subnets and ENIs, which every snapshot needs); the server
  // copies the other resource types from the latest snapshot, so the new one is complete.
  retryBtn.addEventListener("click", () => {
    startJob(modal.dataset.refreshUrl, { only: skippedNames }, [retryBtn]);
  });

  // Re-attach after a reload or on another page: the account's running job (kept hidden
  // if the user hid it), or the result of the job this tab started if it ended while the
  // page was loading.
  fetch(modal.dataset.currentUrl, { credentials: "same-origin" })
    .then((r) => (r.ok ? r.json() : { job: null }))
    .then((d) => {
      const job = d.job;
      if (!job) return;
      if (job.running) attach(job, !d.hidden);
      else if (sessionStorage.getItem(WATCH_KEY) === job.id) attach(job, true);
    })
    .catch(() => {});
})();
