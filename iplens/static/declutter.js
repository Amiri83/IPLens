/* IPLens Extended view decluttering rules: mirrors iplens/declutter.py function by
   function (tests/test_declutter.py runs both on the same input). Pure functions, no
   DOM: loaded by the Visual page as window.IPLensDeclutter, or required by node. */
(function (root, factory) {
  "use strict";
  if (typeof module === "object" && module.exports) module.exports = factory();
  else root.IPLensDeclutter = factory();
})(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  const EVIDENCE = ["observed", "configured", "permitted", "referenced"];  // strongest first
  const RANK = Object.fromEntries(EVIDENCE.map((lvl, i) => [lvl, i]));
  const DEFAULT_EVIDENCE = ["observed", "configured"];
  const FOCUS_HOPS = [1, 2];
  const AGG_MIN = 2;
  const EDGE_W_UNIT = 2;
  const EDGE_W_MAX = 12;
  const SOURCE_SERVICES = new Set(["events", "apigateway"]);
  const DUAL_SERVICES = new Set(["sns", "s3"]);
  const COMPUTE_SERVICES = new Set(["lambda", "ecs"]);

  function edgeWidth(count) {
    return Math.min(EDGE_W_MAX, EDGE_W_UNIT * Math.max(1, count));
  }

  function pair(a, b) {
    return a < b ? `${a}\u0000${b}` : `${b}\u0000${a}`;
  }

  function cmp(a, b) {
    return a < b ? -1 : a > b ? 1 : 0;
  }

  // One drawn edge per unordered node pair; see iplens.declutter.merge_edges.
  function mergeEdges(edges, levels, endpoint) {
    const shownLevels = new Set(levels);
    const merged = new Map();
    edges.forEach((e) => {
      const s = endpoint ? endpoint(e.source) : e.source;
      const t = endpoint ? endpoint(e.target) : e.target;
      if (!s || !t || s === t) return;
      const key = pair(s, t);
      if (!merged.has(key)) merged.set(key, { lines: [], types: new Set() });
      const m = merged.get(key);
      m.types.add(e.type || "ext");
      (e.lines || []).forEach((ln) => {
        m.lines.push({
          evidence: ln.evidence,
          label: ln.label || "",
          text: ln.text || "",
          source: e.source,
          target: e.target,
          drawn_source: s,
          drawn_target: t,
          shown: shownLevels.has(ln.evidence),
        });
      });
    });
    const out = [];
    merged.forEach((m) => {
      const lines = m.lines.slice().sort((a, b) => RANK[a.evidence] - RANK[b.evidence] || cmp(a.text, b.text));
      const shown = lines.filter((ln) => ln.shown);
      if (!shown.length) return;
      const best = shown[0];
      const s = best.drawn_source;
      const t = best.drawn_target;
      const count = new Set(shown.map((ln) => pair(ln.source, ln.target))).size;
      lines.forEach((ln) => {
        ln.reverse = ln.drawn_source !== s;
        delete ln.drawn_source;
        delete ln.drawn_target;
      });
      out.push({
        source: s,
        target: t,
        evidence: best.evidence,
        label: best.label,
        types: Array.from(m.types).sort(cmp),
        count: count,
        extra: lines.length - count,
        width: edgeWidth(count),
        bidir: shown.some((ln) => ln.reverse),
        lines: lines,
      });
    });
    return out;
  }

  // ``start`` and every node at most ``hops`` drawn edges away (direction ignored).
  function neighbourhood(edges, start, hops) {
    const adjacent = new Map();
    const link = (a, b) => {
      if (!adjacent.has(a)) adjacent.set(a, new Set());
      adjacent.get(a).add(b);
    };
    edges.forEach((e) => {
      link(e.source, e.target);
      link(e.target, e.source);
    });
    const seen = new Set([start]);
    let frontier = [start];
    for (let i = 0; i < Math.max(0, hops); i += 1) {
      const next = [];
      frontier.forEach((f) => (adjacent.get(f) || new Set()).forEach((n) => {
        if (!seen.has(n)) {
          seen.add(n);
          next.push(n);
        }
      }));
      frontier = next;
    }
    return seen;
  }

  // Left-to-right rank of a service node: 0 source, 1 compute, 2 target.
  function serviceTier(service, feedsCompute) {
    if (COMPUTE_SERVICES.has(service)) return 1;
    if (SOURCE_SERVICES.has(service) || (DUAL_SERVICES.has(service) && feedsCompute)) return 0;
    return 2;
  }

  return {
    EVIDENCE, DEFAULT_EVIDENCE, FOCUS_HOPS, AGG_MIN, EDGE_W_UNIT, EDGE_W_MAX,
    edgeWidth, mergeEdges, neighbourhood, serviceTier,
  };
});
