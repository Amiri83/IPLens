/* IPLens Visual page tag filters: mirrors iplens/tagfilter.py function by function
   (tests/test_tagfilter.py runs both on the same input). Pure functions, no DOM: loaded
   by the Visual page as window.IPLensTagFilter, or required by node. */
(function (root, factory) {
  "use strict";
  if (typeof module === "object" && module.exports) module.exports = factory();
  else root.IPLensTagFilter = factory();
})(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  function keyValues(tags, key) {
    const wanted = key.toLowerCase();
    return Object.entries(tags || {}).filter(([k]) => k.toLowerCase() === wanted).map(([, v]) => v);
  }

  function matches(flt, tags) {
    const found = keyValues(tags, flt.tag_key);
    if (!found.length) return Boolean(flt.include_untagged);
    return found.some((v) => flt.values.includes(v));
  }

  function resourceVisible(resource, filters) {
    return filters.every((f) => f.resource_type !== resource.type || matches(f, resource.tags));
  }

  // {type: [shown, total]}; shown(resource) -> bool.
  function typeCounts(resources, shown) {
    const counts = {};
    resources.forEach((r) => {
      const c = counts[r.type] || (counts[r.type] = [0, 0]);
      c[0] += shown(r) ? 1 : 0;
      c[1] += 1;
    });
    return Object.fromEntries(Object.keys(counts).sort().map((t) => [t, counts[t]]));
  }

  // subnets: [{subnet_id, resources}]; shown(resource) -> bool.
  function hiddenContainers(subnets, shown, hideEmpty) {
    if (!hideEmpty) return { subnets: [], vpc: false };
    const empty = subnets.filter((s) => !s.resources.some(shown)).map((s) => s.subnet_id);
    return { subnets: empty, vpc: empty.length === subnets.length };
  }

  function byLower(a, b) {
    const x = a.toLowerCase(), y = b.toLowerCase();
    return x < y ? -1 : x > y ? 1 : 0;
  }

  // {type: {tag key: [values]}}: keys differing only in case are one, spelled as first seen.
  function discoveredTags(resources) {
    const out = {};
    const spelling = new Map();
    resources.forEach((r) => {
      const keys = out[r.type] || (out[r.type] = {});
      Object.entries(r.tags || {}).forEach(([k, v]) => {
        const id = `${r.type}\u0000${k.toLowerCase()}`;
        if (!spelling.has(id)) spelling.set(id, k);
        const key = spelling.get(id);
        (keys[key] || (keys[key] = new Set())).add(v);
      });
    });
    return Object.fromEntries(Object.keys(out).sort().map((t) => [t, Object.fromEntries(
      Object.keys(out[t]).sort(byLower).map((k) => [k, Array.from(out[t][k]).sort()]),
    )]));
  }

  return {
    keyValues: keyValues,
    matches: matches,
    resourceVisible: resourceVisible,
    typeCounts: typeCounts,
    hiddenContainers: hiddenContainers,
    discoveredTags: discoveredTags,
  };
});
