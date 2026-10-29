/* IPLens Visual page view filters: mirrors iplens/tagfilter.py function by function
   (tests/test_tagfilter.py runs both on the same input). Pure functions, no DOM: loaded
   by the Visual page as window.IPLensTagFilter, or required by node. */
(function (root, factory) {
  "use strict";
  if (typeof module === "object" && module.exports) module.exports = factory();
  else root.IPLensTagFilter = factory();
})(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  // tag_values ({key: [values]}: the ENI's and all its owners') when present, else tags.
  function filterTags(resource) {
    const values = resource.tag_values;
    if (values === undefined || values === null) return resource.tags || {};
    return values;
  }

  // A key may hold one value or a list of them.
  function keyValues(tags, key) {
    const wanted = key.toLowerCase();
    const out = [];
    Object.entries(tags || {}).forEach(([k, v]) => {
      if (k.toLowerCase() === wanted) out.push(...(Array.isArray(v) ? v : [v]));
    });
    return out;
  }

  function matches(flt, tags) {
    const found = keyValues(tags, flt.tag_key);
    if (!found.length) return Boolean(flt.include_untagged);
    return found.some((v) => flt.values.includes(v));
  }

  // Lower-cased, non-empty comma-separated terms of the name filter.
  function nameTerms(text) {
    return (text || "").split(",").map((p) => p.trim().toLowerCase()).filter(Boolean);
  }

  // A term is part of the name, an owner's name or the ENI id (no term: true).
  function nameMatches(resource, terms) {
    if (!terms.length) return true;
    const texts = [resource.name, ...(resource.owners || []), resource.eni_id]
      .filter(Boolean).map((f) => f.toLowerCase());
    return terms.some((t) => texts.some((f) => f.includes(t)));
  }

  // Every tag filter (any resource type) and the name filter must match.
  function resourceVisible(resource, filters, name) {
    const tags = filterTags(resource);
    return filters.every((f) => matches(f, tags)) && nameMatches(resource, nameTerms(name));
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

  // {tag key: [values]} over every resource: keys differing only in case are one,
  // spelled as first seen.
  function discoveredTags(resources) {
    const out = {};
    const spelling = new Map();
    resources.forEach((r) => {
      Object.entries(filterTags(r)).forEach(([k, v]) => {
        const id = k.toLowerCase();
        if (!spelling.has(id)) spelling.set(id, k);
        const key = spelling.get(id);
        const set = out[key] || (out[key] = new Set());
        (Array.isArray(v) ? v : [v]).forEach((x) => set.add(x));
      });
    });
    return Object.fromEntries(Object.keys(out).sort(byLower).map((k) => [k, Array.from(out[k]).sort()]));
  }

  return {
    filterTags: filterTags,
    keyValues: keyValues,
    matches: matches,
    nameTerms: nameTerms,
    nameMatches: nameMatches,
    resourceVisible: resourceVisible,
    typeCounts: typeCounts,
    hiddenContainers: hiddenContainers,
    discoveredTags: discoveredTags,
  };
});
