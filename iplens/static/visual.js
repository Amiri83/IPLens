/* IPLens Visual page: nested VPC -> subnet -> resource diagram with resource edges
   (cytoscape.js + dagre, both vendored). */
(function () {
  "use strict";

  const CELL_W = 170;          // horizontal spacing of resource nodes inside a subnet
  const CELL_H = 140;          // vertical spacing (icon + name + up to 4 IP lines)
  const COLS = 4;              // resource columns per subnet box
  const SUBNETS_PER_ROW = 3;
  const SUBNET_GAP_X = 90;
  const SUBNET_GAP_Y = 130;    // leaves room for the subnet label above each box
  const SUBNET_MIN_W = 2 * CELL_W - 40;
  const SUBNET_PAD = 28;
  const SUBNET_LABEL_H = 48;   // three 11px lines above each subnet box
  const MAX_IPS_IN_LABEL = 3;
  const MAX_TITLE_LINES = 12;  // tooltip lines listed for an edge merged into a group node

  const container = document.getElementById("cy");
  if (!container || typeof cytoscape === "undefined") return;
  const status = document.getElementById("cy-status");
  const tip = document.getElementById("cy-tip");
  const layoutSelect = document.getElementById("layout");
  const edgeBoxes = Array.from(document.querySelectorAll('input[type="checkbox"][name="edges"]'));
  const iconBase = container.dataset.icons;
  const eniUrl = container.dataset.eniUrl;

  // -- labels (names arrive pre-truncated as label_*; tooltips show the full text) ----

  function resourceLabel(r) {
    const lines = [r.label_name];
    if (r.name !== r.type_label) lines.push(r.type_label);
    lines.push(...r.ips.slice(0, MAX_IPS_IN_LABEL));
    if (r.ips.length > MAX_IPS_IN_LABEL) lines.push(`+${r.ips.length - MAX_IPS_IN_LABEL} more`);
    return lines.join("\n");
  }

  function resourceTitle(r) {
    const lines = [r.name];
    if (r.type_label !== r.name) lines.push(r.type_label);
    if (r.ref && r.ref !== r.name) lines.push(r.ref);
    lines.push(r.eni_id, ...r.ips);
    return lines.join("\n");
  }

  function usage(s) {
    return `used ${s.used} · idle ${s.idle} · free ${s.free} / ${s.size}`;
  }

  function subnetLabel(s) {
    return [s.label_name, s.label_meta, usage(s)].join("\n");
  }

  function subnetTitle(s) {
    return [s.name || s.subnet_id, s.subnet_id, `${s.cidr} · ${s.az}`, usage(s)].join("\n");
  }

  function groupLabel(g, expanded) {
    return `${expanded ? "▾" : "▸"} ${g.name}\n${g.ip_count} IPs · click to ${expanded ? "collapse" : "expand"}`;
  }

  // -- elements -----------------------------------------------------------------------

  function resourceElement(r, parent, order, extra) {
    return {
      group: "nodes",
      data: {
        id: "res:" + r.eni_id,
        parent: parent,
        order: order,
        label: resourceLabel(r),
        title: resourceTitle(r),
        icon: iconBase + r.icon,
        eni: r.eni_id,
        ...extra,
      },
      classes: "res" + (r.status === "available" ? " idle" : "") + (extra.memberOf ? " member hidden" : ""),
    };
  }

  function buildElements(data) {
    const vpc = data.vpc;
    const els = [{
      group: "nodes",
      data: {
        id: "vpc",
        label: `${vpc.label_name}\n${vpc.vpc_id} · ${vpc.label_cidrs}`,
        title: [vpc.name || vpc.vpc_id, vpc.vpc_id, ...vpc.cidrs].join("\n"),
        icon: iconBase + data.icons.vpc,
      },
      classes: "vpc",
    }];
    vpc.subnets.forEach((s, si) => {
      const sid = "subnet:" + s.subnet_id;
      els.push({
        group: "nodes",
        data: { id: sid, parent: "vpc", order: si, label: subnetLabel(s), title: subnetTitle(s) },
        classes: "subnet" + (s.items.length ? "" : " empty"),
      });
      s.items.forEach((item, i) => {
        if (item.kind === "group") {
          els.push({
            group: "nodes",
            data: {
              id: item.id, parent: sid, order: i, label: groupLabel(item, false),
              title: `${item.name}\n${item.ip_count} IPs`,
              icon: iconBase + item.icon, raw: item,
            },
            classes: "group",
          });
          item.members.forEach((m, j) => {
            els.push(resourceElement(m, sid, i + (j + 1) / (item.members.length + 1), { memberOf: item.id }));
          });
        } else {
          els.push(resourceElement(item, sid, i, {}));
        }
      });
    });
    return els;
  }

  // -- edges --------------------------------------------------------------------------

  function enabledEdgeTypes() {
    return new Set(edgeBoxes.filter((b) => b.checked).map((b) => b.value));
  }

  // A member hidden inside a collapsed group is drawn through its group node.
  function endpointId(cy, eniId) {
    const n = cy.getElementById("res:" + eniId);
    if (n.empty()) return null;
    return n.hasClass("hidden") ? n.data("memberOf") : n.id();
  }

  function visibleEdges(cy, edges, types) {
    const merged = new Map();
    edges.forEach((e) => {
      if (!types.has(e.type)) return;
      const s = endpointId(cy, e.source);
      const t = endpointId(cy, e.target);
      if (!s || !t || s === t) return;
      const key = `${e.type}|${s}|${t}`;
      const m = merged.get(key);
      if (m) {
        m.n += 1;
        if (m.titles.length < MAX_TITLE_LINES) m.titles.push(e.title);
      } else {
        merged.set(key, { type: e.type, source: s, target: t, label: e.label, titles: [e.title], n: 1 });
      }
    });
    return Array.from(merged.values());
  }

  function syncEdges(cy, edges) {
    const items = visibleEdges(cy, edges, enabledEdgeTypes());
    cy.batch(() => {
      cy.edges().remove();
      cy.add(items.map((m, i) => ({
        group: "edges",
        data: {
          id: "edge:" + i,
          source: m.source,
          target: m.target,
          label: m.n > 1 ? `${m.label} ×${m.n}` : m.label,
          title: m.titles.join("\n") + (m.n > m.titles.length ? `\n… +${m.n - m.titles.length} more` : ""),
        },
        classes: "edge-" + m.type,
      })));
    });
  }

  function rememberEdgeFilter() {
    const params = new URLSearchParams(window.location.search);
    params.delete("edges");
    params.append("edges", "");
    edgeBoxes.filter((b) => b.checked).forEach((b) => params.append("edges", b.value));
    window.history.replaceState(null, "", `${window.location.pathname}?${params}`);
  }

  // -- layouts ------------------------------------------------------------------------

  function sortedKids(subnet) {
    return subnet.children()
      .filter((n) => !n.hasClass("hidden"))
      .sort((a, b) => a.data("order") - b.data("order"));
  }

  // Deterministic grid layout: subnets in rows, resources in a grid inside each subnet.
  function gridLayout(cy) {
    let x0 = 0, y0 = 0, rowH = 0, col = 0;
    const subnets = cy.nodes(".subnet").sort((a, b) => a.data("order") - b.data("order"));
    cy.batch(() => {
      subnets.forEach((sn) => {
        const kids = sortedKids(sn);
        const n = Math.max(kids.length, 1);
        const cols = Math.min(COLS, n);
        const rows = Math.ceil(n / cols);
        if (kids.length) {
          kids.forEach((k, i) => {
            k.position({ x: x0 + (i % cols) * CELL_W, y: y0 + Math.floor(i / cols) * CELL_H });
          });
        } else {
          sn.position({ x: x0 + CELL_W / 2, y: y0 });
        }
        x0 += Math.max(cols * CELL_W, 2 * CELL_W) + SUBNET_GAP_X;
        rowH = Math.max(rowH, rows * CELL_H);
        col += 1;
        if (col === SUBNETS_PER_ROW) {
          col = 0; x0 = 0; y0 += rowH + SUBNET_GAP_Y; rowH = 0;
        }
      });
    });
  }

  /* Top-down dagre layout of the compound graph. Besides the LB/ECS edges (LB above its
     targets), invisible helper edges keep the picture compact:
       - a "head" node per subnet reserves room for the label drawn above the box and
         enforces the minimum box width;
       - item i -> item i+COLS wraps a subnet's resources into rows of COLS;
       - subnet k-SUBNETS_PER_ROW -> subnet k wraps subnets into rows.
     SG edges are left out: they are numerous and often cyclic. */
  function dagreLayout(cy, edges) {
    const g = new dagre.graphlib.Graph({ compound: true, multigraph: true });
    g.setGraph({ rankdir: "TB", nodesep: 30, ranksep: 40, marginx: 20, marginy: 20 });
    g.setDefaultEdgeLabel(() => ({}));

    const leaves = [];
    cy.nodes().filter((n) => !n.hasClass("hidden")).forEach((n) => {
      if (n.isParent()) {
        g.setNode(n.id(), {});
      } else {
        const dim = n.layoutDimensions({ nodeDimensionsIncludeLabels: true });
        g.setNode(n.id(), { width: dim.w, height: dim.h });
        leaves.push(n);
      }
      if (n.parent().nonempty()) g.setParent(n.id(), n.parent().id());
    });

    const link = (a, b, weight) => g.setEdge(a, b, { weight: weight, minlen: 1 }, `${a}>${b}`);
    const subnets = cy.nodes(".subnet").sort((a, b) => a.data("order") - b.data("order"));
    const tops = [];     // first layout node of each subnet
    const bottoms = [];  // last layout node of each subnet
    subnets.forEach((sn) => {
      const kids = sortedKids(sn);
      if (!kids.length) {
        tops.push(sn.id());
        bottoms.push(sn.id());
        return;
      }
      const head = "head:" + sn.id();
      const labelW = sn.boundingBox({ includeNodes: false, includeLabels: true }).w || 0;
      g.setNode(head, { width: Math.max(SUBNET_MIN_W + 2 * SUBNET_PAD, labelW), height: SUBNET_LABEL_H });
      g.setParent(head, sn.id());
      kids.forEach((k, i) => {
        if (i < COLS) link(head, k.id(), 1);
        if (i + COLS < kids.length) link(k.id(), kids[i + COLS].id(), 1);
      });
      tops.push(head);
      bottoms.push(kids[kids.length - 1].id());
    });
    for (let k = SUBNETS_PER_ROW; k < tops.length; k += 1) {
      link(bottoms[k - SUBNETS_PER_ROW], tops[k], 1);
    }
    visibleEdges(cy, edges, new Set(["targets", "ecs_lb"])).forEach((e) => {
      // ECS->LB points "up"; reverse it so the load balancer ranks above the service.
      if (e.type === "ecs_lb") link(e.target, e.source, 2);
      else link(e.source, e.target, 2);
    });

    dagre.layout(g);
    cy.batch(() => {
      leaves.forEach((n) => {
        const p = g.node(n.id());
        // dagre centres the box including the label; cytoscape positions the node body.
        const dy = (p.height - n.outerHeight()) / 2;
        n.position({ x: p.x, y: p.y - (n.hasClass("subnet") ? -dy : dy) });
      });
    });
  }

  function runLayout(cy, edges) {
    if (layoutSelect.value === "dagre" && typeof dagre !== "undefined") {
      try {
        dagreLayout(cy, edges);
        return;
      } catch (err) {
        console.warn("dagre layout failed, using grid layout", err);
        layoutSelect.value = "grid";
      }
    }
    gridLayout(cy);
  }

  function toggleGroup(cy, group, expand) {
    const members = cy.nodes(".member").filter((n) => n.data("memberOf") === group.id());
    const expanded = expand === undefined ? members.hasClass("hidden") : expand;
    if (expanded) members.removeClass("hidden"); else members.addClass("hidden");
    group.data("label", groupLabel(group.data("raw"), expanded));
  }

  // -- style --------------------------------------------------------------------------

  const style = [
    { selector: "node", style: {
      "label": "data(label)", "font-size": 10, "text-wrap": "wrap", "text-max-width": 160,
      "color": "#1f2933", "font-family": "system-ui, sans-serif",
    } },
    { selector: ".vpc", style: {
      "shape": "rectangle", "background-color": "#f7f3ff", "background-opacity": 1,
      "border-width": 2, "border-color": "#8c4fff", "padding": 50,
      "text-valign": "top", "text-halign": "center", "font-size": 14, "font-weight": "bold",
      "text-margin-y": -6, "text-max-width": 420,
      "background-image": "data(icon)", "background-width": 32, "background-height": 32,
      "background-position-x": 0, "background-position-y": 0, "background-clip": "none",
    } },
    { selector: ".subnet", style: {
      "shape": "rectangle", "background-color": "#ffffff", "border-width": 1.5,
      "border-color": "#7aa116", "border-style": "solid", "padding": SUBNET_PAD,
      "text-valign": "top", "text-halign": "center", "font-size": 11, "text-margin-y": -4,
      "text-max-width": 300, "min-width": SUBNET_MIN_W,
    } },
    { selector: ".subnet.empty", style: { "width": SUBNET_MIN_W, "height": 50 } },
    { selector: ".res, .group", style: {
      "shape": "round-rectangle", "width": 44, "height": 44,
      "background-color": "#ffffff", "background-image": "data(icon)",
      "background-fit": "contain", "border-width": 0,
      "text-valign": "bottom", "text-halign": "center", "text-margin-y": 5,
    } },
    { selector: ".res.idle", style: { "border-width": 3, "border-color": "#e8a33a" } },
    { selector: ".group", style: {
      "border-width": 3, "border-color": "#2457c5", "border-style": "double",
      "font-weight": "bold",
    } },
    { selector: ".hidden", style: { "display": "none" } },
    { selector: "node.res:active, node.group:active", style: { "overlay-opacity": 0.15 } },
    { selector: "edge", style: {
      "curve-style": "bezier", "width": 2, "target-arrow-shape": "triangle", "arrow-scale": 0.9,
      "label": "data(label)", "font-size": 9, "color": "#1f2933", "min-zoomed-font-size": 7,
      "text-rotation": "autorotate", "text-background-color": "#ffffff",
      "text-background-opacity": 0.85, "text-background-padding": 2,
    } },
    { selector: "edge.edge-targets", style: { "line-color": "#2457c5", "target-arrow-color": "#2457c5" } },
    { selector: "edge.edge-ecs_lb", style: { "line-color": "#2f8f4e", "target-arrow-color": "#2f8f4e" } },
    { selector: "edge.edge-sg", style: {
      "line-style": "dashed", "line-dash-pattern": [6, 4], "width": 1.2, "line-color": "#8a94a3",
      "target-arrow-color": "#8a94a3", "target-arrow-shape": "vee", "opacity": 0.85,
      "color": "#535e6b",
    } },
    { selector: "edge:selected, edge.hover", style: { "width": 3, "opacity": 1, "z-index": 10 } },
  ];

  // -- tooltip ------------------------------------------------------------------------

  function showTip(evt) {
    const title = evt.target.data("title");
    if (!title) return;
    tip.textContent = title;
    const pos = evt.renderedPosition || evt.target.renderedPosition();
    tip.style.left = `${container.offsetLeft + pos.x + 14}px`;
    tip.style.top = `${container.offsetTop + pos.y + 14}px`;
    tip.hidden = false;
  }

  function hideTip() {
    tip.hidden = true;
  }

  // -- page ---------------------------------------------------------------------------

  function render(data) {
    if (!data.vpc) {
      status.textContent = "No VPC data in this snapshot.";
      return;
    }
    const edges = data.edges || [];
    const cy = cytoscape({
      container: container,
      elements: buildElements(data),
      style: style,
      layout: { name: "preset" },
      minZoom: 0.05,
      maxZoom: 3,
      autoungrabify: true,
      boxSelectionEnabled: false,
    });
    const relayout = () => {
      syncEdges(cy, edges);
      runLayout(cy, edges);
    };
    relayout();
    cy.fit(undefined, 30);

    cy.on("tap", "node.res", (evt) => {
      window.location.href = eniUrl.replace("__ENI__", encodeURIComponent(evt.target.data("eni")));
    });
    cy.on("tap", "node.group", (evt) => {
      toggleGroup(cy, evt.target);
      relayout();
    });
    cy.on("mouseover", "node.res, node.group", () => { container.style.cursor = "pointer"; });
    cy.on("mouseout", "node", () => { container.style.cursor = ""; });
    cy.on("mouseover", "node, edge", showTip);
    cy.on("mousemove", "node, edge", showTip);
    cy.on("mouseout", "node, edge", hideTip);
    cy.on("mouseover", "edge", (evt) => evt.target.addClass("hover"));
    cy.on("mouseout", "edge", (evt) => evt.target.removeClass("hover"));
    cy.on("viewport", hideTip);

    const zoomBy = (factor) => {
      cy.zoom({
        level: cy.zoom() * factor,
        renderedPosition: { x: container.clientWidth / 2, y: container.clientHeight / 2 },
      });
    };
    document.getElementById("zoom-in").addEventListener("click", () => zoomBy(1.25));
    document.getElementById("zoom-out").addEventListener("click", () => zoomBy(0.8));
    document.getElementById("zoom-fit").addEventListener("click", () => cy.fit(undefined, 30));
    document.getElementById("expand-all").addEventListener("click", () => {
      cy.nodes(".group").forEach((g) => toggleGroup(cy, g, true));
      relayout();
    });
    document.getElementById("collapse-all").addEventListener("click", () => {
      cy.nodes(".group").forEach((g) => toggleGroup(cy, g, false));
      relayout();
    });
    layoutSelect.addEventListener("change", () => {
      runLayout(cy, edges);
      cy.fit(undefined, 30);
    });
    edgeBoxes.forEach((box) => box.addEventListener("change", () => {
      syncEdges(cy, edges);
      rememberEdgeFilter();
    }));

    (data.edge_types || []).forEach((t) => {
      const el = document.querySelector(`[data-edge-count="${t.type}"]`);
      if (el) el.textContent = `(${t.count})`;
    });
    const nRes = data.vpc.subnets.reduce((a, s) => a + s.resource_count, 0);
    status.textContent = `${data.vpc.subnets.length} subnet(s) · ${nRes} resource ENI(s) · ` +
      `${edges.length} connection(s) · snapshot #${data.snapshot_id}` +
      (data.edges_truncated ? " · SG references truncated" : "");
  }

  fetch(container.dataset.src, { credentials: "same-origin" })
    .then((r) => {
      if (!r.ok) throw new Error("HTTP " + r.status);
      return r.json();
    })
    .then(render)
    .catch((err) => { status.textContent = "Could not load diagram data (" + err.message + ")."; });
})();
