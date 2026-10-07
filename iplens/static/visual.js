/* IPLens Visual page: nested VPC -> subnet -> resource diagram (cytoscape.js, vendored). */
(function () {
  "use strict";

  const CELL_W = 170;          // horizontal spacing of resource nodes inside a subnet
  const CELL_H = 140;          // vertical spacing (icon + name + up to 4 IP lines)
  const COLS = 4;              // resource columns per subnet box
  const SUBNETS_PER_ROW = 3;
  const SUBNET_GAP_X = 90;
  const SUBNET_GAP_Y = 130;    // leaves room for the subnet label above each box
  const MAX_IPS_IN_LABEL = 3;

  const container = document.getElementById("cy");
  if (!container || typeof cytoscape === "undefined") return;
  const status = document.getElementById("cy-status");
  const iconBase = container.dataset.icons;
  const eniUrl = container.dataset.eniUrl;

  function resourceLabel(r) {
    const lines = [r.name];
    if (r.name !== r.type_label) lines.push(r.type_label);
    lines.push(...r.ips.slice(0, MAX_IPS_IN_LABEL));
    if (r.ips.length > MAX_IPS_IN_LABEL) lines.push(`+${r.ips.length - MAX_IPS_IN_LABEL} more`);
    return lines.join("\n");
  }

  function subnetLabel(s) {
    return [
      s.name || s.subnet_id,
      `${s.subnet_id} · ${s.cidr} · ${s.az}`,
      `used ${s.used} · idle ${s.idle} · free ${s.free} / ${s.size}`,
    ].join("\n");
  }

  function groupLabel(g, expanded) {
    return `${expanded ? "▾" : "▸"} ${g.name}\n${g.ip_count} IPs · click to ${expanded ? "collapse" : "expand"}`;
  }

  function resourceElement(r, parent, order, extra) {
    return {
      group: "nodes",
      data: {
        id: "res:" + r.eni_id,
        parent: parent,
        order: order,
        label: resourceLabel(r),
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
        label: `${vpc.name || vpc.vpc_id}\n${vpc.vpc_id} · ${vpc.cidrs.join(", ")}`,
        icon: iconBase + data.icons.vpc,
      },
      classes: "vpc",
    }];
    vpc.subnets.forEach((s, si) => {
      const sid = "subnet:" + s.subnet_id;
      els.push({
        group: "nodes",
        data: { id: sid, parent: "vpc", order: si, label: subnetLabel(s) },
        classes: "subnet" + (s.items.length ? "" : " empty"),
      });
      s.items.forEach((item, i) => {
        if (item.kind === "group") {
          els.push({
            group: "nodes",
            data: {
              id: item.id, parent: sid, order: i, label: groupLabel(item, false),
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

  // Deterministic grid layout: subnets in rows, resources in a grid inside each subnet.
  function layout(cy) {
    let x0 = 0, y0 = 0, rowH = 0, col = 0;
    const subnets = cy.nodes(".subnet").sort((a, b) => a.data("order") - b.data("order"));
    cy.batch(() => {
      subnets.forEach((sn) => {
        const kids = sn.children()
          .filter((n) => !n.hasClass("hidden"))
          .sort((a, b) => a.data("order") - b.data("order"));
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

  function toggleGroup(cy, group, expand) {
    const members = cy.nodes(".member").filter((n) => n.data("memberOf") === group.id());
    const expanded = expand === undefined ? members.hasClass("hidden") : expand;
    if (expanded) members.removeClass("hidden"); else members.addClass("hidden");
    group.data("label", groupLabel(group.data("raw"), expanded));
  }

  const style = [
    { selector: "node", style: {
      "label": "data(label)", "font-size": 10, "text-wrap": "wrap", "text-max-width": 160,
      "color": "#1f2933", "font-family": "system-ui, sans-serif",
    } },
    { selector: ".vpc", style: {
      "shape": "rectangle", "background-color": "#f7f3ff", "background-opacity": 1,
      "border-width": 2, "border-color": "#8c4fff", "padding": 50,
      "text-valign": "top", "text-halign": "center", "font-size": 14, "font-weight": "bold",
      "text-margin-y": -6,
      "background-image": "data(icon)", "background-width": 32, "background-height": 32,
      "background-position-x": 0, "background-position-y": 0, "background-clip": "none",
    } },
    { selector: ".subnet", style: {
      "shape": "rectangle", "background-color": "#ffffff", "border-width": 1.5,
      "border-color": "#7aa116", "border-style": "solid", "padding": 28,
      "text-valign": "top", "text-halign": "center", "font-size": 11, "text-margin-y": -4,
      "min-width": 2 * CELL_W - 40,
    } },
    { selector: ".subnet.empty", style: { "width": 2 * CELL_W - 40, "height": 50 } },
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
  ];

  function render(data) {
    if (!data.vpc) {
      status.textContent = "No VPC data in this snapshot.";
      return;
    }
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
    layout(cy);
    cy.fit(undefined, 30);

    cy.on("tap", "node.res", (evt) => {
      window.location.href = eniUrl.replace("__ENI__", encodeURIComponent(evt.target.data("eni")));
    });
    cy.on("tap", "node.group", (evt) => {
      toggleGroup(cy, evt.target);
      layout(cy);
    });
    cy.on("mouseover", "node.res, node.group", () => { container.style.cursor = "pointer"; });
    cy.on("mouseout", "node", () => { container.style.cursor = ""; });

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
      layout(cy);
    });
    document.getElementById("collapse-all").addEventListener("click", () => {
      cy.nodes(".group").forEach((g) => toggleGroup(cy, g, false));
      layout(cy);
    });

    const nRes = data.vpc.subnets.reduce((a, s) => a + s.resource_count, 0);
    status.textContent = `${data.vpc.subnets.length} subnet(s) · ${nRes} resource ENI(s) · snapshot #${data.snapshot_id}`;
  }

  fetch(container.dataset.src, { credentials: "same-origin" })
    .then((r) => {
      if (!r.ok) throw new Error("HTTP " + r.status);
      return r.json();
    })
    .then(render)
    .catch((err) => { status.textContent = "Could not load diagram data (" + err.message + ")."; });
})();
