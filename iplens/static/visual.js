/* IPLens Visual page: nested VPC -> subnet -> resource diagram with resource edges
   (cytoscape.js + dagre, both vendored). The Extended view (data-mode="extended") adds
   regional services and external gateways beside the VPC and styles every edge by its
   strongest evidence level (observed > configured > permitted > referenced). */
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
  const CELL_GAP = 24;         // grid layout: space between two wrapped resource labels
  // Label line widths in px; full names are wrapped after "- _ . /" to fit.
  const TEXT_W = { res: 180, subnet: 300, vpc: 420 };
  const FONTS = {
    res: "normal normal 10px system-ui, sans-serif",
    subnet: "normal normal 11px system-ui, sans-serif",
    vpc: "normal bold 14px system-ui, sans-serif",
  };

  const container = document.getElementById("cy");
  if (!container || typeof cytoscape === "undefined") return;
  const status = document.getElementById("cy-status");
  const note = document.getElementById("cy-note");
  const tip = document.getElementById("cy-tip");
  const layoutSelect = document.getElementById("layout");
  const edgeBoxes = Array.from(document.querySelectorAll('input[type="checkbox"][name="edges"]'));
  const iconBase = container.dataset.icons;
  const eniUrl = container.dataset.eniUrl;
  const csrf = container.dataset.csrf;
  const vpcId = container.dataset.vpc;
  const showVpcBox = document.getElementById("show-vpc");
  const showSubnetsBox = document.getElementById("show-subnets");
  const shortenBox = document.getElementById("shorten-names");
  const groupBySelect = document.getElementById("group-by");
  const groupTagSelect = document.getElementById("group-tag");
  const expandExportBox = document.getElementById("export-expand");
  const extended = container.dataset.mode === "extended";
  const iconRoot = container.dataset.iconRoot;
  const evidenceBoxes = Array.from(document.querySelectorAll('input[type="checkbox"][name="evidence"]'));
  const serviceFilters = document.getElementById("service-filters");
  const detail = document.getElementById("edge-detail");
  const EVIDENCE = ["observed", "configured", "permitted", "referenced"];  // strongest first
  const EXT_GAP = 160;         // space between the VPC box and the areas beside it
  const EXT_COLS = 3;          // "Regional services" columns
  const SHORT_MAX = parseInt(container.dataset.shortMax, 10) || 32;
  const SAVE_DELAY_MS = 400;
  const GROUP_LABEL_MEMBERS = 3;  // mirrors iplens.queries.GROUP_LABEL_MEMBERS
  const CTX_PAD = 12;             // "Group by" box padding around its resources
  const CTX_LABEL_H = 16;
  // "Group by" box / outline colours (dark enough for text on white).
  const PALETTE = ["#2457c5", "#c2410c", "#2f8f4e", "#9333ea", "#b0469b", "#0e7490",
    "#a16207", "#be123c", "#4d7c0f", "#475569"];
  const UNMANAGED_COLOR = "#8a94a3";
  // Dragged positions for this account + VPC: {node id: {x, y}}.
  let saved = JSON.parse(document.getElementById("visual-positions").textContent || "{}");

  // -- labels (full names arrive as label_*; the page wraps or shortens them) ---------

  const SEPARATORS = "-_./";

  // Mirrors iplens.visual.middle_ellipsize: keep the start and the (longer) end so
  // names sharing a prefix stay distinguishable, e.g. "datalab-…-kafka-producer".
  function middleEllipsize(text, limit) {
    text = text || "";
    if (text.length <= limit) return text;
    if (limit <= 2) return "…".slice(0, limit);
    const budget = limit - 1;
    const headN = Math.floor(budget * 2 / 5);
    const tailN = budget - headN;
    let head = text.slice(0, headN);
    let tail = text.slice(-tailN);
    const cut = Math.max(...Array.from(SEPARATORS, (c) => head.lastIndexOf(c)));
    if (cut >= Math.floor(headN / 2)) head = head.slice(0, cut + 1);
    const starts = Array.from(SEPARATORS, (c) => tail.indexOf(c)).filter((i) => i >= 0);
    if (starts.length && Math.min(...starts) <= Math.floor(tailN / 2)) tail = tail.slice(Math.min(...starts));
    return head + "…" + tail;
  }

  function shortName(text) {
    return shortenBox && shortenBox.checked ? middleEllipsize(text, SHORT_MAX) : text;
  }

  // "<first owner> +N more" for a shared ENI: only the first name is shortened.
  function resourceName(r) {
    const owners = r.owners || [];
    const more = owners.length > 1 ? ` +${owners.length - 1} more` : "";
    if (more && r.label_name === owners[0] + more) return shortName(owners[0]) + more;
    return shortName(r.label_name);
  }

  const measureCtx = document.createElement("canvas").getContext("2d");
  function textWidth(text, font) {
    measureCtx.font = font;
    return measureCtx.measureText(text).width;
  }

  /* One label line broken into lines no wider than TEXT_W[kind], after "- _ . /" or
     whitespace (a part too wide on its own is broken anywhere). Explicit line breaks
     make cytoscape's label box, and so the layout spacing, fit the wrapped text, and
     carry over unchanged into the SVG / draw.io exports. */
  function wrapLine(text, kind) {
    const maxW = TEXT_W[kind];
    const font = FONTS[kind];
    if (!text || textWidth(text, font) <= maxW) return text || "";
    const lines = [];
    let line = "";
    const push = (part) => {
      if (line && textWidth(line + part, font) > maxW) {
        lines.push(line.trimEnd());
        line = "";
      }
      line += line ? part : part.trimStart();
    };
    (text.match(/[^\-_./\s]+[\-_./\s]*|[\-_./\s]+/g) || [text]).forEach((part) => {
      if (textWidth(part, font) <= maxW) {
        push(part);
        return;
      }
      Array.from(part).forEach((ch) => push(ch));
    });
    if (line.trim()) lines.push(line.trimEnd());
    return lines.join("\n");
  }

  function resourceLabel(r) {
    const lines = [wrapLine(resourceName(r), "res")];
    if (r.name !== r.type_label) lines.push(r.type_label);
    lines.push(...r.ips.slice(0, MAX_IPS_IN_LABEL));
    if (r.ips.length > MAX_IPS_IN_LABEL) lines.push(`+${r.ips.length - MAX_IPS_IN_LABEL} more`);
    return lines.join("\n");
  }

  function resourceTitle(r) {
    const lines = [r.name];
    if (r.type_label !== r.name) lines.push(r.type_label);
    if (r.owners && r.owners.length > 1) {
      lines.push(`Shared by ${r.owners.length}:`, ...r.owners.map((o) => "  " + o));
    } else if (r.ref && r.ref !== r.name) {
      lines.push(r.ref);
    }
    lines.push(r.eni_id, ...r.ips);
    return lines.join("\n");
  }

  function usage(s) {
    return `used ${s.used} · idle ${s.idle} · free ${s.free} / ${s.size}`;
  }

  function subnetLabel(s) {
    return [wrapLine(shortName(s.label_name), "subnet"), wrapLine(s.label_meta, "subnet"), usage(s)]
      .join("\n");
  }

  function subnetTitle(s, facts) {
    return [s.name || s.subnet_id, s.subnet_id, `${s.cidr} · ${s.az}`, usage(s), ...(facts || [])].join("\n");
  }

  function iconUrl(file) {
    return (file.startsWith("ext/") ? iconRoot : iconBase) + file;
  }

  // Extended view: a regional service or external gateway node.
  function extLabel(n) {
    const lines = [wrapLine(shortName(n.label_name), "res"), n.service_label];
    if (n.broad_access) lines.push("⚠ broad access");
    return lines.join("\n");
  }

  function extTitle(n) {
    const lines = [n.label_name, n.service_label];
    if (n.arn) lines.push(n.arn);
    return lines.concat(n.facts || []).join("\n");
  }

  function vpcLabel(vpc) {
    return [wrapLine(shortName(vpc.label_name), "vpc"), wrapLine(`${vpc.vpc_id} · ${vpc.label_cidrs}`, "vpc")]
      .join("\n");
  }

  // "14 × VPC endpoint: lambda, sts, …" (mirrors iplens.queries.group_name; member
  // names are shortened with the other labels).
  function groupName(g) {
    const names = g.member_names || [];
    const shown = names.slice(0, GROUP_LABEL_MEMBERS).map(shortName);
    const base = `${g.count} × ${g.type_label}`;
    if (!shown.length) return base;
    return `${base}: ${shown.join(", ")}${names.length > shown.length ? ", …" : ""}`;
  }

  function groupLabel(g, expanded) {
    return `${expanded ? "▾" : "▸"} ${wrapLine(groupName(g), "res")}\n` +
      `${g.ip_count} IPs · click to ${expanded ? "collapse" : "expand"}`;
  }

  function groupTitle(g) {
    const names = g.member_names || [];
    const lines = [`${g.count} × ${g.type_label} · ${g.ip_count} IPs`, ...names.slice(0, MAX_TITLE_LINES)];
    if (names.length > MAX_TITLE_LINES) lines.push(`… +${names.length - MAX_TITLE_LINES} more`);
    return lines.join("\n");
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
        iconFile: r.icon,
        eni: r.eni_id,
        raw: r,
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
        label: vpcLabel(vpc),
        title: [vpc.name || vpc.vpc_id, vpc.vpc_id, ...vpc.cidrs].join("\n"),
        icon: iconBase + data.icons.vpc,
        iconFile: data.icons.vpc,
        raw: vpc,
      },
      classes: "vpc",
      grabbable: false,  // dragging the whole VPC would only look like panning
    }];
    const ext = data.extended;
    const facts = (ext && ext.subnet_facts) || {};
    vpc.subnets.forEach((s, si) => {
      const sid = "subnet:" + s.subnet_id;
      els.push({
        group: "nodes",
        data: {
          id: sid, parent: "vpc", order: si, label: subnetLabel(s),
          title: subnetTitle(s, facts[s.subnet_id]), raw: s,
        },
        classes: "subnet" + (s.items.length ? "" : " empty"),
      });
      s.items.forEach((item, i) => {
        if (item.kind === "group") {
          els.push({
            group: "nodes",
            data: {
              id: item.id, parent: sid, order: i, label: groupLabel(item, false),
              title: groupTitle(item), expanded: false,
              icon: iconBase + item.icon, iconFile: item.icon, raw: item,
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
    if (ext) {
      // "Regional services" / "External" boxes beside (never inside) the VPC.
      Object.entries(ext.areas || {}).forEach(([area, label]) => {
        const members = ext.nodes.filter((n) => n.area === area);
        if (!members.length) return;
        els.push({
          group: "nodes",
          data: { id: "area:" + area, label: label, title: label, area: area },
          classes: "area",
          grabbable: false,
        });
        members.forEach((n, i) => {
          els.push({
            group: "nodes",
            data: {
              id: n.id, parent: "area:" + area, order: i, label: extLabel(n), title: extTitle(n),
              icon: iconUrl(n.icon), iconFile: n.icon, service: n.service, raw: n,
            },
            classes: "ext" + (n.broad_access ? " broad" : ""),
          });
        });
      });
    }
    return els;
  }

  // Rebuild every node label, e.g. after "Shorten long names" was toggled.
  function refreshLabels(cy) {
    cy.batch(() => {
      cy.nodes().forEach((n) => {
        const raw = n.data("raw");
        if (n.hasClass("vpc")) n.data("label", vpcLabel(raw));
        else if (n.hasClass("subnet")) n.data("label", subnetLabel(raw));
        else if (n.hasClass("res")) n.data("label", resourceLabel(raw));
        else if (n.hasClass("group")) n.data("label", groupLabel(raw, n.data("expanded")));
        else if (n.hasClass("ext")) n.data("label", extLabel(raw));
      });
    });
  }

  // -- "Group by": dashed boxes around resources sharing an SG / tag value / TF root ----

  function contextKeys(raw, mode, tagKey, data) {
    if (mode === "sg") {
      return (raw.sgs || []).map((id) => ({ key: "sg:" + id, label: "SG " + ((data.sg_names || {})[id] || id) }));
    }
    if (mode === "tag") {
      const tags = raw.tags || {};
      if (!tagKey || !Object.prototype.hasOwnProperty.call(tags, tagKey)) return [];
      return [{ key: "tag:" + tags[tagKey], label: `${tagKey}=${tags[tagKey]}` }];
    }
    if (mode === "tf") {
      const roots = Array.from(new Set((raw.tf || []).map((m) => m.root)));
      if (!roots.length) return [{ key: "tf:", label: "Terraform: unmanaged", unmanaged: true }];
      return roots.map((r) => ({ key: "tf:" + r, label: "Terraform: " + r }));
    }
    return [];
  }

  /* Rebuild the context boxes: one non-compound "ctx" node per SG / tag value / root,
     sized to the bounding box of its resources (a collapsed member counts through its
     group node) and drawn behind them; the resources get an outline in its colour.
     A resource can sit in several boxes (several SGs); it is outlined in the first. */
  function syncContext(cy, data) {
    const mode = groupBySelect ? groupBySelect.value : "";
    const tagKey = groupTagSelect ? groupTagSelect.value : "";
    cy.batch(() => {
      cy.nodes(".ctx").remove();
      cy.nodes(".tinted").removeClass("tinted").removeData("color");
      if (!mode) return;
      const boxes = new Map();
      cy.nodes(".res").forEach((n) => {
        const shown = n.hasClass("hidden") ? n.data("memberOf") : n.id();
        contextKeys(n.data("raw"), mode, tagKey, data).forEach((k) => {
          if (!boxes.has(k.key)) boxes.set(k.key, { ...k, shown: new Set(), members: [] });
          const box = boxes.get(k.key);
          box.shown.add(shown);
          box.members.push(n.id());
        });
      });
      Array.from(boxes.values())
        .sort((a, b) => (a.unmanaged ? 1 : 0) - (b.unmanaged ? 1 : 0) || a.label.localeCompare(b.label))
        .forEach((box, i) => {
          const color = box.unmanaged ? UNMANAGED_COLOR : PALETTE[i % PALETTE.length];
          const nodes = cy.collection(Array.from(box.shown).map((id) => cy.getElementById(id)));
          const bb = nodes.boundingBox({ includeLabels: true, includeOverlays: false });
          const pad = CTX_PAD + (i % 3) * 4;  // boxes around the same nodes stay apart
          cy.add({
            group: "nodes",
            data: {
              id: "ctx:" + i, label: box.label, color: color, members: box.members,
              w: bb.w + 2 * pad, h: bb.h + 2 * pad + CTX_LABEL_H,
              title: `${box.label}\n${box.members.length} resource(s)`,
            },
            position: { x: (bb.x1 + bb.x2) / 2, y: (bb.y1 + bb.y2) / 2 - CTX_LABEL_H / 2 },
            classes: "ctx",
            grabbable: false,
            selectable: false,
          });
          nodes.forEach((n) => {
            if (!n.data("color")) n.data("color", color);
            n.addClass("tinted");
          });
        });
    });
  }

  function populateTagKeys(data) {
    if (!groupTagSelect) return;
    const wanted = groupTagSelect.dataset.selected || "";
    (data.tag_keys || []).forEach((k) => {
      const opt = document.createElement("option");
      opt.value = k;
      opt.textContent = k;
      opt.selected = k === wanted;
      groupTagSelect.appendChild(opt);
    });
    if (!groupTagSelect.value && data.tag_keys && data.tag_keys.length) {
      groupTagSelect.value = data.tag_keys[0];
    }
  }

  function rememberGroupBy() {
    const params = new URLSearchParams(window.location.search);
    params.delete("group");
    params.delete("tag");
    if (groupBySelect.value) params.set("group", groupBySelect.value);
    if (groupBySelect.value === "tag" && groupTagSelect.value) params.set("tag", groupTagSelect.value);
    window.history.replaceState(null, "", `${window.location.pathname}?${params}`);
  }

  // -- edges --------------------------------------------------------------------------

  function enabledEdgeTypes() {
    return new Set(edgeBoxes.filter((b) => b.checked).map((b) => b.value));
  }

  function enabledEvidence() {
    return new Set(evidenceBoxes.filter((b) => b.checked).map((b) => b.value));
  }

  // A member hidden inside a collapsed group is drawn through its group node
  // (unless ``expandAll``: exports with "Expand all groups" keep the member).
  // Extended view endpoints ("vpc", "x:<service>:<name>") are node ids already; a node
  // hidden by the service filter takes its edges with it.
  function endpointId(cy, id, expandAll) {
    if (id === "vpc" || id.startsWith("x:")) {
      const x = cy.getElementById(id);
      return x.nonempty() && !x.hasClass("filtered") ? id : null;
    }
    const n = cy.getElementById("res:" + id);
    if (n.empty()) return null;
    return n.hasClass("hidden") && !expandAll ? n.data("memberOf") : n.id();
  }

  function bestEvidence(lines) {
    return EVIDENCE.find((lvl) => lines.some((ln) => ln.evidence === lvl)) || "configured";
  }

  /* Edges as drawn: endpoints mapped onto visible nodes, edges of one type between the
     same two nodes merged. In the Extended view only evidence lines of the ticked
     levels count, and an edge without any is left out. */
  function visibleEdges(cy, edges, types, expandAll) {
    const merged = new Map();
    const levels = enabledEvidence();
    edges.forEach((e) => {
      if (e.type !== "ext" && !types.has(e.type)) return;
      const lines = extended ? (e.lines || []).filter((ln) => levels.has(ln.evidence)) : [];
      if (extended && !lines.length) return;
      const s = endpointId(cy, e.source, expandAll);
      const t = endpointId(cy, e.target, expandAll);
      if (!s || !t || s === t) return;
      const key = `${e.type}|${s}|${t}`;
      const m = merged.get(key);
      if (m) {
        m.n += 1;
        if (m.titles.length < MAX_TITLE_LINES) m.titles.push(e.title);
        m.lines.push(...lines);
      } else {
        merged.set(key, {
          type: e.type, source: s, target: t, label: e.label, titles: [e.title], n: 1, lines: lines,
        });
      }
    });
    const items = Array.from(merged.values());
    items.forEach((m) => {
      m.evidence = extended ? bestEvidence(m.lines) : "";
      if (extended && m.type === "ext") {
        const best = m.lines.find((ln) => ln.evidence === m.evidence);
        m.label = best ? best.label : m.label;
      }
    });
    return items;
  }

  function edgeLabel(m) {
    const extra = m.type === "ext" && m.lines.length > 1 ? ` +${m.lines.length - 1}` : "";
    return (m.n > 1 ? `${shortName(m.label)} ×${m.n}` : shortName(m.label)) + extra;
  }

  // Export edge type: the evidence style in the Extended view, else the edge type.
  function exportType(type, evidence) {
    return extended ? "ev_" + (evidence || "configured") : type;
  }

  function syncEdges(cy, edges) {
    const items = visibleEdges(cy, edges, enabledEdgeTypes());
    cy.batch(() => {
      cy.edges().remove();
      cy.add(items.map((m, i) => ({
        group: "edges",
        data: {
          id: "edge:" + i,
          etype: m.type,
          evidence: m.evidence,
          lines: m.lines,
          source: m.source,
          target: m.target,
          label: edgeLabel(m),
          title: extended
            ? m.lines.slice(0, MAX_TITLE_LINES).map((ln) => `[${ln.evidence}] ${ln.text}`).join("\n") +
              (m.lines.length > MAX_TITLE_LINES ? `\n… +${m.lines.length - MAX_TITLE_LINES} more (click for all)` : "")
            : m.titles.join("\n") + (m.n > m.titles.length ? `\n… +${m.n - m.titles.length} more` : ""),
        },
        classes: "edge-" + m.type + (extended ? " ev-" + m.evidence : ""),
      })));
    });
  }

  // -- extended view: service filter, detail panel, layout beside the VPC -------------

  function populateServiceFilters(cy, data, onChange) {
    if (!serviceFilters || !data.extended) return;
    const services = data.extended.services || [];
    if (services.length) document.getElementById("service-filters-empty").remove();
    services.forEach((s) => {
      const label = document.createElement("label");
      label.className = "edge-filter";
      const box = document.createElement("input");
      box.type = "checkbox";
      box.name = "service";
      box.value = s.service;
      box.checked = true;
      box.addEventListener("change", () => {
        cy.nodes(".ext").filter((n) => n.data("service") === s.service).toggleClass("filtered", !box.checked);
        // An area whose every node is filtered out disappears too.
        cy.nodes(".area").forEach((a) => {
          a.toggleClass("filtered", a.children().every((c) => c.hasClass("filtered")));
        });
        onChange();
      });
      label.append(box, ` ${s.label} `);
      const count = document.createElement("span");
      count.className = "muted";
      count.textContent = `(${s.count})`;
      label.append(count);
      serviceFilters.append(label);
    });
  }

  function nodeName(cy, id) {
    const n = cy.getElementById(id);
    const raw = n.data("raw") || {};
    return raw.label_name || raw.name || n.id();
  }

  // Every evidence line of an edge (or the facts of a service node), as plain text.
  function showDetail(title, lines) {
    if (!detail) return;
    document.getElementById("edge-detail-title").textContent = title;
    const list = document.getElementById("edge-detail-lines");
    list.replaceChildren(...lines.map((ln) => {
      const li = document.createElement("li");
      if (ln.evidence) {
        const badge = document.createElement("span");
        badge.className = "badge ev-" + ln.evidence;
        badge.textContent = ln.evidence;
        li.append(badge, " ");
      }
      li.append(ln.text);
      return li;
    }));
    detail.hidden = false;
  }

  /* Place the "Regional services" area to the right of the VPC and the "External" area
     to its left, each a grid of nodes (sorted by service, then name). */
  function placeExtended(cy) {
    const areas = cy.nodes(".area");
    if (areas.empty()) return;
    const vpc = cy.getElementById("vpc").boundingBox({ includeLabels: true });
    cy.batch(() => {
      areas.forEach((area) => {
        const kids = area.children().sort((a, b) => {
          const ra = a.data("raw"), rb = b.data("raw");
          return ra.service.localeCompare(rb.service) || ra.label_name.localeCompare(rb.label_name);
        });
        let cellW = CELL_W, cellH = CELL_H;
        kids.forEach((k) => {
          const dim = k.layoutDimensions({ nodeDimensionsIncludeLabels: true });
          cellW = Math.max(cellW, dim.w + CELL_GAP);
          cellH = Math.max(cellH, dim.h + CELL_GAP);
        });
        const regional = area.data("area") === "regional";
        const cols = regional ? Math.min(EXT_COLS, kids.length) : 1;
        const x0 = regional ? vpc.x2 + EXT_GAP + cellW / 2 : vpc.x1 - EXT_GAP - cellW / 2;
        const y0 = vpc.y1 + 60;
        kids.forEach((k, i) => {
          k.position({ x: x0 + (i % cols) * cellW, y: y0 + Math.floor(i / cols) * cellH });
        });
      });
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
  // Cells grow with the widest / tallest wrapped label so labels never overlap.
  function gridLayout(cy) {
    let x0 = 0, y0 = 0, rowH = 0, col = 0;
    const subnets = cy.nodes(".subnet").sort((a, b) => a.data("order") - b.data("order"));
    cy.batch(() => {
      subnets.forEach((sn) => {
        const kids = sortedKids(sn);
        const n = Math.max(kids.length, 1);
        const cols = Math.min(COLS, n);
        const rows = Math.ceil(n / cols);
        let cellW = CELL_W, cellH = CELL_H;
        kids.forEach((k) => {
          const dim = k.layoutDimensions({ nodeDimensionsIncludeLabels: true });
          cellW = Math.max(cellW, dim.w + CELL_GAP);
          cellH = Math.max(cellH, dim.h + CELL_GAP);
        });
        const labelW = sn.boundingBox({ includeNodes: false, includeLabels: true }).w || 0;
        if (kids.length) {
          kids.forEach((k, i) => {
            k.position({ x: x0 + (i % cols) * cellW, y: y0 + Math.floor(i / cols) * cellH });
          });
        } else {
          sn.position({ x: x0 + cellW / 2, y: y0 });
        }
        x0 += Math.max(cols * cellW, 2 * CELL_W, labelW) + SUBNET_GAP_X;
        rowH = Math.max(rowH, rows * cellH);
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
     SG and reach edges are left out: they are numerous and often cyclic. */
  function dagreLayout(cy, edges) {
    const g = new dagre.graphlib.Graph({ compound: true, multigraph: true });
    g.setGraph({ rankdir: "TB", nodesep: 30, ranksep: 40, marginx: 20, marginy: 20 });
    g.setDefaultEdgeLabel(() => ({}));

    // Extended view nodes are placed beside the VPC afterwards (placeExtended).
    const leaves = [];
    cy.nodes().filter((n) => !n.hasClass("hidden") && !n.hasClass("ctx") && !n.hasClass("area") &&
      !n.hasClass("ext")).forEach((n) => {
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
    visibleEdges(cy, edges, new Set(["targets", "ecs_lb"])).filter((e) => e.type !== "ext").forEach((e) => {
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

  // -- saved positions, borders and server state ----------------------------------------

  function post(url, fields) {
    const body = new URLSearchParams({ csrf_token: csrf, ...fields });
    return fetch(url, { method: "POST", body: body, credentials: "same-origin" }).then((r) => {
      if (!r.ok) throw new Error("HTTP " + r.status);
    });
  }

  function leaves(cy) {
    return cy.nodes().filter((n) => !n.isParent() && !n.hasClass("hidden") && !n.hasClass("ctx"));
  }

  function applySaved(cy) {
    cy.batch(() => {
      leaves(cy).forEach((n) => {
        const p = saved[n.id()];
        if (p) n.position({ x: p.x, y: p.y });
      });
    });
  }

  let saveTimer = null;
  function savePositions(cy) {
    // Merge, so members of a collapsed group keep their saved spot.
    leaves(cy).forEach((n) => {
      const p = n.position();
      saved[n.id()] = { x: Math.round(p.x * 10) / 10, y: Math.round(p.y * 10) / 10 };
    });
    clearTimeout(saveTimer);
    saveTimer = setTimeout(() => {
      post(container.dataset.layoutUrl, { vpc: vpcId, positions: JSON.stringify(saved) })
        .then(() => { note.textContent = "Layout saved for this account and VPC."; })
        .catch((err) => { note.textContent = `Could not save the layout (${err.message}).`; });
    }, SAVE_DELAY_MS);
  }

  function applyBorders(cy) {
    cy.batch(() => {
      cy.nodes(".vpc").toggleClass("noborder", !showVpcBox.checked);
      cy.nodes(".subnet").toggleClass("noborder", !showSubnetsBox.checked);
    });
  }

  // Only the posted toggles change server-side.
  function savePrefs(fields) {
    post(container.dataset.prefsUrl, fields)
      .catch((err) => { note.textContent = `Could not save the setting (${err.message}).`; });
  }

  function saveBorders() {
    savePrefs({
      show_vpc: showVpcBox.checked ? "1" : "0",
      show_subnets: showSubnetsBox.checked ? "1" : "0",
    });
  }

  // -- export -------------------------------------------------------------------------

  function nodeKind(n) {
    if (n.hasClass("vpc")) return "vpc";
    if (n.hasClass("subnet")) return "subnet";
    if (n.hasClass("ctx")) return "ctx";
    if (n.hasClass("area")) return "area";
    return n.hasClass("group") ? "group" : "res";
  }

  function groupMembers(cy, group) {
    return cy.nodes(".member").filter((n) => n.data("memberOf") === group.id());
  }

  /* The diagram as drawn: visible nodes with absolute boxes, visible edges. With
     ``expand`` ("Expand all groups") a collapsed group also carries its members and
     the edges go to the members; the server lays the members out in place of the
     group box (iplens.diagram.expand_groups). An expanded group's header is left out. */
  function currentView(cy, dataEdges, expand) {
    const nodes = [];
    cy.nodes().filter((n) => n.visible()).forEach((n) => {
      const kind = nodeKind(n);
      if (expand && kind === "group" && n.data("expanded")) return;
      const bb = n.boundingBox({ includeLabels: false, includeOverlays: false });
      const node = {
        id: n.id(),
        kind: kind,
        parent: n.parent().nonempty() ? n.parent().id() : null,
        label: n.data("label") || "",
        x: bb.x1, y: bb.y1, w: bb.w, h: bb.h,
        icon: n.data("iconFile") || "",
        idle: n.hasClass("idle"),
        color: n.data("color") || "",
      };
      if (kind === "ctx") node.member_ids = n.data("members") || [];
      if (expand && kind === "group") {
        node.members = groupMembers(cy, n).map((m) => ({
          id: m.id(),
          label: m.data("label") || "",
          icon: m.data("iconFile") || "",
          idle: m.hasClass("idle"),
          color: m.data("color") || "",
          w: m.width(),
          h: m.height(),
        }));
      }
      nodes.push(node);
    });
    const edges = expand
      ? visibleEdges(cy, dataEdges, enabledEdgeTypes(), true).map((m) => ({
        source: m.source,
        target: m.target,
        type: exportType(m.type, m.evidence),
        label: edgeLabel(m),
      }))
      : cy.edges().filter((e) => e.visible()).map((e) => ({
        source: e.source().id(),
        target: e.target().id(),
        type: exportType(e.data("etype"), e.data("evidence")),
        label: e.data("label") || "",
      }));
    return {
      vpc_id: vpcId,
      mode: extended ? "extended" : "ip",
      show_vpc: showVpcBox.checked,
      show_subnets: showSubnetsBox.checked,
      expand_groups: Boolean(expand),
      nodes: nodes,
      edges: edges,
    };
  }

  // A hidden form POST: the attachment response downloads without leaving the page.
  function download(url, view) {
    const form = document.createElement("form");
    form.method = "post";
    form.action = url;
    form.hidden = true;
    [["csrf_token", csrf], ["view", JSON.stringify(view)]].forEach(([name, value]) => {
      const input = document.createElement("input");
      input.type = "hidden";
      input.name = name;
      input.value = value;
      form.appendChild(input);
    });
    document.body.appendChild(form);
    form.submit();
    form.remove();
  }

  function runLayout(cy, edges) {
    let done = false;
    if (layoutSelect.value === "dagre" && typeof dagre !== "undefined") {
      try {
        dagreLayout(cy, edges);
        done = true;
      } catch (err) {
        console.warn("dagre layout failed, using grid layout", err);
        layoutSelect.value = "grid";
      }
    }
    if (!done) gridLayout(cy);
    if (extended) placeExtended(cy);
  }

  // -- focus (single click): highlight one node's edges, dim the rest ------------------

  // Only leaves are dimmed: opacity on a subnet/VPC box would also fade its children.
  function applyFocus(cy, nodeId) {
    cy.batch(() => {
      cy.elements(".dim, .focus").removeClass("dim focus");
      const node = nodeId ? cy.getElementById(nodeId) : cy.collection();
      if (node.empty() || node.hasClass("hidden")) return;
      const edges = node.connectedEdges();
      const lit = node.union(edges.connectedNodes());
      cy.nodes(".res, .group, .ext").difference(lit).addClass("dim");
      cy.edges().difference(edges).addClass("dim");
      node.addClass("focus");
      edges.addClass("focus");
    });
  }

  function toggleGroup(cy, group, expand) {
    const members = groupMembers(cy, group);
    const expanded = expand === undefined ? members.hasClass("hidden") : expand;
    if (expanded) members.removeClass("hidden"); else members.addClass("hidden");
    group.data("expanded", expanded);
    group.data("label", groupLabel(group.data("raw"), expanded));
  }

  // -- style --------------------------------------------------------------------------

  const style = [
    { selector: "node", style: {
      // Labels arrive pre-wrapped by wrapLine; the slack absorbs measuring differences.
      "label": "data(label)", "font-size": 10, "text-wrap": "wrap", "text-max-width": TEXT_W.res + 4,
      "color": "#1f2933", "font-family": "system-ui, sans-serif",
    } },
    { selector: ".vpc", style: {
      "shape": "rectangle", "background-color": "#f7f3ff", "background-opacity": 1,
      "border-width": 2, "border-color": "#8c4fff", "padding": 50,
      "text-valign": "top", "text-halign": "center", "font-size": 14, "font-weight": "bold",
      "text-margin-y": -6, "text-max-width": TEXT_W.vpc + 4,
      "background-image": "data(icon)", "background-width": 32, "background-height": 32,
      "background-position-x": 0, "background-position-y": 0, "background-clip": "none",
    } },
    { selector: ".subnet", style: {
      "shape": "rectangle", "background-color": "#ffffff", "border-width": 1.5,
      "border-color": "#7aa116", "border-style": "solid", "padding": SUBNET_PAD,
      "text-valign": "top", "text-halign": "center", "font-size": 11, "text-margin-y": -4,
      "text-max-width": TEXT_W.subnet + 4, "min-width": SUBNET_MIN_W,
    } },
    { selector: ".subnet.empty", style: { "width": SUBNET_MIN_W, "height": 50 } },
    // Border toggles: the box disappears, its label stays.
    { selector: ".vpc.noborder", style: {
      "border-width": 0, "background-opacity": 0, "background-image-opacity": 0,
    } },
    { selector: ".subnet.noborder", style: { "border-width": 0, "background-opacity": 0 } },
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
    { selector: ".res.tinted, .group.tinted", style: {
      "outline-width": 2.5, "outline-color": "data(color)", "outline-offset": 2,
    } },
    // "Group by" boxes: translucent, never in the way of clicks, drags or tooltips.
    { selector: ".ctx", style: {
      "shape": "round-rectangle", "width": "data(w)", "height": "data(h)",
      "background-color": "data(color)", "background-opacity": 0.05,
      "border-width": 1.5, "border-style": "dashed", "border-color": "data(color)",
      "label": "data(label)", "color": "data(color)", "font-size": 10, "font-weight": "bold",
      "text-valign": "top", "text-halign": "center", "text-margin-y": CTX_LABEL_H,
      "events": "no",
    } },
    // Extended view: areas beside the VPC, service / gateway nodes, evidence styles.
    { selector: ".area", style: {
      "shape": "rectangle", "background-color": "#f6f7f9", "border-width": 2,
      "border-style": "dashed", "border-color": "#5b6573", "padding": 30,
      "text-valign": "top", "text-halign": "center", "font-size": 12, "font-weight": "bold",
      "text-margin-y": -6, "text-max-width": TEXT_W.vpc,
    } },
    { selector: ".ext", style: {
      "shape": "round-rectangle", "width": 44, "height": 44,
      "background-color": "#ffffff", "background-image": "data(icon)",
      "background-fit": "contain", "border-width": 0,
      "text-valign": "bottom", "text-halign": "center", "text-margin-y": 5,
    } },
    { selector: ".ext.broad", style: { "border-width": 3, "border-color": "#c2410c", "border-style": "dashed" } },
    { selector: ".hidden, .filtered", style: { "display": "none" } },
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
    { selector: "edge.edge-reach", style: {
      "line-style": "dashed", "line-dash-pattern": [3, 3], "width": 1.6, "line-color": "#b0469b",
      "target-arrow-color": "#b0469b", "target-arrow-shape": "vee", "color": "#7a2f6b",
    } },
    // Mirrors EDGE_STYLES["ev_*"] in iplens/diagram.py and the ev-* swatches in style.css.
    { selector: "edge.ev-observed", style: {
      "line-color": "#1a7f37", "target-arrow-color": "#1a7f37", "width": 3,
      "line-style": "solid", "target-arrow-shape": "triangle", "color": "#14532d",
    } },
    { selector: "edge.ev-configured", style: {
      "line-color": "#2457c5", "target-arrow-color": "#2457c5", "width": 2,
      "line-style": "solid", "target-arrow-shape": "triangle",
    } },
    { selector: "edge.ev-permitted", style: {
      "line-color": "#c2410c", "target-arrow-color": "#c2410c", "width": 1.8,
      "line-style": "dashed", "line-dash-pattern": [7, 4], "target-arrow-shape": "vee",
      "color": "#7c2d12", "opacity": 1,
    } },
    { selector: "edge.ev-referenced", style: {
      "line-color": "#6b7280", "target-arrow-color": "#6b7280", "width": 1.5,
      "line-style": "dashed", "line-dash-pattern": [2, 3], "target-arrow-shape": "vee",
      "color": "#374151", "opacity": 1,
    } },
    { selector: "node.dim", style: { "opacity": 0.2 } },
    { selector: "edge.dim", style: { "opacity": 0.08, "text-opacity": 0 } },
    { selector: "node.focus", style: { "overlay-color": "#2457c5", "overlay-opacity": 0.12 } },
    { selector: "edge:selected, edge.hover, edge.focus", style: {
      "width": 3, "opacity": 1, "z-index": 10,
    } },
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
    const ext = extended ? data.extended : null;
    const edges = (data.edges || []).concat(ext ? ext.edges || [] : []);
    const cy = cytoscape({
      container: container,
      elements: buildElements(data),
      style: style,
      layout: { name: "preset" },
      minZoom: 0.05,
      maxZoom: 3,
      boxSelectionEnabled: false,
    });
    applyBorders(cy);
    let focused = null;  // id of the node whose edges are highlighted
    const refreshEdges = () => {
      syncEdges(cy, edges);  // re-adds every edge, so the highlight is re-applied
      applyFocus(cy, focused);
    };
    populateTagKeys(data);
    const refreshContext = () => syncContext(cy, data);
    // Saved (dragged) positions always win over the automatic layout.
    const relayout = () => {
      refreshEdges();
      runLayout(cy, edges);
      applySaved(cy);
      refreshContext();
    };
    relayout();
    cy.fit(undefined, 30);

    // "onetap" fires only after the double-click window (multiClickDebounceTime) has
    // passed without a second tap, so a double-click never also toggles the highlight.
    cy.on("onetap", "node.res", (evt) => {
      focused = focused === evt.target.id() ? null : evt.target.id();
      applyFocus(cy, focused);
    });
    cy.on("dbltap", "node.res", (evt) => {
      window.location.href = eniUrl.replace("__ENI__", encodeURIComponent(evt.target.data("eni")));
    });
    cy.on("onetap", "node.group", (evt) => {
      toggleGroup(cy, evt.target);
      relayout();
    });
    cy.on("onetap", (evt) => {
      if (evt.target !== cy || !focused) return;
      focused = null;
      applyFocus(cy, null);
    });
    if (ext) {
      // Extended view: a service node highlights its edges and lists its facts; an edge
      // lists every evidence line behind it.
      cy.on("onetap", "node.ext", (evt) => {
        const n = evt.target;
        focused = focused === n.id() ? null : n.id();
        applyFocus(cy, focused);
        const raw = n.data("raw");
        const facts = (raw.facts || []).map((text) => ({ text: text }));
        if (raw.arn) facts.unshift({ text: raw.arn });
        showDetail(`${raw.service_label}: ${raw.label_name}`, facts.length ? facts : [{ text: "No further details." }]);
      });
      cy.on("onetap", "edge", (evt) => {
        const e = evt.target;
        const lines = e.data("lines") || [];
        showDetail(
          `${nodeName(cy, e.source().id())} → ${nodeName(cy, e.target().id())}: ` +
            `${lines.length} evidence line(s), strongest ${e.data("evidence")}`,
          lines,
        );
      });
      cy.on("mouseover", "node.ext, edge", () => { container.style.cursor = "pointer"; });
      cy.on("mouseout", "edge", () => { container.style.cursor = ""; });
      populateServiceFilters(cy, data, refreshEdges);
      evidenceBoxes.forEach((box) => box.addEventListener("change", refreshEdges));
      (ext.evidence_levels || []).forEach((lvl) => {
        const el = document.querySelector(`[data-evidence-count="${lvl.level}"]`);
        if (el) el.textContent = `(${lvl.count})`;
      });
      setupFlowLogs();
    }
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
      applySaved(cy);
      refreshContext();
      cy.fit(undefined, 30);
    });
    cy.on("dragfree", "node", () => {
      savePositions(cy);
      refreshContext();
    });
    // Boxes follow a dragged resource (at most once per frame).
    let contextFrame = 0;
    cy.on("drag", "node.res, node.group", () => {
      if (!groupBySelect.value || contextFrame) return;
      contextFrame = requestAnimationFrame(() => {
        contextFrame = 0;
        refreshContext();
      });
    });
    cy.on("grab", "node", hideTip);
    document.getElementById("reset-layout").addEventListener("click", () => {
      post(container.dataset.resetUrl, { vpc: vpcId })
        .then(() => {
          saved = {};
          runLayout(cy, edges);
          refreshContext();
          cy.fit(undefined, 30);
          note.textContent = "Layout reset.";
        })
        .catch((err) => { note.textContent = `Could not reset the layout (${err.message}).`; });
    });
    [showVpcBox, showSubnetsBox].forEach((box) => box.addEventListener("change", () => {
      applyBorders(cy);
      saveBorders();
    }));
    // Label sizes change, so the automatic layout is redone; dragged nodes keep their spot.
    shortenBox.addEventListener("change", () => {
      refreshLabels(cy);
      relayout();
      savePrefs({ shorten_names: shortenBox.checked ? "1" : "0" });
    });
    const exportView = () => currentView(cy, edges, expandExportBox && expandExportBox.checked);
    document.getElementById("export-svg").addEventListener("click", () => {
      download(container.dataset.exportSvg, exportView());
    });
    document.getElementById("export-drawio").addEventListener("click", () => {
      download(container.dataset.exportDrawio, exportView());
    });
    [groupBySelect, groupTagSelect].forEach((sel) => sel.addEventListener("change", () => {
      groupTagSelect.hidden = groupBySelect.value !== "tag";
      refreshContext();
      rememberGroupBy();
    }));
    edgeBoxes.forEach((box) => box.addEventListener("change", () => {
      refreshEdges();
      rememberEdgeFilter();
    }));

    (data.edge_types || []).forEach((t) => {
      const el = document.querySelector(`[data-edge-count="${t.type}"]`);
      if (el) el.textContent = `(${t.count})`;
    });
    const nRes = data.vpc.subnets.reduce((a, s) => a + s.resource_count, 0);
    const cut = (data.edge_types || []).filter((t) => t.truncated).map((t) => t.label);
    status.textContent = `${data.vpc.subnets.length} subnet(s) · ${nRes} resource ENI(s) · ` +
      `${edges.length} connection(s) · snapshot #${data.snapshot_id}` +
      (cut.length ? ` · truncated: ${cut.join(", ")}` : "") +
      (ext ? ` · ${ext.nodes.length} regional / external node(s)` +
        (ext.hidden_nodes ? ` (${ext.hidden_nodes} crawled node(s) not linked to this VPC hidden)` : "") +
        (ext.crawl ? "" : " · services not crawled yet") +
        (ext.flow ? ` · flow logs: ${ext.flow.pairs} aggregate(s), ${ext.flow.bytes_label} scanned` : "")
        : "");
  }

  // -- extended view: opt-in flow log query (estimate first, then confirm) --------------

  function setupFlowLogs() {
    const box = document.getElementById("flow-logs");
    if (!box) return;
    const windowSelect = document.getElementById("flow-window");
    const estimateBtn = document.getElementById("flow-estimate");
    const runBtn = document.getElementById("flow-run");
    const result = document.getElementById("flow-estimate-result");
    const postJson = (url, fields) => {
      const body = new URLSearchParams({ csrf_token: csrf, vpc: vpcId, ...fields });
      return fetch(url, { method: "POST", body: body, credentials: "same-origin" }).then((r) => {
        if (!r.ok) throw new Error("HTTP " + r.status);
        return r.json();
      });
    };
    // A changed window needs a new estimate before the query can run.
    windowSelect.addEventListener("change", () => {
      runBtn.hidden = true;
      result.textContent = "";
    });
    estimateBtn.addEventListener("click", () => {
      runBtn.hidden = true;
      estimateBtn.disabled = true;
      result.textContent = "Estimating…";
      postJson(box.dataset.estimateUrl, { window: windowSelect.value })
        .then((r) => {
          if (!r.ok) {
            result.textContent = r.error;
            return;
          }
          const warn = (r.warnings || []).join(" ");
          if (!r.log_groups.length) {
            result.textContent = warn || "No flow logs found for this VPC.";
            return;
          }
          result.textContent = `Estimated scan over ${r.window_label}: ${r.estimated_label} ` +
            `(${r.cost_label}) in ${r.log_groups.length} log group(s).` + (warn ? ` ${warn}` : "");
          runBtn.textContent = `Run query (≈ ${r.estimated_label})`;
          runBtn.hidden = false;
        })
        .catch((err) => { result.textContent = `Estimate failed (${err.message}).`; })
        .finally(() => { estimateBtn.disabled = false; });
    });
    runBtn.addEventListener("click", () => {
      runBtn.disabled = true;
      estimateBtn.disabled = true;
      result.textContent = "Running Logs Insights query… this can take up to two minutes.";
      postJson(box.dataset.runUrl, { window: windowSelect.value, confirm: "1" })
        .then((r) => {
          if (!r.ok) {
            result.textContent = r.error;
            return;
          }
          result.textContent = `Done: ${r.pairs} ENI↔ENI/port aggregate(s) stored, ` +
            `${r.bytes_label} scanned. Reloading…`;
          window.location.reload();
        })
        .catch((err) => { result.textContent = `Query failed (${err.message}).`; })
        .finally(() => {
          runBtn.disabled = false;
          estimateBtn.disabled = false;
          runBtn.hidden = true;
        });
    });
  }

  fetch(container.dataset.src, { credentials: "same-origin" })
    .then((r) => {
      if (!r.ok) throw new Error("HTTP " + r.status);
      return r.json();
    })
    .then(render)
    .catch((err) => { status.textContent = "Could not load diagram data (" + err.message + ")."; });
})();
