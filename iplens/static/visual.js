/* IPLens Visual page: nested VPC -> subnet -> resource diagram with resource edges
   (cytoscape.js + dagre, both vendored). The Extended view (data-mode="extended") adds
   regional services and external gateways and is decluttered (rules in declutter.js):
     - one edge per node pair, styled by its strongest shown evidence level
       (observed > configured > permitted > referenced), "+N" for further evidence;
     - regional services of one type and Lambda / ECS ENIs of a subnet are collapsible
       groups; edges between collapsed groups merge into one, wider with its count;
     - one left-to-right dagre layout (sources -> compute -> targets), edges routed
       along dagre's paths; swimlanes per app when grouping by tag / Terraform root;
     - focus mode: a clicked or searched node and its 1- or 2-hop neighbourhood only.
   Both views share the toolbar: the Layout choice (grid by default; dagre, or a
   cytoscape.js layout applied box by box) and the expanded groups are remembered per
   account and view, dragged positions per account, VPC and view. */
(function () {
  "use strict";

  const CELL_W = 170;          // horizontal spacing of resource nodes inside a subnet
  const CELL_H = 140;          // vertical spacing (icon + name + up to 4 IP lines)
  const COLS = 4;              // resource columns per subnet box
  const SUBNETS_PER_ROW = 3;
  const SUBNET_MIN_W = 2 * CELL_W - 40;
  const SUBNET_PAD = 28;
  const SUBNET_LABEL_H = 48;   // three 11px lines above each subnet box
  const MAX_IPS_IN_LABEL = 3;
  const MAX_TITLE_LINES = 12;  // tooltip lines listed for an edge merged into a group node
  const CELL_GAP = 24;         // grid layout: space between two wrapped resource labels
  const BLOCK_GAP_X = 90;      // block layouts: space between two boxes in a row
  const BLOCK_GAP_Y = 60;      // ... and between two rows (box labels are measured)
  const container = document.getElementById("cy");
  if (!container || typeof cytoscape === "undefined") return;
  const extended = container.dataset.mode === "extended";
  // The Extended view draws bigger icons and labels so that it stays readable at Fit;
  // Fit never zooms out below MIN_READABLE_ZOOM there (pan or zoom out to see the rest).
  const ICON = extended ? 56 : 44;
  const RES_FONT = extended ? 12 : 10;
  const MIN_READABLE_ZOOM = 0.6;
  // Label line widths in px; full names are wrapped after "- _ . /" to fit.
  const TEXT_W = { res: extended ? 200 : 180, subnet: 300, vpc: 420 };
  const FONTS = {
    res: `normal normal ${RES_FONT}px system-ui, sans-serif`,
    subnet: "normal normal 11px system-ui, sans-serif",
    vpc: "normal bold 14px system-ui, sans-serif",
  };
  const NOT_SET = "(not set)";  // mirrors iplens.environment.NOT_SET_LABEL
  const status = document.getElementById("cy-status");
  const note = document.getElementById("cy-note");
  const tip = document.getElementById("cy-tip");
  const layoutSelect = document.getElementById("layout");
  const edgeBoxes = Array.from(document.querySelectorAll('input[type="checkbox"][name="edges"]'));
  const iconBase = container.dataset.icons;
  const eniUrl = container.dataset.eniUrl;
  const csrf = container.dataset.csrf;
  const vpcId = container.dataset.vpc;
  const layoutKey = container.dataset.layoutKey || vpcId;  // saved positions per view
  const showVpcBox = document.getElementById("show-vpc");
  const showSubnetsBox = document.getElementById("show-subnets");
  const showLegendBox = document.getElementById("show-legend");
  const legend = document.getElementById("visual-legend");
  const shortenBox = document.getElementById("shorten-names");
  const groupBySelect = document.getElementById("group-by");
  const groupTagSelect = document.getElementById("group-tag");
  const expandExportBox = document.getElementById("export-expand");
  const envFilters = document.getElementById("env-filters");
  const view = extended ? "extended" : "ip";  // per-view state key (iplens.viewstate.VIEWS)
  const iconRoot = container.dataset.iconRoot;
  const evidenceBoxes = Array.from(document.querySelectorAll('input[type="checkbox"][name="evidence"]'));
  const serviceFilters = document.getElementById("service-filters");
  const detail = document.getElementById("edge-detail");
  const focusSearch = document.getElementById("focus-search");
  const focusHops = document.getElementById("focus-hops");
  const focusReset = document.getElementById("focus-reset");
  const D = window.IPLensDeclutter;
  const GROUP_THRESHOLD = 10;  // mirrors iplens.queries.VISUAL_GROUP_THRESHOLD
  const COMPUTE_TYPES = new Set(["lambda", "ecs"]);
  const SHARED_LANE = "shared";
  const LANE_HEAD = 36;        // swimlanes: room for the lane title above each band
  const LANE_GAP = 56;
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

  // Extended view service group: "▸ SQS queue ×18" (collapsed node) / "▾ …" (box).
  function svcLabel(g, expanded) {
    const names = g.member_names.slice(0, GROUP_LABEL_MEMBERS).map(shortName);
    const more = g.member_names.length > names.length ? ", …" : "";
    const head = `${expanded ? "▾" : "▸"} ${g.type_label} ×${g.count}`;
    return expanded
      ? `${head} · click here to collapse`
      : `${head}\n${wrapLine(names.join(", ") + more, "res")}\nclick to expand`;
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
        else if (n.hasClass("svc")) n.data("label", svcLabel(raw, false));
        else if (n.hasClass("svcbox")) n.data("label", svcLabel(raw, true));
        else if (n.hasClass("group")) n.data("label", groupLabel(raw, n.data("expanded")));
        else if (n.hasClass("ext")) n.data("label", extLabel(raw));
        else if (n.hasClass("vpcleaf")) n.data("label", vpcLabel(raw));
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
    if (mode === "env") {
      const env = raw.environment || "";
      return [{ key: "env:" + env, label: "environment: " + (env || NOT_SET), unmanaged: !env }];
    }
    return [];
  }

  // -- environment filter (both views) --------------------------------------------------

  const ENV_PARAM = "envoff";  // URL: the unticked environments ("" = not set)

  function environmentsOf(data, extNodes) {
    const counts = new Map();
    const add = (env) => counts.set(env || "", (counts.get(env || "") || 0) + 1);
    allResources(data.vpc).forEach((r) => add(r.environment));
    (extNodes || []).forEach((n) => add(n.environment));
    return Array.from(counts.entries())
      .sort((a, b) => (a[0] === "" ? 1 : 0) - (b[0] === "" ? 1 : 0) || a[0].localeCompare(b[0]));
  }

  function envOff() {
    if (!envFilters) return new Set();
    return new Set(Array.from(envFilters.querySelectorAll('input[name="env"]'))
      .filter((b) => !b.checked).map((b) => b.value));
  }

  function populateEnvFilters(envs, onChange) {
    if (!envFilters) return;
    const initial = new URLSearchParams(window.location.search).getAll(ENV_PARAM);
    envFilters.querySelectorAll("label, #env-filters-empty").forEach((el) => el.remove());
    if (!envs.length) {
      const none = document.createElement("span");
      none.className = "muted small";
      none.id = "env-filters-empty";
      none.textContent = "No resources.";
      envFilters.append(none);
      return;
    }
    envs.forEach(([env, count]) => {
      const label = document.createElement("label");
      label.className = "edge-filter";
      const box = document.createElement("input");
      box.type = "checkbox";
      box.name = "env";
      box.value = env;
      box.checked = !initial.includes(env);
      box.addEventListener("change", () => {
        rememberEnvFilter();
        onChange();
      });
      const num = document.createElement("span");
      num.className = "muted";
      num.textContent = `(${count})`;
      label.append(box, ` ${env || NOT_SET} `, num);
      envFilters.append(label);
    });
  }

  function rememberEnvFilter() {
    const params = new URLSearchParams(window.location.search);
    params.delete(ENV_PARAM);
    envOff().forEach((env) => params.append(ENV_PARAM, env));
    window.history.replaceState(null, "", `${window.location.pathname}?${params}`);
  }

  /* IP view: resources of unticked environments disappear, and a group whose members are
     all gone with them (the Extended view folds this into applyServiceFilter). */
  function applyEnvFilterIp(cy) {
    const off = envOff();
    cy.batch(() => {
      cy.nodes(".res").forEach((n) => { n.toggleClass("filtered", off.has(n.data("raw").environment || "")); });
      cy.nodes(".group").forEach((g) => {
        g.toggleClass("filtered", groupMembers(cy, g).every((m) => m.hasClass("filtered")));
      });
    });
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
      if (!mode || laneMode()) return;  // Extended view: swimlanes instead of boxes
      const boxes = new Map();
      cy.nodes(".res").forEach((n) => {
        if (n.hasClass("filtered")) return;  // environment filter
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
  function endpointId(cy, id, expandAll) {
    const n = cy.getElementById("res:" + id);
    if (n.empty() || n.hasClass("filtered")) return null;
    return n.hasClass("hidden") && !expandAll ? n.data("memberOf") : n.id();
  }

  /* IP view edges as drawn: endpoints mapped onto visible nodes, edges of one type
     between the same two nodes merged. */
  function visibleEdges(cy, edges, types, expandAll) {
    const merged = new Map();
    edges.forEach((e) => {
      if (!types.has(e.type)) return;
      const s = endpointId(cy, e.source, expandAll);
      const t = endpointId(cy, e.target, expandAll);
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

  function edgeLabel(m) {
    return m.n > 1 ? `${shortName(m.label)} ×${m.n}` : shortName(m.label);
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
          source: m.source,
          target: m.target,
          label: edgeLabel(m),
          title: m.titles.join("\n") + (m.n > m.titles.length ? `\n… +${m.n - m.titles.length} more` : ""),
        },
        classes: "edge-" + m.type,
      })));
    });
  }

  // -- extended view: scene (lanes, groups), drawn edges, focus ------------------------

  // Expanded group ids (both views, saved per account, view and VPC); every other group
  // is collapsed.
  const expandedGroups = new Set(JSON.parse(document.getElementById("visual-expanded").textContent || "[]"));
  let focusId = null;  // node whose neighbourhood is shown (focus mode), else null

  // Swimlanes replace the "Group by" boxes for tags, Terraform roots and environments.
  function laneMode() {
    return extended && Boolean(groupBySelect) && ["tag", "tf", "env"].includes(groupBySelect.value);
  }

  // Extended view: crawled nodes not linked to this VPC that are drawn on request
  // ("Not linked" panel), or all of them with "Show all crawled nodes".
  const extraShown = new Set();
  const showAllCrawled = document.getElementById("show-all-crawled");

  function shownExtNodes(ext) {
    const all = showAllCrawled && showAllCrawled.checked;
    return (ext.nodes || []).concat((ext.hidden || []).filter((n) => all || extraShown.has(n.id)));
  }

  function hops() {
    const n = parseInt(focusHops ? focusHops.value : "1", 10);
    return D.FOCUS_HOPS.includes(n) ? n : D.FOCUS_HOPS[0];
  }

  function allResources(vpc) {
    const out = [];
    vpc.subnets.forEach((s) => s.items.forEach((item) => {
      (item.kind === "group" ? item.members : [item]).forEach((r) => out.push(r));
    }));
    return out;
  }

  /* Lane of every resource (its first tag value / Terraform root) and every regional
     node (the lane it has most connections to, a few passes so that a chain like
     rule -> function -> queue follows its function); the rest goes to a shared lane. */
  function assignLanes(data, resources, edges) {
    const mode = groupBySelect.value;
    const tagKey = groupTagSelect ? groupTagSelect.value : "";
    const lanes = new Map();
    const laneOf = new Map();  // edge endpoint id (ENI id, "x:…") -> lane key
    const unset = { key: "tag:", label: `${tagKey || "tag"}: not set`, unmanaged: true };
    resources.forEach((r) => {
      const k = contextKeys(r, mode, tagKey, data)[0] || unset;
      lanes.set(k.key, k);
      laneOf.set(r.eni_id, k.key);
    });
    const shownExt = shownExtNodes(data.extended);
    if (mode === "env") {  // a service with a known environment goes to its lane
      shownExt.filter((n) => n.environment).forEach((n) => {
        const k = contextKeys(n, mode, tagKey, data)[0];
        lanes.set(k.key, k);
        laneOf.set(n.id, k.key);
      });
    }
    const extNodes = shownExt.map((n) => n.id);
    for (let pass = 0; pass < 3; pass += 1) {
      extNodes.forEach((id) => {
        if (laneOf.has(id)) return;
        const votes = new Map();
        edges.forEach((e) => {
          const other = e.source === id ? e.target : e.target === id ? e.source : null;
          const k = other ? laneOf.get(other) : null;
          if (k) votes.set(k, (votes.get(k) || 0) + 1);
        });
        let best = null;
        votes.forEach((v, k) => {
          if (!best || v > best[1] || (v === best[1] && k < best[0])) best = [k, v];
        });
        if (best) laneOf.set(id, best[0]);
      });
    }
    lanes.set(SHARED_LANE, { key: SHARED_LANE, label: "Shared / not linked to one app", unmanaged: true });
    const ordered = Array.from(lanes.values())
      .sort((a, b) => (a.unmanaged ? 1 : 0) - (b.unmanaged ? 1 : 0) || a.label.localeCompare(b.label));
    const ids = new Map(ordered.map((l, i) => [l.key, "lane:" + i]));
    return {
      list: ordered.map((l, i) => ({
        id: ids.get(l.key), label: l.label, order: i,
        color: l.unmanaged ? UNMANAGED_COLOR : PALETTE[i % PALETTE.length],
      })),
      of: (id) => ids.get(laneOf.get(id) || SHARED_LANE),
    };
  }

  function extElement(n, parent, extra) {
    return {
      group: "nodes",
      data: {
        id: n.id, parent: parent, label: extLabel(n), title: extTitle(n),
        icon: iconUrl(n.icon), iconFile: n.icon, service: n.service, raw: n, ...extra,
      },
      classes: "ext" + (n.broad_access ? " broad" : "") + (n.linked === false ? " unlinked" : "") +
        (extra.memberOf ? " member hidden" : ""),
    };
  }

  function groupElement(id, parent, order, g) {
    return {
      group: "nodes",
      data: {
        id: id, parent: parent, order: order, label: groupLabel(g, false), title: groupTitle(g),
        expanded: false, icon: iconBase + g.icon, iconFile: g.icon, raw: g,
      },
      classes: "group",
    };
  }

  /* Extended view elements. Without swimlanes: VPC > subnets > resources, regional /
     external nodes at the top level. With swimlanes: one lane per app holding its
     resources and regional nodes (the VPC itself is a node of the shared lane).
     Inside each subnet / lane, Lambda and ECS ENIs of one type (from D.AGG_MIN on) and
     other types (above GROUP_THRESHOLD) become a collapsible group; regional nodes of
     one service (from D.AGG_MIN on) become a service group: a collapsed node, or when
     expanded a box ("svcbox") around its members. */
  function extElements(data, edges) {
    const vpc = data.vpc;
    const ext = data.extended;
    const resources = allResources(vpc);
    const facts = ext.subnet_facts || {};
    const lanes = laneMode() ? assignLanes(data, resources, edges) : null;
    const els = [];
    const vpcData = {
      id: "vpc", label: vpcLabel(vpc), title: [vpc.name || vpc.vpc_id, vpc.vpc_id, ...vpc.cidrs].join("\n"),
      icon: iconBase + data.icons.vpc, iconFile: data.icons.vpc, raw: vpc,
    };
    if (lanes) {
      lanes.list.forEach((l) => els.push({
        group: "nodes",
        data: { id: l.id, label: l.label, title: l.label, order: l.order, color: l.color },
        classes: "lane", grabbable: false, selectable: false,
      }));
      els.push({ group: "nodes", data: { ...vpcData, parent: lanes.of("vpc") }, classes: "vpcleaf" });
    } else {
      els.push({ group: "nodes", data: vpcData, classes: "vpc", grabbable: false });
      vpc.subnets.forEach((s, si) => els.push({
        group: "nodes",
        data: {
          id: "subnet:" + s.subnet_id, parent: "vpc", order: si, label: subnetLabel(s),
          title: subnetTitle(s, facts[s.subnet_id]), raw: s,
        },
        classes: "subnet" + (s.items.length ? "" : " empty"),
      }));
    }

    const byParent = new Map();  // container id -> Map(type -> resources)
    resources.forEach((r) => {
      const parent = lanes ? lanes.of(r.eni_id) : "subnet:" + r.subnet_id;
      if (!byParent.has(parent)) byParent.set(parent, new Map());
      const byType = byParent.get(parent);
      if (!byType.has(r.type)) byType.set(r.type, []);
      byType.get(r.type).push(r);
    });
    byParent.forEach((byType, parent) => {
      let order = 0;
      byType.forEach((members, type) => {
        const min = COMPUTE_TYPES.has(type) ? D.AGG_MIN : GROUP_THRESHOLD + 1;
        if (members.length < min) {
          members.forEach((r) => els.push(resourceElement(r, parent, order++, {})));
          return;
        }
        const gid = `group:${parent}:${type}`;
        const g = {
          kind: "group", id: gid, type: type, type_label: members[0].type_label,
          member_names: Array.from(new Set(members.map((m) => m.name).filter(Boolean))),
          count: members.length, ip_count: members.reduce((a, m) => a + m.ips.length, 0),
          icon: members[0].icon,
        };
        els.push(groupElement(gid, parent, order, g));
        members.forEach((m, j) => {
          els.push(resourceElement(m, parent, order + (j + 1) / (members.length + 1), { memberOf: gid }));
        });
        order += 1;
      });
    });

    const byService = new Map();  // "<lane>|<service>" -> nodes
    shownExtNodes(ext).forEach((n) => {
      const key = `${lanes ? lanes.of(n.id) : ""}|${n.service}`;
      if (!byService.has(key)) byService.set(key, []);
      byService.get(key).push(n);
    });
    byService.forEach((members, key) => {
      const parent = key.split("|")[0] || undefined;
      if (members.length < D.AGG_MIN) {
        members.forEach((n) => els.push(extElement(n, parent, {})));
        return;
      }
      const service = members[0].service;
      const gid = `svc:${parent ? parent + ":" : ""}${service}`;
      const g = {
        id: gid, service: service, type_label: members[0].service_label, count: members.length,
        member_names: members.map((n) => n.label_name), names: members.map((n) => n.name),
        arns: members.map((n) => n.arn).filter(Boolean),
      };
      const title = [`${g.type_label} ×${g.count}`, ...g.member_names.slice(0, MAX_TITLE_LINES)];
      if (g.count > MAX_TITLE_LINES) title.push(`… +${g.count - MAX_TITLE_LINES} more`);
      els.push({
        group: "nodes",
        data: { id: "box:" + gid, parent: parent, label: svcLabel(g, true), title: title.join("\n"), raw: g, group: gid },
        classes: "svcbox hidden", grabbable: false,
      });
      els.push({
        group: "nodes",
        data: {
          id: gid, parent: parent, label: svcLabel(g, false), title: title.join("\n"),
          icon: iconUrl(members[0].icon), iconFile: members[0].icon, service: service, raw: g,
        },
        classes: "group svc",
      });
      members.forEach((n) => els.push(extElement(n, "box:" + gid, { memberOf: gid })));
    });
    return els;
  }

  function setExpanded(cy, group, on) {
    if (on) expandedGroups.add(group.id()); else expandedGroups.delete(group.id());
    groupMembers(cy, group).toggleClass("hidden", !on);
    group.data("expanded", on);
    if (group.hasClass("svc")) {
      cy.getElementById("box:" + group.id()).toggleClass("hidden", !on);
      group.toggleClass("hidden", on);
    } else {
      group.data("label", groupLabel(group.data("raw"), on));
    }
  }

  // Service and environment filters: unticked services / environments disappear, and
  // with them a group of only those.
  function applyServiceFilter(cy) {
    const off = new Set(Array.from(document.querySelectorAll('input[name="service"]'))
      .filter((b) => !b.checked).map((b) => b.value));
    const envs = envOff();
    const envGone = (n) => envs.has((n.data("raw") || {}).environment || "");
    cy.batch(() => {
      cy.nodes(".ext").forEach((n) => { n.toggleClass("filtered", off.has(n.data("service")) || envGone(n)); });
      cy.nodes(".res").forEach((n) => { n.toggleClass("filtered", envGone(n)); });
      cy.nodes(".group").forEach((g) => {
        const gone = groupMembers(cy, g).every((m) => m.hasClass("filtered"));
        g.toggleClass("filtered", gone);
        if (g.hasClass("svc")) cy.getElementById("box:" + g.id()).toggleClass("filtered", gone);
      });
    });
  }

  // Where an edge end is drawn: its node, or the collapsed group holding it.
  function extEndpoint(cy, id) {
    const n = cy.getElementById(id === "vpc" || id.startsWith("x:") ? id : "res:" + id);
    if (n.empty() || n.hasClass("filtered")) return null;
    const g = n.data("memberOf");
    return g && !expandedGroups.has(g) ? g : n.id();
  }

  function drawnEdges(cy, edges) {
    const types = enabledEdgeTypes();
    const input = edges.filter((e) => e.type === "ext" || types.has(e.type));
    return D.mergeEdges(input, Array.from(enabledEvidence()), (id) => extEndpoint(cy, id));
  }

  /* The focused node as drawn now: a member of a collapsed group focuses the group, an
     expanded group its members. Empty when nothing (shown) is focused. */
  function focusTargets(cy) {
    if (!focusId) return [];
    let n = cy.getElementById(focusId);
    if (n.empty()) return [];
    const g = n.data("memberOf");
    if (g && !expandedGroups.has(g)) n = cy.getElementById(g);
    if (n.empty() || n.hasClass("filtered")) return [];
    if (n.hasClass("group") && expandedGroups.has(n.id())) {
      const members = groupMembers(cy, n).filter((m) => !m.hasClass("filtered")).map((m) => m.id());
      return n.hasClass("svc") ? members : [n.id(), ...members];
    }
    return [n.id()];
  }

  /* Focus mode: every node outside the focused node's neighbourhood is hidden, and so
     is a box (subnet, VPC, lane, service group) left without a shown node. */
  function applyExtFocus(cy, drawn) {
    cy.nodes(".unfocused").removeClass("unfocused");
    cy.nodes(".focus").removeClass("focus");
    const targets = focusTargets(cy);
    if (!targets.length) return drawn;
    const keep = new Set();
    targets.forEach((id) => D.neighbourhood(drawn, id, hops()).forEach((k) => keep.add(k)));
    targets.forEach((id) => cy.getElementById(id).addClass("focus"));
    cy.nodes().forEach((n) => {
      if (!n.isParent() && !n.hasClass("ctx") && !n.hasClass("pin") && !keep.has(n.id())) n.addClass("unfocused");
    });
    cy.nodes().filter((n) => n.isParent())
      .sort((a, b) => b.ancestors().length - a.ancestors().length)
      .forEach((p) => {
        const empty = p.children().every((c) => ["unfocused", "hidden", "filtered", "pin"].some((k) => c.hasClass(k)));
        if (empty) p.addClass("unfocused");
      });
    return drawn.filter((e) => keep.has(e.source) && keep.has(e.target));
  }

  function extEdgeLabel(m) {
    return shortName(m.label) + (m.count > 1 ? ` ×${m.count}` : "") + (m.extra ? ` +${m.extra}` : "");
  }

  function extEdgeTitle(m) {
    const shown = m.lines.filter((ln) => ln.shown);
    const lines = shown.slice(0, MAX_TITLE_LINES).map((ln) => `[${ln.evidence}] ${ln.text}`);
    if (m.count > 1) lines.unshift(`${m.count} connections merged`);
    const more = m.lines.length - Math.min(shown.length, MAX_TITLE_LINES);
    if (more > 0) lines.push(`… +${more} more evidence line(s) (click for all)`);
    return lines.join("\n");
  }

  // Draws the merged edges (after focus); returns them for the layout.
  function syncExtEdges(cy, edges) {
    const drawn = applyExtFocus(cy, drawnEdges(cy, edges));
    cy.batch(() => {
      cy.edges().remove();
      cy.add(drawn.map((m, i) => ({
        group: "edges",
        data: {
          id: "edge:" + i, etype: "ext", source: m.source, target: m.target,
          evidence: m.evidence, lines: m.lines, count: m.count, extra: m.extra,
          width: m.width, bidir: m.bidir, label: extEdgeLabel(m), title: extEdgeTitle(m),
        },
        classes: `edge-ext ev-${m.evidence}` + (m.count > 1 ? " agg" : "") + (m.bidir ? " bidir" : ""),
      })));
    });
    return drawn;
  }

  /* Search box: the best match by name, ARN, IP, ENI id or member name (exact >
     prefix > substring; a node before a group). */
  function findNode(cy, query) {
    const q = query.trim().toLowerCase();
    if (!q) return null;
    let best = null;
    let bestScore = 0;
    cy.nodes(".res, .ext, .group, .vpc, .vpcleaf").forEach((n) => {
      if (n.hasClass("filtered")) return;
      const raw = n.data("raw") || {};
      const fields = [raw.label_name, raw.name, raw.arn, raw.ref, raw.eni_id, raw.vpc_id,
        ...(raw.ips || []), ...(raw.owners || []), ...(raw.member_names || []), ...(raw.arns || [])];
      let score = 0;
      fields.filter(Boolean).forEach((f) => {
        const s = String(f).toLowerCase();
        if (s === q) score = Math.max(score, 3);
        else if (s.startsWith(q)) score = Math.max(score, 2);
        else if (s.includes(q)) score = Math.max(score, 1);
      });
      if (score && n.hasClass("group")) score -= 0.5;
      if (score > bestScore) {
        best = n;
        bestScore = score;
      }
    });
    return best;
  }

  function populateServiceFilters(data, onChange) {
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
      box.addEventListener("change", onChange);
      label.append(box, ` ${s.label} `);
      const count = document.createElement("span");
      count.className = "muted";
      count.textContent = `(${s.count})`;
      label.append(count);
      serviceFilters.append(label);
    });
  }

  // Display name of a node id, or of an edge end as stored (ENI id, "x:…", "vpc").
  function nodeName(cy, id) {
    let n = cy.getElementById(id);
    if (n.empty()) n = cy.getElementById("res:" + id);
    const raw = n.data("raw") || {};
    return raw.label_name || raw.name || (raw.type_label ? `${raw.type_label} ×${raw.count}` : "") || id;
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

  // -- extended view layout: one left-to-right dagre graph -----------------------------

  function isServiceNode(n) {
    return n.hasClass("ext") || n.hasClass("svc");
  }

  function isCompute(n) {
    return !isServiceNode(n) || D.serviceTier(n.data("service"), false) === 1;
  }

  /* One dagre layout (rankdir LR) of everything shown, boxes included: the VPC, its
     subnets, service groups and lanes are dagre clusters. Edges are oriented by tier so
     that sources (EventBridge / SNS / API Gateway / S3) rank left of compute (Lambda /
     ECS / the VPC's resources) and targets right of it. An edge to a box (e.g. a VPC
     route) is laid out to the box's first node. Returns dagre's route of every edge. */
  function extLayout(cy, drawn) {
    const g = new dagre.graphlib.Graph({ compound: true, multigraph: true });
    g.setGraph({ rankdir: "LR", nodesep: 56, ranksep: 150, edgesep: 16, marginx: 30, marginy: 30 });
    g.setDefaultEdgeLabel(() => ({}));
    cy.nodes(".pin").remove();
    const shown = cy.nodes().filter((n) => n.visible() && !n.hasClass("ctx"));
    const leaves = [];
    shown.forEach((n) => {
      if (n.isParent() && n.children().some((c) => c.visible())) {
        g.setNode(n.id(), {});
      } else {
        const dim = n.layoutDimensions({ nodeDimensionsIncludeLabels: true });
        g.setNode(n.id(), { width: dim.w, height: dim.h });
        leaves.push(n);
      }
    });
    shown.forEach((n) => {
      const p = n.parent();
      if (p.nonempty() && g.hasNode(p.id())) g.setParent(n.id(), p.id());
    });
    const leafIds = new Set(leaves.map((n) => n.id()));
    const layoutEnd = (id) => {
      if (leafIds.has(id)) return id;
      const first = cy.getElementById(id).descendants().filter((d) => leafIds.has(d.id()))[0];
      return first ? first.id() : null;
    };
    const feeds = new Set(drawn.filter((e) => isCompute(cy.getElementById(e.target))).map((e) => e.source));
    const tier = (id) => {
      const n = cy.getElementById(id);
      return isServiceNode(n) ? D.serviceTier(n.data("service"), feeds.has(id)) : 1;
    };
    const routes = [];
    drawn.forEach((e, i) => {
      const s = layoutEnd(e.source);
      const t = layoutEnd(e.target);
      if (!s || !t || s === t) return;
      const flip = tier(e.source) > tier(e.target);
      const [v, w] = flip ? [t, s] : [s, t];
      g.setEdge(v, w, { weight: Math.min(e.count || 1, 5), minlen: 1 }, "edge:" + i);
      routes.push({ id: "edge:" + i, v: v, w: w, flip: flip, direct: s === e.source && t === e.target });
    });

    dagre.layout(g);
    cy.batch(() => {
      leaves.forEach((n) => {
        const p = g.node(n.id());
        const dy = (p.height - n.outerHeight()) / 2;  // dagre centres node + label
        n.position({ x: p.x, y: p.y - dy });
      });
    });
    const out = new Map();
    routes.forEach((r) => {
      if (!r.direct) return;  // laid out to a stand-in node: drawn as a plain curve
      const pts = (g.edge({ v: r.v, w: r.w, name: r.id }) || {}).points || [];
      out.set(r.id, r.flip ? pts.slice().reverse() : pts);
    });
    if (laneMode()) stackLanes(cy, out);
    return out;
  }

  /* Swimlanes: dagre keeps each lane's nodes together; the lanes are then stacked top
     to bottom (keeping x, so tiers line up across lanes) and stretched to one width by
     two invisible "pin" nodes each. Routes inside a lane move with it; routes between
     lanes are dropped (plain curves). */
  function stackLanes(cy, routes) {
    const lanes = cy.nodes(".lane").filter((l) => l.visible())
      .sort((a, b) => a.data("order") - b.data("order"));
    const shiftOf = new Map();
    let top = null;
    cy.batch(() => {
      lanes.forEach((lane) => {
        const kids = lane.descendants().filter((n) => !n.isParent() && n.visible());
        if (kids.empty()) return;
        const bb = kids.boundingBox({ includeLabels: true, includeOverlays: false });
        if (top === null) top = bb.y1;
        const shift = top + LANE_HEAD - bb.y1;
        kids.forEach((k) => {
          k.position({ x: k.position("x"), y: k.position("y") + shift });
          shiftOf.set(k.id(), shift);
        });
        top += bb.h + LANE_HEAD + LANE_GAP;
      });
    });
    cy.edges().forEach((e) => {
      const route = routes.get(e.id());
      if (!route) return;
      const a = shiftOf.get(e.source().id());
      const b = shiftOf.get(e.target().id());
      if (a === undefined || a !== b) routes.delete(e.id());
      else routes.set(e.id(), route.map((p) => ({ x: p.x, y: p.y + a })));
    });
    const all = cy.nodes(".lane").descendants().filter((n) => !n.isParent() && n.visible())
      .boundingBox({ includeLabels: true, includeOverlays: false });
    cy.batch(() => {
      lanes.forEach((lane) => {
        const kids = lane.descendants().filter((n) => !n.isParent() && n.visible());
        if (kids.empty()) return;
        const y = kids.boundingBox().y1;
        [all.x1, all.x2].forEach((x, i) => cy.add({
          group: "nodes",
          data: { id: `pin:${lane.id()}:${i}`, parent: lane.id() },
          position: { x: x, y: y },
          classes: "pin", grabbable: false, selectable: false,
        }));
      });
    });
  }

  /* Edges follow dagre's route (fewer crossings, never through a node) as
     unbundled-bezier control points relative to the source -> target line. */
  function applyRoutes(cy, routes) {
    cy.batch(() => {
      cy.edges().forEach((e) => {
        const pts = (routes.get(e.id()) || []).slice(1, -1);
        const s = e.source().position();
        const t = e.target().position();
        const dx = t.x - s.x;
        const dy = t.y - s.y;
        const l2 = dx * dx + dy * dy;
        if (!pts.length || l2 < 1) {
          unroute(e);
          return;
        }
        const l = Math.sqrt(l2);
        e.style({
          "curve-style": "unbundled-bezier",
          "edge-distances": "node-position",
          "control-point-weights": pts.map((p) => ((p.x - s.x) * dx + (p.y - s.y) * dy) / l2),
          "control-point-distances": pts.map((p) => ((p.x - s.x) * -dy + (p.y - s.y) * dx) / l),
        });
      });
    });
  }

  // Back to a plain curve, e.g. once an end was dragged away from dagre's route.
  function unroute(edges) {
    edges.removeStyle("curve-style edge-distances control-point-weights control-point-distances");
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
      .filter((n) => !n.hasClass("hidden") && !n.hasClass("filtered"))
      .sort((a, b) => a.data("order") - b.data("order"));
  }

  function shownInLayout(n) {
    return n.visible() && !n.hasClass("ctx") && !n.hasClass("pin");
  }

  // Layout order: the data's order, then (Extended view) source -> compute -> target
  // tier and service, then id, so every layout is deterministic.
  function layoutRank(n) {
    const order = n.data("order");
    const tier = isServiceNode(n) ? D.serviceTier(n.data("service"), false) : 1;
    return [order === undefined ? Infinity : order, tier, n.data("service") || "", n.id()];
  }

  function byLayoutRank(a, b) {
    const ra = layoutRank(a);
    const rb = layoutRank(b);
    for (let i = 0; i < ra.length; i += 1) {
      if (ra[i] !== rb[i]) return ra[i] < rb[i] ? -1 : 1;
    }
    return 0;
  }

  // Grid cells as large as the widest / tallest wrapped label, so labels never overlap.
  function gridCells(nodes) {
    const n = nodes.length;
    const cols = Math.max(Math.min(COLS, n), Math.ceil(Math.sqrt(n)));
    let cellW = CELL_W, cellH = CELL_H;
    nodes.forEach((k) => {
      const dim = k.layoutDimensions({ nodeDimensionsIncludeLabels: true });
      cellW = Math.max(cellW, dim.w + CELL_GAP);
      cellH = Math.max(cellH, dim.h + CELL_GAP);
    });
    nodes.forEach((k, i) => k.position({ x: (i % cols) * cellW, y: Math.floor(i / cols) * cellH }));
  }

  /* Grid / circle / concentric / breadthfirst, box by box. Inside every box (VPC,
     subnet, expanded service group, swimlane, and the page itself) the shown nodes that
     are not boxes are laid out by the chosen layout into one block (grid: gridCells, the
     others: the cytoscape.js layout of that name), each inner box is laid out the same
     way into a block of its own, and the blocks are packed in rows (swimlanes: one per
     row). A box therefore always stays one block: a subnet's resources or an expanded
     service group's members are never scattered between other nodes. */
  function blockLayout(cy, name) {
    const isContainer = (n) => n.isParent() || n.hasClass("subnet");
    const isBox = (n) => n.isParent() && n.children().some(shownInLayout);
    const kidsOf = (box) => box.children().filter(shownInLayout).sort(byLayoutRank);
    // Uncached: a box's bounds must follow the nodes just moved inside it.
    const bb = (eles) => eles.boundingBox({ includeLabels: true, includeOverlays: false, useCache: false });

    function placeLoose(nodes) {
      if (name === "grid" || nodes.length < 2) {
        gridCells(nodes);
        return;
      }
      nodes.union(nodes.edgesWith(nodes)).layout({
        name: name, fit: false, animate: false, avoidOverlap: true,
        nodeDimensionsIncludeLabels: true, directed: false,
        boundingBox: { x1: 0, y1: 0, w: Math.max(400, nodes.length * 60), h: Math.max(300, nodes.length * 45) },
      }).run();
    }

    // Lays out ``kids`` (the shown children of one box) with their block at (0, 0).
    function arrange(kids) {
      const loose = kids.filter((n) => !isContainer(n));
      const boxes = kids.filter(isContainer);
      const blocks = [];
      if (loose.nonempty()) {
        placeLoose(loose);
        blocks.push({ measure: loose, move: loose });
      }
      boxes.forEach((b) => {
        if (!isBox(b)) {  // an empty subnet
          blocks.push({ measure: b, move: b });
          return;
        }
        arrange(kidsOf(b));
        blocks.push({ measure: b, move: b.descendants().filter((d) => shownInLayout(d) && !isBox(d)) });
      });
      const lanes = boxes.nonempty() && boxes.every((b) => b.hasClass("lane"));
      const perRow = lanes ? 1 : Math.max(SUBNETS_PER_ROW, Math.ceil(Math.sqrt(blocks.length)));
      let x = 0, y = 0, rowH = 0;
      blocks.forEach((blk, i) => {
        if (i && i % perRow === 0) {
          x = 0; y += rowH + BLOCK_GAP_Y; rowH = 0;
        }
        const box = bb(blk.measure);
        const dx = x - box.x1;
        const dy = y - box.y1;
        blk.move.forEach((n) => n.position({ x: n.position("x") + dx, y: n.position("y") + dy }));
        x += box.w + BLOCK_GAP_X;
        rowH = Math.max(rowH, box.h);
      });
    }

    // Not batched: compound bounds are only kept up to date outside a batch.
    arrange(cy.nodes().orphans().filter(shownInLayout).sort(byLayoutRank));
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

    // IP view only; the Extended view has its own left-to-right layout (extLayout).
    const leaves = [];
    cy.nodes().filter((n) => !n.hasClass("hidden") && !n.hasClass("ctx") && !n.hasClass("filtered")).forEach((n) => {
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
    return cy.nodes().filter((n) => !n.isParent() && !n.hasClass("hidden") && !n.hasClass("ctx") &&
      !n.hasClass("pin"));
  }

  // Extended view: dragged positions belong to the full diagram only (not to focus mode
  // or swimlanes, which are laid out afresh every time).
  function savingPositions() {
    return !extended || (!focusId && !laneMode());
  }

  // Returns the nodes moved to a saved position.
  function applySaved(cy) {
    const moved = leaves(cy).filter((n) => Boolean(saved[n.id()]));
    cy.batch(() => {
      moved.forEach((n) => {
        const p = saved[n.id()];
        n.position({ x: p.x, y: p.y });
      });
    });
    return moved;
  }

  let saveTimer = null;
  function savePositions(cy) {
    if (!savingPositions()) {
      note.textContent = "Positions are not saved in focus mode or with swimlanes.";
      return;
    }
    // Merge, so members of a collapsed group keep their saved spot.
    leaves(cy).forEach((n) => {
      const p = n.position();
      saved[n.id()] = { x: Math.round(p.x * 10) / 10, y: Math.round(p.y * 10) / 10 };
    });
    clearTimeout(saveTimer);
    saveTimer = setTimeout(() => {
      post(container.dataset.layoutUrl, { vpc: layoutKey, positions: JSON.stringify(saved) })
        .then(() => { note.textContent = "Layout saved for this account, VPC and view."; })
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

  // Extended view: an expanded service group exports as an "area" box, a swimlane as a
  // "lane" box, the VPC drawn as a node of the shared lane as a resource.
  function nodeKind(n) {
    if (n.hasClass("vpc")) return "vpc";
    if (n.hasClass("subnet")) return "subnet";
    if (n.hasClass("ctx")) return "ctx";
    if (n.hasClass("svcbox")) return "area";
    if (n.hasClass("lane")) return "lane";
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
    cy.nodes().filter((n) => n.visible() && !n.hasClass("pin")).forEach((n) => {
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
        node.members = groupMembers(cy, n).filter((m) => !m.hasClass("filtered")).map((m) => ({
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
        ...(e.hasClass("agg") ? { width: e.data("width") } : {}),
        ...(e.data("bidir") ? { bidir: true } : {}),
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

  /* The chosen layout of either view: dagre (IP view: top-down dagreLayout, Extended
     view: left-to-right extLayout, which returns dagre's edge routes), else blockLayout.
     Falls back to the grid. Returns the edge routes (empty unless dagre). */
  function runLayout(cy, edges, drawn) {
    const name = layoutSelect.value;
    try {
      if (name === "dagre") {
        if (extended) return extLayout(cy, drawn);
        dagreLayout(cy, edges);
      } else {
        cy.nodes(".pin").remove();  // only the dagre swimlanes need them
        blockLayout(cy, name);
      }
    } catch (err) {
      console.warn(`${name} layout failed, using the grid layout`, err);
      cy.nodes(".pin").remove();
      blockLayout(cy, "grid");
    }
    return new Map();
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
    if (expanded) expandedGroups.add(group.id()); else expandedGroups.delete(group.id());
    if (expanded) members.removeClass("hidden"); else members.addClass("hidden");
    group.data("expanded", expanded);
    group.data("label", groupLabel(group.data("raw"), expanded));
  }

  // -- style --------------------------------------------------------------------------

  const style = [
    { selector: "node", style: {
      // Labels arrive pre-wrapped by wrapLine; the slack absorbs measuring differences.
      "label": "data(label)", "font-size": RES_FONT, "text-wrap": "wrap", "text-max-width": TEXT_W.res + 4,
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
      "shape": "round-rectangle", "width": ICON, "height": ICON,
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
    // Extended view: expanded service groups, swimlanes, service / gateway nodes,
    // evidence styles.
    { selector: ".svcbox", style: {
      "shape": "rectangle", "background-color": "#f6f7f9", "border-width": 2,
      "border-style": "dashed", "border-color": "#5b6573", "padding": 24,
      "text-valign": "top", "text-halign": "center", "font-size": 12, "font-weight": "bold",
      "text-margin-y": -6, "text-max-width": TEXT_W.vpc,
    } },
    { selector: ".lane", style: {
      "shape": "rectangle", "background-color": "data(color)", "background-opacity": 0.04,
      "border-width": 1.5, "border-color": "data(color)", "padding": 24,
      "label": "data(label)", "color": "data(color)", "font-size": 13, "font-weight": "bold",
      "text-valign": "top", "text-halign": "center", "text-margin-y": -6,
      "text-max-width": TEXT_W.vpc,
    } },
    { selector: ".pin", style: { "width": 1, "height": 1, "opacity": 0, "events": "no", "label": "" } },
    { selector: ".vpcleaf", style: {
      "shape": "round-rectangle", "width": ICON, "height": ICON, "background-color": "#f7f3ff",
      "background-image": "data(icon)", "background-fit": "contain", "border-width": 2,
      "border-color": "#8c4fff", "text-valign": "bottom", "text-halign": "center",
      "text-margin-y": 5, "font-weight": "bold",
    } },
    { selector: ".ext", style: {
      "shape": "round-rectangle", "width": ICON, "height": ICON,
      "background-color": "#ffffff", "background-image": "data(icon)",
      "background-fit": "contain", "border-width": 0,
      "text-valign": "bottom", "text-halign": "center", "text-margin-y": 5,
    } },
    { selector: ".ext.broad", style: { "border-width": 3, "border-color": "#c2410c", "border-style": "dashed" } },
    // Crawled but not linked to this VPC (drawn from the "Not linked" panel).
    { selector: ".ext.unlinked", style: {
      "border-width": 2, "border-color": "#8a94a3", "border-style": "dotted", "background-image-opacity": 0.75,
    } },
    { selector: ".hidden, .filtered, .unfocused", style: { "display": "none" } },
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
      "line-color": "#1a7f37", "target-arrow-color": "#1a7f37", "source-arrow-color": "#1a7f37",
      "width": 3, "line-style": "solid", "target-arrow-shape": "triangle", "color": "#14532d",
    } },
    { selector: "edge.ev-configured", style: {
      "line-color": "#2457c5", "target-arrow-color": "#2457c5", "source-arrow-color": "#2457c5",
      "width": 2, "line-style": "solid", "target-arrow-shape": "triangle",
    } },
    { selector: "edge.ev-permitted", style: {
      "line-color": "#c2410c", "target-arrow-color": "#c2410c", "source-arrow-color": "#c2410c",
      "width": 1.8, "line-style": "dashed", "line-dash-pattern": [7, 4], "target-arrow-shape": "vee",
      "color": "#7c2d12", "opacity": 1,
    } },
    { selector: "edge.ev-referenced", style: {
      "line-color": "#6b7280", "target-arrow-color": "#6b7280", "source-arrow-color": "#6b7280",
      "width": 1.5, "line-style": "dashed", "line-dash-pattern": [2, 3], "target-arrow-shape": "vee",
      "color": "#374151", "opacity": 1,
    } },
    // Evidence in both directions: an arrow at each end.
    { selector: "edge.bidir.ev-observed, edge.bidir.ev-configured", style: { "source-arrow-shape": "triangle" } },
    { selector: "edge.bidir.ev-permitted, edge.bidir.ev-referenced", style: { "source-arrow-shape": "vee" } },
    { selector: "node.dim", style: { "opacity": 0.2 } },
    { selector: "edge.dim", style: { "opacity": 0.08, "text-opacity": 0 } },
    { selector: "node.focus", style: { "overlay-color": "#2457c5", "overlay-opacity": 0.12 } },
    { selector: "edge:selected, edge.hover, edge.focus", style: {
      "width": 3, "opacity": 1, "z-index": 10,
    } },
    // Merged connections (collapsed groups): stroke width grows with their count.
    { selector: "edge.agg", style: { "width": "data(width)", "arrow-scale": 0.7 } },
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
    populateTagKeys(data);  // before the Extended view's swimlanes need the tag key
    const cy = cytoscape({
      container: container,
      elements: ext ? extElements(data, edges) : buildElements(data),
      style: style,
      layout: { name: "preset" },
      minZoom: 0.05,
      maxZoom: 3,
      boxSelectionEnabled: false,
    });
    // Groups expanded when the page was last used (this account, view and VPC).
    cy.nodes(".group").filter((g) => expandedGroups.has(g.id()))
      .forEach((g) => (ext ? setExpanded(cy, g, true) : toggleGroup(cy, g, true)));
    applyBorders(cy);
    let focused = null;  // IP view: id of the node whose edges are highlighted
    let drawnCount = 0;
    const refreshEdges = () => {
      syncEdges(cy, edges);  // re-adds every edge, so the highlight is re-applied
      applyFocus(cy, focused);
    };
    const refreshContext = () => syncContext(cy, data);
    // Saved (dragged) positions always win over the automatic layout.
    const relayout = () => {
      if (ext) {
        const drawn = syncExtEdges(cy, edges);
        drawnCount = drawn.length;
        const routes = runLayout(cy, edges, drawn);
        const moved = savingPositions() ? applySaved(cy) : cy.collection();
        applyRoutes(cy, routes);
        unroute(moved.connectedEdges());
        updateStatus();
      } else {
        applyEnvFilterIp(cy);
        refreshEdges();
        runLayout(cy, edges);
        applySaved(cy);
      }
      refreshContext();
    };
    // Extended view: never below a readable zoom; a larger diagram starts at its top left.
    const fitShown = () => {
      const shown = cy.elements(":visible");
      cy.fit(shown, 30);
      if (!ext || shown.empty() || cy.zoom() >= MIN_READABLE_ZOOM) return;
      const bb = shown.boundingBox();
      cy.zoom(MIN_READABLE_ZOOM);
      cy.pan({ x: 30 - bb.x1 * MIN_READABLE_ZOOM, y: 30 - bb.y1 * MIN_READABLE_ZOOM });
      note.textContent = "The diagram is larger than the screen at a readable size: drag to pan, " +
        "or zoom out with −.";
    };
    const saveExpanded = () => savePrefs({
      view: view, vpc: vpcId, expanded: JSON.stringify(Array.from(expandedGroups)),
    });

    // Extended view: focus mode, groups, filters remembered per account.
    const setFocus = (id) => {
      focusId = id;
      relayout();
      fitShown();
      if (focusReset) focusReset.disabled = !focusId;
      note.textContent = focusId
        ? `Showing ${nodeName(cy, focusId)} and its ${hops()}-hop neighbourhood · ` +
          "Esc or Show all to see everything."
        : "";
    };
    const rebuild = () => {
      cy.elements().remove();
      cy.add(extElements(data, edges));
      applyServiceFilter(cy);
      cy.nodes(".group").filter((g) => expandedGroups.has(g.id())).forEach((g) => setExpanded(cy, g, true));
      applyBorders(cy);
      relayout();
      fitShown();
    };
    if (ext) populateServiceFilters(data, () => {
      applyServiceFilter(cy);
      relayout();
    });
    const refreshEnvFilters = () => populateEnvFilters(
      environmentsOf(data, ext ? shownExtNodes(ext) : []),
      () => {
        if (ext) applyServiceFilter(cy);
        relayout();
      },
    );
    refreshEnvFilters();
    if (ext) applyServiceFilter(cy);
    relayout();
    fitShown();

    if (ext) {
      // Click a node: its neighbourhood only. Click a group: expand / collapse it;
      // double-click it: its neighbourhood. An edge (or a service node) lists all of
      // its evidence below the diagram.
      cy.on("onetap", "node.res, node.ext, node.vpcleaf", (evt) => {
        const n = evt.target;
        if (n.hasClass("ext")) {
          const raw = n.data("raw");
          const facts = (raw.facts || []).map((text) => ({ text: text }));
          if (raw.arn) facts.unshift({ text: raw.arn });
          showDetail(`${raw.service_label}: ${raw.label_name}`, facts.length ? facts : [{ text: "No further details." }]);
        }
        setFocus(n.id());
      });
      cy.on("onetap", "node.group", (evt) => {
        setExpanded(cy, evt.target, !expandedGroups.has(evt.target.id()));
        relayout();
        saveExpanded();
      });
      cy.on("dbltap", "node.group", (evt) => setFocus(evt.target.id()));
      cy.on("onetap", "node.svcbox", (evt) => {
        if (!evt.target.hasClass("svcbox")) return;  // a tap on a member bubbles up
        setExpanded(cy, cy.getElementById(evt.target.data("group")), false);
        relayout();
        saveExpanded();
      });
      cy.on("onetap", "edge", (evt) => {
        const e = evt.target;
        const lines = e.data("lines") || [];
        const count = e.data("count") || 1;
        showDetail(
          `${nodeName(cy, e.source().id())} ${e.data("bidir") ? "↔" : "→"} ${nodeName(cy, e.target().id())}: ` +
            `${lines.length} evidence line(s)` + (count > 1 ? ` over ${count} merged connections` : "") +
            `, drawn as ${e.data("evidence")}`,
          lines.map((ln) => ({
            evidence: ln.evidence,
            text: (count > 1 || ln.reverse ? `${nodeName(cy, ln.source)} → ${nodeName(cy, ln.target)}: ` : "") +
              ln.text + (ln.shown ? "" : " (level not shown: tick it under Evidence)"),
          })),
        );
      });
      cy.on("mouseover", "node.ext, node.vpcleaf, node.svcbox, edge", () => { container.style.cursor = "pointer"; });
      cy.on("mouseout", "edge", () => { container.style.cursor = ""; });
      cy.on("grab", "node", (evt) => unroute(evt.target.union(evt.target.descendants()).connectedEdges()));
      evidenceBoxes.forEach((box) => box.addEventListener("change", () => {
        relayout();
        savePrefs({ evidence: Array.from(enabledEvidence()).join(",") });
      }));
      (ext.evidence_levels || []).forEach((lvl) => {
        const el = document.querySelector(`[data-evidence-count="${lvl.level}"]`);
        if (el) el.textContent = `(${lvl.count})`;
      });
      const find = () => {
        const n = findNode(cy, focusSearch.value);
        if (!n) {
          note.textContent = `No node matches "${focusSearch.value.trim()}".`;
          return;
        }
        const g = n.data("memberOf");
        if (g && !expandedGroups.has(g)) {
          setExpanded(cy, cy.getElementById(g), true);
          saveExpanded();
        }
        setFocus(n.id());
      };
      if (focusSearch) {
        // Enter searches instead of submitting the page form.
        focusSearch.addEventListener("keydown", (evt) => {
          if (evt.key !== "Enter") return;
          evt.preventDefault();
          find();
        });
        document.getElementById("focus-find").addEventListener("click", find);
      }
      if (focusReset) focusReset.addEventListener("click", () => setFocus(null));
      if (focusHops) focusHops.addEventListener("change", () => { if (focusId) setFocus(focusId); });
      document.addEventListener("keydown", (evt) => {
        if (evt.key === "Escape" && focusId) setFocus(null);
      });
      setupFlowLogs();
      setupUnlinked(cy, ext, () => {
        rebuild();
        refreshEnvFilters();
      });
    } else {
      // "onetap" fires only after the double-click window (multiClickDebounceTime) has
      // passed without a second tap, so a double-click never also toggles the highlight.
      cy.on("onetap", "node.res", (evt) => {
        focused = focused === evt.target.id() ? null : evt.target.id();
        applyFocus(cy, focused);
      });
      cy.on("onetap", "node.group", (evt) => {
        toggleGroup(cy, evt.target);
        relayout();
        saveExpanded();
      });
      cy.on("onetap", (evt) => {
        if (evt.target !== cy || !focused) return;
        focused = null;
        applyFocus(cy, null);
      });
    }
    cy.on("dbltap", "node.res", (evt) => {
      window.location.href = eniUrl.replace("__ENI__", encodeURIComponent(evt.target.data("eni")));
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
    document.getElementById("zoom-fit").addEventListener("click", fitShown);
    const expandAll = (on) => {
      cy.nodes(".group").forEach((g) => (ext ? setExpanded(cy, g, on) : toggleGroup(cy, g, on)));
      relayout();
      fitShown();
      saveExpanded();
    };
    document.getElementById("expand-all").addEventListener("click", () => expandAll(true));
    document.getElementById("collapse-all").addEventListener("click", () => expandAll(false));
    layoutSelect.addEventListener("change", () => {
      relayout();
      fitShown();
      savePrefs({ view: view, layout: layoutSelect.value });
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
    // Forgets the dragged positions of this VPC and view, and leaves focus mode / the
    // highlight: the full diagram in its automatic layout.
    document.getElementById("reset-layout").addEventListener("click", () => {
      focusId = null;
      focused = null;
      if (focusReset) focusReset.disabled = true;
      if (detail) detail.hidden = true;
      applyFocus(cy, null);
      post(container.dataset.resetUrl, { vpc: layoutKey })
        .then(() => {
          saved = {};
          note.textContent = "Layout reset.";
        })
        .catch((err) => { note.textContent = `Could not reset the layout (${err.message}).`; })
        .finally(() => {
          relayout();
          fitShown();
        });
    });
    [showVpcBox, showSubnetsBox].forEach((box) => box.addEventListener("change", () => {
      applyBorders(cy);
      saveBorders();
    }));
    showLegendBox.addEventListener("change", () => {
      legend.hidden = !showLegendBox.checked;
      savePrefs({ show_legend: showLegendBox.checked ? "1" : "0" });
    });
    // Label sizes change, so the automatic layout is redone; dragged nodes keep their spot.
    shortenBox.addEventListener("change", () => {
      refreshLabels(cy);
      relayout();
      savePrefs({ shorten_names: shortenBox.checked ? "1" : "0" });
    });
    // The Extended view exports exactly what is drawn (focus, groups, filters).
    const exportView = () => currentView(cy, edges, !ext && expandExportBox && expandExportBox.checked);
    document.getElementById("export-svg").addEventListener("click", () => {
      download(container.dataset.exportSvg, exportView());
    });
    document.getElementById("export-drawio").addEventListener("click", () => {
      download(container.dataset.exportDrawio, exportView());
    });
    let lanesShown = laneMode();
    [groupBySelect, groupTagSelect].forEach((sel) => sel.addEventListener("change", () => {
      groupTagSelect.hidden = groupBySelect.value !== "tag";
      // Swimlanes (Extended view, tag / Terraform root) change which box holds a node.
      if (ext && (lanesShown || laneMode())) {
        lanesShown = laneMode();
        rebuild();
      } else {
        refreshContext();
      }
      rememberGroupBy();
    }));
    edgeBoxes.forEach((box) => box.addEventListener("change", () => {
      if (ext) relayout(); else refreshEdges();
      rememberEdgeFilter();
    }));

    (data.edge_types || []).forEach((t) => {
      const el = document.querySelector(`[data-edge-count="${t.type}"]`);
      if (el) el.textContent = `(${t.count})`;
    });
    function updateStatus() {
      const nRes = data.vpc.subnets.reduce((a, s) => a + s.resource_count, 0);
      const cut = (data.edge_types || []).filter((t) => t.truncated).map((t) => t.label);
      status.textContent = `${data.vpc.subnets.length} subnet(s) · ${nRes} resource ENI(s) · ` +
        `${edges.length} connection(s) · snapshot #${data.snapshot_id}` +
        (cut.length ? ` · truncated: ${cut.join(", ")}` : "") +
        (ext ? ` · ${shownExtNodes(ext).length} regional / external node(s)` +
          (ext.hidden_nodes ? ` (${ext.hidden_nodes} crawled node(s) not linked to this VPC: see Not linked)` : "") +
          ` · ${drawnCount} line(s) drawn` +
          (ext.crawl ? "" : " · services not crawled yet") +
          (ext.flow ? ` · flow logs: ${ext.flow.pairs} aggregate(s), ${ext.flow.bytes_label} scanned` : "")
          : "");
    }
    updateStatus();
  }

  // -- extended view: crawled nodes not linked to this VPC (side panel) -----------------

  const MAX_UNLINKED_ITEMS = 300;

  /* "Not linked: N": the crawled regional nodes the diagram leaves out because nothing
     drawn for this VPC links to them. Clicking one draws it (unlinked, dotted border) and
     centres on it; clicking it again removes it; "Show all crawled nodes" draws them all.
     ``redraw`` rebuilds the diagram (which fits it). */
  function setupUnlinked(cy, ext, redraw) {
    const panel = document.getElementById("unlinked-panel");
    if (!panel || !ext.hidden_nodes) return;
    panel.hidden = false;
    document.getElementById("unlinked-count").textContent = ext.hidden_nodes;
    const list = document.getElementById("unlinked-list");
    const search = document.getElementById("unlinked-search");
    const more = document.getElementById("unlinked-more");
    const hidden = ext.hidden || [];

    const reveal = (id) => {
      let n = cy.getElementById(id);
      const g = n.nonempty() ? n.data("memberOf") : null;
      if (g && !expandedGroups.has(g)) n = cy.getElementById(g);
      if (n.empty() || !n.visible()) return;
      cy.animate({ center: { eles: n }, zoom: Math.max(cy.zoom(), MIN_READABLE_ZOOM) }, { duration: 250 });
      n.flashClass("focus", 1500);
    };

    const draw = () => {
      const q = search.value.trim().toLowerCase();
      const all = showAllCrawled.checked;
      const items = hidden.filter((n) => !q ||
        `${n.label_name} ${n.service_label} ${n.arn}`.toLowerCase().includes(q));
      list.replaceChildren(...items.slice(0, MAX_UNLINKED_ITEMS).map((n) => {
        const shown = all || extraShown.has(n.id);
        const li = document.createElement("li");
        li.className = shown ? "shown" : "";
        const btn = document.createElement("button");
        btn.type = "button";
        btn.textContent = n.label_name;
        btn.title = [n.service_label, n.arn, all ? "Shown (Show all crawled nodes)"
          : shown ? "Click to remove it from the diagram" : "Click to draw it"].filter(Boolean).join("\n");
        btn.addEventListener("click", () => {
          if (!all) {
            if (extraShown.has(n.id)) extraShown.delete(n.id); else extraShown.add(n.id);
            redraw();
            draw();
          }
          if (all || extraShown.has(n.id)) reveal(n.id);
        });
        const svc = document.createElement("span");
        svc.className = "muted";
        svc.textContent = ` · ${n.service_label}`;
        li.append(btn, svc);
        return li;
      }));
      const rest = items.length - Math.min(items.length, MAX_UNLINKED_ITEMS) + (ext.hidden_nodes - hidden.length);
      more.hidden = rest <= 0;
      more.textContent = `… and ${rest} more (narrow the filter)`;
    };
    search.addEventListener("input", draw);
    showAllCrawled.addEventListener("change", () => {
      redraw();
      draw();
    });
    draw();
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
