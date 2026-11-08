// Audit view. Chain integrity is decided server-side and reported here; the
// browser never recomputes a hash. Two presentations read the same
// /api/audit payload: a readable timeline and an AG Grid for drill-down.
// Every value reaches the DOM through textContent.
(function () {
  "use strict";

  var STORAGE_KEY = "orrix.audit.columnState.v1";
  var firstBadSeq = null;

  // -- readable labels ---------------------------------------------------

  var ACTION_LABEL = {
    "web.login": "Signed in",
    "web.seller_input_saved": "Saved seller shipment details",
    "web.approval_created": "Seller approved an action",
    "web.approve_refused:stale_view": "Approval refused: the case had changed",
    "web.reader_rerun_refused:reader_not_configured":
      "Reader re-run refused: not configured",
    "web.reader_rerun_refused:rate_limited": "Reader re-run refused: rate limited",
    "pipeline.synced": "Fetched the dispute from PayPal",
    "pipeline.facts_built": "Built trusted facts from the PayPal record",
    "pipeline.facts_failed": "Could not build facts from the record",
    "pipeline.discrepancy_detected":
      "Found a conflict between the buyer text and the record"
  };

  var ACTOR_LABEL = {
    admin: "You (admin)",
    pipeline: "Orrix pipeline",
    executor: "Executor",
    system: "System"
  };

  function actionLabel(action) {
    var text = action == null ? "" : String(action);
    if (Object.prototype.hasOwnProperty.call(ACTION_LABEL, text)) {
      return ACTION_LABEL[text];
    }
    if (text.indexOf("pipeline.reader:") === 0) {
      return "Reader produced a validated claim form";
    }
    if (text.indexOf("web.reader_rerun:") === 0) {
      return "Re-ran the reader";
    }
    if (text.indexOf("pipeline.buyer_text_extracted:") === 0) {
      return "Extracted buyer text (length only; never stored)";
    }
    if (text.indexOf("pipeline.decided:") === 0) {
      return "Policy decided in plain code";
    }
    if (text.indexOf("pipeline.failed:") === 0) {
      return "The pipeline failed: " + text.slice("pipeline.failed:".length);
    }
    if (text.indexOf("execute.") === 0) {
      return "Executor: " + text.slice("execute.".length);
    }
    return text;
  }

  function actorLabel(actor) {
    var text = actor == null ? "" : String(actor);
    return ACTOR_LABEL[text] || text;
  }

  // -- timeline ----------------------------------------------------------

  function labelledLine(label, value, mono) {
    var line = document.createElement("div");
    line.className = "detail-line";
    var name = document.createElement("span");
    name.className = "detail-label";
    name.textContent = label;
    var body = document.createElement("span");
    if (mono) body.className = "mono";
    body.textContent = value == null ? "" : String(value);
    line.appendChild(name);
    line.appendChild(body);
    return line;
  }

  function timelineItem(row) {
    var item = document.createElement("li");
    item.className = "timeline-item";
    item.setAttribute("data-seq", String(row.seq));
    item.setAttribute("data-chain-ok", row.chain_ok ? "true" : "false");
    if (row.is_first_bad) item.classList.add("is-first-bad");

    var node = document.createElement("span");
    node.className = "timeline-node";
    node.setAttribute("aria-hidden", "true");
    item.appendChild(node);

    var body = document.createElement("div");
    body.className = "timeline-body";

    var head = document.createElement("div");
    head.className = "timeline-head";
    var label = document.createElement("span");
    label.className = "timeline-label";
    label.textContent = actionLabel(row.action);
    head.appendChild(label);
    var badge = document.createElement("span");
    badge.className = "origin origin-" + ((row.origin_tag || "").toString());
    badge.textContent = row.origin_label == null ? "" : String(row.origin_label);
    head.appendChild(badge);
    body.appendChild(head);

    var meta = document.createElement("div");
    meta.className = "timeline-meta";
    var seq = document.createElement("span");
    seq.className = "mono";
    seq.textContent = "#" + row.seq;
    meta.appendChild(seq);
    var when = document.createElement("span");
    when.className = "mono";
    when.textContent = row.ts == null ? "" : String(row.ts);
    meta.appendChild(when);
    var actor = document.createElement("span");
    actor.textContent = actorLabel(row.actor);
    meta.appendChild(actor);
    if (row.dispute_id) {
      var dispute = document.createElement("span");
      dispute.className = "mono";
      dispute.textContent = row.dispute_id;
      meta.appendChild(dispute);
    }
    body.appendChild(meta);

    // Expandable raw JSON. This is the entry as the API reports it, shown
    // verbatim so the readable labels can be checked against the source.
    var details = document.createElement("details");
    details.className = "payload-details";
    var summary = document.createElement("summary");
    summary.textContent = "Raw entry";
    details.appendChild(summary);
    var raw = document.createElement("pre");
    raw.className = "payload mono";
    raw.textContent = JSON.stringify(row, null, 2);
    details.appendChild(raw);
    body.appendChild(details);

    item.appendChild(body);
    return item;
  }

  var BREAK_NOTE =
    "Nothing after this sequence can be vouched for: the chain links forward, " +
    "so one broken row invalidates everything below it.";

  function renderTimeline(rows) {
    var host = document.getElementById("audit-timeline");
    if (!host) return;
    while (host.firstChild) host.removeChild(host.firstChild);

    if (!rows.length) {
      OrrixGrid.showNote(
        "audit-empty",
        "No audit entries yet. Signing in, opening a case and every write each " +
          "append one entry."
      );
      return;
    }

    var ordered = rows.slice().sort(function (a, b) {
      return b.seq - a.seq;
    });

    ordered.forEach(function (row) {
      host.appendChild(timelineItem(row));
      if (row.is_first_bad) {
        var note = document.createElement("li");
        note.className = "timeline-break";
        note.setAttribute("role", "note");
        note.textContent = "Chain broken at sequence " + row.seq + ". " + BREAK_NOTE;
        host.appendChild(note);
      }
    });
  }

  // -- chain banner ------------------------------------------------------

  function renderBanner(payload) {
    var banner = document.querySelector("[data-chain-banner]");
    if (!banner) return;
    var title = banner.querySelector("[data-chain-title]");
    var detail = banner.querySelector("[data-chain-detail]");
    var broken = payload.chain_ok === false;
    banner.setAttribute("data-state", broken ? "broken" : "ok");
    if (title) {
      title.textContent = broken
        ? "Chain broken at sequence " + payload.first_bad_seq
        : "Chain intact";
    }
    if (detail) {
      if (broken) {
        detail.textContent =
          "Everything from sequence " + payload.first_bad_seq +
          " onward is highlighted below and cannot be vouched for.";
      } else {
        var how = payload.keyed ? "with HMAC" : "with plain SHA-256";
        detail.textContent =
          payload.entries + " entries verified " + how +
          (payload.keyed ? "" : ". No AUDIT_HMAC_KEY, so a forger with database access could rebuild it.");
      }
    }
  }

  // -- grid --------------------------------------------------------------

  function chainChip(params) {
    var ok = params.data ? params.data.chain_ok : true;
    return OrrixGrid.chip(
      ok ? "ok" : "broken",
      ok ? "chip-confirmed" : "chip-conflicting"
    );
  }

  var columns = [
    { headerName: "Seq", field: "seq", width: 90, sort: "desc", cellClass: "mono" },
    { headerName: "Time", field: "ts", minWidth: 215, cellClass: "mono" },
    { headerName: "Actor", field: "actor", width: 130, filter: "agSetColumnFilter" },
    { headerName: "Action", field: "action", minWidth: 270, cellClass: "mono" },
    { headerName: "Dispute", field: "dispute_id", minWidth: 190, cellClass: "mono" },
    {
      headerName: "Origin",
      field: "origin_label",
      minWidth: 215,
      filter: "agSetColumnFilter",
      cellRenderer: OrrixGrid.originBadge
    },
    { headerName: "Payload hash", field: "payload_hash", minWidth: 150, cellClass: "mono" },
    { headerName: "Entry hash", field: "entry_hash", minWidth: 150, cellClass: "mono" },
    {
      headerName: "Chain",
      field: "chain_label",
      width: 120,
      filter: "agSetColumnFilter",
      cellRenderer: chainChip
    }
  ];

  document.addEventListener("DOMContentLoaded", function () {
    var host = document.getElementById("audit-grid");

    OrrixGrid.applyLicense();

    var options = {
      columnDefs: columns,
      rowData: [],
      defaultColDef: {
        sortable: true,
        resizable: true,
        filter: true,
        flex: 1,
        enableRowGroup: true
      },
      sideBar: { toolPanels: ["columns", "filters"], defaultToolPanel: null },
      statusBar: {
        statusPanels: [
          { statusPanel: "agTotalRowCountComponent", align: "left" },
          { statusPanel: "agFilteredRowCountComponent", align: "left" }
        ]
      },
      // Highlights the first bad sequence and everything the chain can no
      // longer vouch for.
      getRowClass: function (params) {
        if (!params.data) return null;
        if (firstBadSeq !== null && params.data.seq === firstBadSeq) return "row-chain-bad";
        if (params.data.chain_ok === false) return "row-chain-suspect";
        return null;
      },
      onGridReady: function (event) {
        OrrixGrid.restoreColumnState(event.api, STORAGE_KEY);
      }
    };

    var api = host ? agGrid.createGrid(host, options) : null;
    if (api) {
      var save = OrrixGrid.persistColumnState(api, STORAGE_KEY);
      ["columnMoved", "columnResized", "columnVisible", "sortChanged"].forEach(function (name) {
        api.addEventListener(name, save);
      });
    }

    function load() {
      return OrrixGrid.loadJson("/api/audit").then(function (payload) {
        firstBadSeq = payload.first_bad_seq;
        renderBanner(payload);
        renderTimeline(payload.rows || []);
        if (api) {
          api.setGridOption("rowData", payload.rows || []);
          api.redrawRows();
        }
        return payload;
      });
    }

    load();

    // The Verify button posts through HTMX and swaps in the banner. The
    // banner carries the bad sequence in a data attribute, which is data,
    // not script, so the CSP stays strict.
    document.body.addEventListener("htmx:afterSwap", function (event) {
      if (!event.target || event.target.id !== "verification") return;
      var banner = document.getElementById("verification-result");
      if (!banner) return;
      var raw = banner.getAttribute("data-bad-seq");
      firstBadSeq = raw ? parseInt(raw, 10) : null;
      load();
      if (
        api &&
        firstBadSeq !== null &&
        !isNaN(firstBadSeq) &&
        typeof api.ensureNodeVisible === "function"
      ) {
        api.ensureNodeVisible(function (node) {
          return node.data && node.data.seq === firstBadSeq;
        });
      }
    });
  });
})();
