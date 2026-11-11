// Dispute queue: grouped by Orrix status, master/detail facts, status bar,
// side panel and quick filter. Every value reaches the DOM via textContent.
(function () {
  "use strict";

  var STORAGE_KEY = "orrix.cases.columnState.v1";

  // -- master/detail -----------------------------------------------------

  function labelled(label, value) {
    var row = document.createElement("div");
    row.className = "detail-line";
    var name = document.createElement("span");
    name.className = "detail-label";
    name.textContent = label;
    var body = document.createElement("span");
    body.textContent = value == null ? "" : String(value);
    row.appendChild(name);
    row.appendChild(body);
    return row;
  }

  function factsTable(facts) {
    var table = document.createElement("table");
    table.className = "facts detail-facts";

    var head = document.createElement("thead");
    var headRow = document.createElement("tr");
    ["Fact", "Value", "Status", "Origin"].forEach(function (heading) {
      var cell = document.createElement("th");
      cell.textContent = heading;
      headRow.appendChild(cell);
    });
    head.appendChild(headRow);
    table.appendChild(head);

    var body = document.createElement("tbody");
    facts.forEach(function (fact) {
      var row = document.createElement("tr");

      var name = document.createElement("td");
      name.className = "mono";
      name.textContent = fact.name;
      row.appendChild(name);

      var value = document.createElement("td");
      value.className = "mono";
      value.textContent = fact.value;
      row.appendChild(value);

      var status = document.createElement("td");
      status.appendChild(OrrixGrid.chip(fact.status, OrrixGrid.statusChipClass(fact.status)));
      row.appendChild(status);

      var origin = document.createElement("td");
      var badge = document.createElement("span");
      badge.className = "origin origin-" + fact.source;
      badge.textContent = fact.origin_label;
      origin.appendChild(badge);
      row.appendChild(origin);

      body.appendChild(row);
    });
    table.appendChild(body);
    return table;
  }

  function DetailRenderer() {}

  DetailRenderer.prototype.init = function (params) {
    var data = (params.data && params.data.detail) || {};
    var host = document.createElement("div");
    host.className = "detail-panel";

    var header = document.createElement("div");
    header.className = "detail-header";

    var link = document.createElement("a");
    link.className = "btn btn-quiet";
    link.href = data.case_url || "#";
    link.textContent = "Open full case file";
    header.appendChild(link);

    header.appendChild(labelled("Tracking", data.completeness || "no"));
    header.appendChild(
      labelled("Evidence submitted", data.evidence_submitted ? "yes" : "no")
    );
    host.appendChild(header);

    // The discrepancy detector's fixed sentence, shown verbatim.
    if (data.discrepancy) {
      var banner = document.createElement("div");
      banner.className = "alert alert-warn detail-banner";
      banner.setAttribute("role", "alert");
      banner.textContent = data.discrepancy;
      host.appendChild(banner);
    }

    if (Array.isArray(data.reasons) && data.reasons.length) {
      var reasons = document.createElement("ul");
      reasons.className = "reasons mono small detail-reasons";
      data.reasons.forEach(function (reason) {
        var item = document.createElement("li");
        item.textContent = reason;
        reasons.appendChild(item);
      });
      host.appendChild(reasons);
    }

    if (Array.isArray(data.facts) && data.facts.length) {
      host.appendChild(factsTable(data.facts));
    } else {
      var empty = document.createElement("p");
      empty.className = "muted";
      empty.textContent = "No facts could be built for this dispute.";
      host.appendChild(empty);
    }

    this.eGui = host;
  };

  DetailRenderer.prototype.getGui = function () {
    return this.eGui;
  };

  // -- columns -----------------------------------------------------------

  // Status pills carry a glyph as well as a word, so the meaning survives
  // without colour. The glyph is set with textContent like everything else.
  var STATUS_ICON = {
    action_available: "\u25B2",
    evidence_submitted_waiting_for_buyer: "\u2713",
    needs_human_review: "\u26A0",
    awaiting_reader: "\u25CB",
    no_action: "\u2014",
    facts_failed: "\u2715"
  };

  var STATUS_PILL = {
    action_available: "pill-action",
    evidence_submitted_waiting_for_buyer: "pill-done",
    needs_human_review: "pill-review",
    awaiting_reader: "pill-wait",
    no_action: "pill-none",
    facts_failed: "pill-bad"
  };

  function statusPill(params) {
    var data = params.data || {};
    var span = document.createElement("span");
    span.className = "status-pill " + (STATUS_PILL[data.orrix_status] || "pill-none");
    var icon = document.createElement("span");
    icon.className = "pill-icon";
    icon.setAttribute("aria-hidden", "true");
    icon.textContent = STATUS_ICON[data.orrix_status] || "\u2022";
    var label = document.createElement("span");
    label.textContent = params.value == null ? "" : String(params.value);
    span.appendChild(icon);
    span.appendChild(label);
    return span;
  }

  function disputeLink(params) {
    if (!params.value) return document.createTextNode("");
    var link = document.createElement("a");
    link.className = "mono grid-link";
    link.href = "/cases/" + encodeURIComponent(params.value);
    link.textContent = params.value;
    return link;
  }

  // Flex sizing with a minimum each, so the set fills the container at
  // 1920px with no horizontal scrollbar and still degrades sensibly.
  var columns = [
    {
      headerName: "Dispute",
      field: "dispute_id",
      flex: 2,
      minWidth: 195,
      cellRenderer: disputeLink,
      filter: "agTextColumnFilter"
    },
    {
      headerName: "Amount",
      field: "amount",
      flex: 1,
      minWidth: 115,
      filter: "agNumberColumnFilter",
      cellClass: "mono amount-cell",
      cellRenderer: OrrixGrid.amountCell
    },
    {
      headerName: "Due",
      field: "hours_left",
      flex: 1,
      minWidth: 105,
      sort: "asc",
      filter: "agNumberColumnFilter",
      cellRenderer: OrrixGrid.deadlineChip,
      comparator: function (a, b) {
        if (a == null) return 1;
        if (b == null) return -1;
        return a - b;
      }
    },
    {
      headerName: "PayPal state",
      field: "state",
      flex: 1.4,
      // Wide enough for the longest state chip; this column used to
      // truncate to "no..." / "ye...".
      minWidth: 180,
      filter: "agTextColumnFilter",
      cellRenderer: OrrixGrid.stateChip
    },
    {
      headerName: "Orrix status",
      field: "orrix_status_label",
      flex: 1.6,
      minWidth: 190,
      filter: "agSetColumnFilter",
      cellRenderer: statusPill,
      tooltipField: "orrix_status_label"
    },
    {
      headerName: "Tracking",
      field: "completeness",
      flex: 1,
      minWidth: 120,
      filter: "agSetColumnFilter",
      cellRenderer: function (p) {
        var element = OrrixGrid.completenessChip(p.value);
        element.classList.add("chip-grid");
        return element;
      }
    },
    {
      headerName: "Review flags",
      field: "flags",
      flex: 1.6,
      minWidth: 160,
      filter: "agTextColumnFilter",
      cellRenderer: OrrixGrid.flagChips
    },
    {
      headerName: "Reason",
      field: "reason",
      flex: 1.6,
      minWidth: 170,
      filter: "agTextColumnFilter",
      // The PayPal reason codes are long; hovering shows the whole value.
      tooltipField: "reason"
    }
  ];

  // Responsive column sets, narrowest first. The dispute, its deadline and
  // the PayPal state are the three that survive to the smallest width; the
  // rest drop in order of how much they add at a glance.
  //
  // The tiers are measured against the GRID's own width, not the window's.
  // The shell keeps a 232px sidebar at every width, so a 900px window
  // leaves the grid about 585px: a tier chosen from the window would put
  // five columns into that space and bring back the horizontal scrollbar
  // the flex sizing is meant to remove. Each threshold below is the sum of
  // its set's minimums plus a little slack, so no tier can ever overflow.
  var NARROW = ["dispute_id", "hours_left", "state"];
  var MEDIUM = NARROW.concat(["amount", "orrix_status_label"]);
  var ALL_FIELDS = columns.map(function (column) {
    return column.field;
  });

  var MEDIUM_MIN_WIDTH = 805;
  var ALL_MIN_WIDTH = 1255;

  function visibleFieldsFor(gridWidth) {
    if (gridWidth >= ALL_MIN_WIDTH) return ALL_FIELDS;
    if (gridWidth >= MEDIUM_MIN_WIDTH) return MEDIUM;
    return NARROW;
  }

  function applyResponsiveColumns(api, host) {
    var width = host ? host.clientWidth : window.innerWidth;
    var keep = visibleFieldsFor(width);
    var hide = ALL_FIELDS.filter(function (field) {
      return keep.indexOf(field) === -1;
    });
    api.setColumnsVisible(keep, true);
    if (hide.length) api.setColumnsVisible(hide, false);
  }

  document.addEventListener("DOMContentLoaded", function () {
    var host = document.getElementById("cases-grid");
    if (!host) return;

    OrrixGrid.applyLicense();

    var options = {
      columnDefs: columns,
      rowData: [],
      defaultColDef: {
        sortable: true,
        resizable: true,
        filter: true,
        flex: 1,
        enableRowGroup: true,
        enableValue: true
      },
      masterDetail: true,
      detailCellRenderer: DetailRenderer,
      detailRowAutoHeight: true,
      // Tall enough for a 26px pill to sit inside with air around it.
      rowHeight: 56,
      headerHeight: 48,
      animateRows: true,
      // Flex already fills the container; this keeps it filled after a
      // column is hidden or shown at a breakpoint.
      autoSizeStrategy: { type: "fitGridWidth" },
      sideBar: {
        toolPanels: ["columns", "filters"],
        defaultToolPanel: null
      },
      statusBar: {
        statusPanels: [
          { statusPanel: "agTotalRowCountComponent", align: "left" },
          { statusPanel: "agFilteredRowCountComponent", align: "left" },
          { statusPanel: "agSelectedRowCountComponent", align: "center" },
          { statusPanel: "agAggregationComponent", align: "right" }
        ]
      },
      rowSelection: { mode: "singleRow", checkboxes: false, enableClickSelection: true },
      tooltipShowDelay: 300,
      onRowClicked: function (event) {
        if (event.event && event.event.defaultPrevented) return;
        var url = event.data && event.data.detail && event.data.detail.case_url;
        if (url) window.location.assign(url);
      },
      onGridReady: function (event) {
        OrrixGrid.restoreColumnState(event.api, STORAGE_KEY);
        applyResponsiveColumns(event.api, document.getElementById("cases-grid"));
      }
    };

    var api = agGrid.createGrid(host, options);
    var save = OrrixGrid.persistColumnState(api, STORAGE_KEY);

    ["columnMoved", "columnResized", "columnVisible", "columnPinned", "sortChanged"].forEach(
      function (eventName) {
        api.addEventListener(eventName, save);
      }
    );

    var quickFilter = document.getElementById("cases-quick-filter");
    if (quickFilter) {
      quickFilter.addEventListener("input", function () {
        api.setGridOption("quickFilterText", quickFilter.value);
      });
    }

    // Quick-filter chips: each one drops a fixed phrase into the quick
    // filter, so they are a shortcut over the same mechanism, not a second
    // one that could disagree with it.
    var chips = document.querySelectorAll("[data-case-filter]");
    Array.prototype.forEach.call(chips, function (chipButton) {
      chipButton.addEventListener("click", function () {
        Array.prototype.forEach.call(chips, function (other) {
          other.classList.toggle("active", other === chipButton);
        });
        var value = chipButton.getAttribute("data-case-filter") || "";
        if (quickFilter) quickFilter.value = value;
        api.setGridOption("quickFilterText", value);
      });
    });
    if (chips.length) chips[0].classList.add("active");

    var reset = document.getElementById("cases-reset-columns");
    if (reset) {
      reset.addEventListener("click", function () {
        OrrixGrid.clearColumnState(STORAGE_KEY);
        api.resetColumnState();
        applyResponsiveColumns(api, host);
        if (quickFilter) {
          quickFilter.value = "";
          api.setGridOption("quickFilterText", "");
        }
      });
    }

    // Re-apply the set only when the tier actually changes, so dragging a
    // window does not repeatedly undo a column the operator chose to show.
    var currentTier = null;
    function syncTier() {
      var tier = visibleFieldsFor(host.clientWidth).length;
      if (tier === currentTier) return;
      currentTier = tier;
      applyResponsiveColumns(api, host);
    }
    syncTier();

    if (window.ResizeObserver) {
      new window.ResizeObserver(syncTier).observe(host);
    } else {
      window.addEventListener("resize", syncTier);
    }

    OrrixGrid.loadJson("/api/cases")
      .then(function (rows) {
        api.setGridOption("rowData", rows);
        applyResponsiveColumns(api, host);
        OrrixGrid.playRowEntrance(host);
        if (!rows.length) {
          OrrixGrid.showNote(
            "cases-empty",
            "No disputes stored yet. Orrix fills this from webhooks and the polling fallback."
          );
        }
      })
      .catch(function (error) {
        OrrixGrid.showNote("cases-empty", "Could not load cases: " + error.message);
      });
  });
})();
