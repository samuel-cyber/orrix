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
    link.className = "mono";
    link.href = "/cases/" + encodeURIComponent(params.value);
    link.textContent = params.value;
    return link;
  }

  var columns = [
    {
      headerName: "Dispute",
      field: "dispute_id",
      minWidth: 210,
      cellRenderer: disputeLink,
      filter: "agTextColumnFilter",
      // The expand arrow belongs on the first visible column.
      cellRendererParams: {},
      showRowGroup: false
    },
    {
      headerName: "Amount",
      field: "amount",
      width: 130,
      filter: "agNumberColumnFilter",
      cellClass: "mono amount-cell",
      valueFormatter: function (p) {
        if (!p.value) return "";
        return p.value + " " + ((p.data && p.data.currency) || "");
      }
    },
    { headerName: "Reason", field: "reason", minWidth: 230, filter: "agTextColumnFilter" },
    { headerName: "PayPal state", field: "state", minWidth: 190, filter: "agTextColumnFilter" },
    {
      headerName: "Due",
      field: "hours_left",
      minWidth: 140,
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
      headerName: "Tracking",
      field: "completeness",
      width: 160,
      filter: "agSetColumnFilter",
      cellRenderer: function (p) {
        return OrrixGrid.completenessChip(p.value);
      }
    },
    {
      headerName: "Review flags",
      field: "flags",
      minWidth: 230,
      filter: "agTextColumnFilter"
    },
    {
      headerName: "Orrix status",
      field: "orrix_status_label",
      minWidth: 250,
      filter: "agSetColumnFilter",
      cellRenderer: statusPill
    }
  ];

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
      rowHeight: 46,
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
      rowSelection: "single",
      tooltipShowDelay: 300,
      onRowClicked: function (event) {
        if (event.event && event.event.defaultPrevented) return;
        var url = event.data && event.data.detail && event.data.detail.case_url;
        if (url) window.location.assign(url);
      },
      onGridReady: function (event) {
        OrrixGrid.restoreColumnState(event.api, STORAGE_KEY);
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
        if (quickFilter) {
          quickFilter.value = "";
          api.setGridOption("quickFilterText", "");
        }
      });
    }

    OrrixGrid.loadJson("/api/cases")
      .then(function (rows) {
        api.setGridOption("rowData", rows);
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
