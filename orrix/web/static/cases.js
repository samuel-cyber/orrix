// Dispute queue grid. Data comes from /api/cases; nothing is interpolated
// into this file, so the CSP needs no inline script.
(function () {
  "use strict";

  function chip(status) {
    var map = {
      yes: "chip-confirmed",
      "seller-asserted": "chip-seller",
      no: "chip-unavailable",
    };
    var span = document.createElement("span");
    span.className = "chip " + (map[status] || "chip-unavailable");
    span.textContent = status;
    return span;
  }

  var columns = [
    {
      headerName: "Dispute",
      field: "dispute_id",
      minWidth: 200,
      cellClass: "mono",
      filter: "agTextColumnFilter",
    },
    {
      headerName: "Amount",
      field: "amount",
      width: 120,
      cellClass: "mono",
      valueFormatter: function (p) {
        if (!p.value) return "";
        return p.value + " " + (p.data.currency || "");
      },
    },
    { headerName: "Reason", field: "reason", minWidth: 220, filter: "agTextColumnFilter" },
    { headerName: "State", field: "state", minWidth: 170, filter: "agTextColumnFilter" },
    {
      headerName: "Due",
      field: "hours_left",
      minWidth: 130,
      sort: "asc",
      comparator: function (a, b) {
        if (a === null || a === undefined) return 1;
        if (b === null || b === undefined) return -1;
        return a - b;
      },
      cellClass: function (p) {
        return p.data && p.data.urgent ? "urgent-cell" : null;
      },
      valueFormatter: function (p) {
        return p.data ? p.data.due_label : "";
      },
      tooltipValueGetter: function (p) {
        return p.data ? p.data.due_date : "";
      },
    },
    {
      headerName: "Tracking",
      field: "completeness",
      width: 150,
      filter: "agTextColumnFilter",
      cellRenderer: function (p) {
        return chip(p.value);
      },
    },
    { headerName: "Review flags", field: "flags", minWidth: 220, filter: "agTextColumnFilter" },
    {
      headerName: "Orrix status",
      field: "orrix_status",
      minWidth: 180,
      cellClass: "mono",
      filter: "agTextColumnFilter",
    },
  ];

  var options = {
    columnDefs: columns,
    rowData: [],
    defaultColDef: { sortable: true, resizable: true, filter: true, flex: 1 },
    rowSelection: "single",
    tooltipShowDelay: 300,
    onRowClicked: function (event) {
      if (event.data && event.data.dispute_id) {
        window.location.href = "/cases/" + encodeURIComponent(event.data.dispute_id);
      }
    },
  };

  document.addEventListener("DOMContentLoaded", function () {
    var host = document.getElementById("cases-grid");
    if (!host) return;

    var api = agGrid.createGrid(host, options);

    fetch("/api/cases", { headers: { Accept: "application/json" } })
      .then(function (response) {
        if (!response.ok) throw new Error("status " + response.status);
        return response.json();
      })
      .then(function (rows) {
        api.setGridOption("rowData", rows);
        var empty = document.getElementById("cases-empty");
        if (empty && rows.length === 0) empty.hidden = false;
      })
      .catch(function (error) {
        var empty = document.getElementById("cases-empty");
        if (empty) {
          empty.hidden = false;
          empty.textContent = "Could not load cases: " + error.message;
        }
      });
  });
})();
