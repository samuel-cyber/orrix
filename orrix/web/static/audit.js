// Audit log grid. Data comes from /api/audit.
(function () {
  "use strict";

  function originBadge(params) {
    var span = document.createElement("span");
    span.className = "origin origin-" + (params.data ? params.data.origin_tag : "");
    span.textContent = params.value || "";
    return span;
  }

  var columns = [
    { headerName: "Seq", field: "seq", width: 90, sort: "desc", cellClass: "mono" },
    { headerName: "Time", field: "ts", minWidth: 220, cellClass: "mono" },
    { headerName: "Actor", field: "actor", width: 130 },
    { headerName: "Action", field: "action", minWidth: 280, cellClass: "mono" },
    { headerName: "Dispute", field: "dispute_id", minWidth: 190, cellClass: "mono" },
    {
      headerName: "Origin",
      field: "origin_label",
      minWidth: 220,
      cellRenderer: originBadge,
    },
    { headerName: "Payload hash", field: "payload_hash", minWidth: 160, cellClass: "mono" },
    { headerName: "Entry hash", field: "entry_hash", minWidth: 160, cellClass: "mono" },
  ];

  var options = {
    columnDefs: columns,
    rowData: [],
    defaultColDef: { sortable: true, resizable: true, filter: true, flex: 1 },
  };

  document.addEventListener("DOMContentLoaded", function () {
    var host = document.getElementById("audit-grid");
    if (!host) return;

    var api = agGrid.createGrid(host, options);

    fetch("/api/audit", { headers: { Accept: "application/json" } })
      .then(function (response) {
        if (!response.ok) throw new Error("status " + response.status);
        return response.json();
      })
      .then(function (rows) {
        api.setGridOption("rowData", rows);
      });
  });
})();
