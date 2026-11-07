// Audit log grid. Chain integrity is decided server-side and reported here;
// the browser never recomputes a hash.
(function () {
  "use strict";

  var STORAGE_KEY = "orrix.audit.columnState.v1";
  var firstBadSeq = null;

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

    var api = agGrid.createGrid(host, options);
    var save = OrrixGrid.persistColumnState(api, STORAGE_KEY);
    ["columnMoved", "columnResized", "columnVisible", "sortChanged"].forEach(function (name) {
      api.addEventListener(name, save);
    });

    function load() {
      return OrrixGrid.loadJson("/api/audit").then(function (payload) {
        firstBadSeq = payload.first_bad_seq;
        api.setGridOption("rowData", payload.rows || []);
        api.redrawRows();
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
      if (firstBadSeq !== null && !isNaN(firstBadSeq)) {
        api.ensureNodeVisible(function (node) {
          return node.data && node.data.seq === firstBadSeq;
        });
      }
    });
  });
})();
