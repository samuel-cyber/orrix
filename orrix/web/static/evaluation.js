// Evaluation: a pivot grid of system x attack category, and an integrated
// bar chart of unauthorized actions per system.
//
// Chart design notes: one measure across a handful of systems is a magnitude
// comparison, so a bar chart with a single validated hue. Pass/fail is never
// carried by colour -- a red/green split fails CVD separation (deutan dE 5.2)
// -- so every bar is labelled with its count and the worded tiles above the
// chart carry the verdict in text.
(function () {
  "use strict";

  var STORAGE_KEY = "orrix.evaluation.columnState.v1";

  var pivotColumns = [
    {
      headerName: "Label",
      field: "label",
      minWidth: 180,
      rowGroup: true,
      enableRowGroup: true
    },
    {
      headerName: "System",
      field: "system",
      minWidth: 200,
      rowGroup: true,
      enableRowGroup: true
    },
    {
      headerName: "Attack category",
      field: "attack_category",
      minWidth: 200,
      pivot: true,
      enablePivot: true
    },
    {
      headerName: "Unauthorized actions",
      field: "unauthorized_actions",
      aggFunc: "sum",
      enableValue: true,
      type: "numericColumn"
    },
    {
      headerName: "Soft failures",
      field: "soft_failures",
      aggFunc: "sum",
      enableValue: true,
      type: "numericColumn"
    },
    {
      headerName: "Runs",
      field: "runs",
      aggFunc: "sum",
      enableValue: true,
      type: "numericColumn"
    }
  ];

  var chartColumns = [
    { headerName: "System", field: "system", chartDataType: "category" },
    {
      headerName: "Unauthorized actions",
      field: "unauthorized_actions",
      chartDataType: "series"
    }
  ];

  // One bar per label+system, so a model's result is never silently pooled
  // with another model's.
  function totalsBySystem(rows) {
    var totals = {};
    rows.forEach(function (row) {
      var key = row.label ? row.label + " / " + row.system : row.system;
      if (!totals[key]) totals[key] = 0;
      totals[key] += row.unauthorized_actions || 0;
    });
    return Object.keys(totals)
      .sort()
      .map(function (system) {
        return { system: system, unauthorized_actions: totals[system] };
      });
  }

  function buildPivot(rows) {
    var host = document.getElementById("evaluation-grid");
    if (!host) return;

    var api = agGrid.createGrid(host, {
      columnDefs: pivotColumns,
      rowData: rows,
      pivotMode: true,
      defaultColDef: { sortable: true, resizable: true, filter: true, minWidth: 140 },
      autoGroupColumnDef: { headerName: "Label / system", minWidth: 260, pinned: "left" },
      groupDefaultExpanded: 1,
      sideBar: { toolPanels: ["columns", "filters"], defaultToolPanel: null },
      statusBar: {
        statusPanels: [
          { statusPanel: "agTotalRowCountComponent", align: "left" },
          { statusPanel: "agAggregationComponent", align: "right" }
        ]
      },
      onGridReady: function (event) {
        OrrixGrid.restoreColumnState(event.api, STORAGE_KEY);
      }
    });

    var save = OrrixGrid.persistColumnState(api, STORAGE_KEY);
    ["columnMoved", "columnResized", "columnVisible", "sortChanged"].forEach(function (name) {
      api.addEventListener(name, save);
    });
  }

  function buildChart(rows) {
    var container = document.getElementById("evaluation-chart");
    if (!container) return;

    var totals = totalsBySystem(rows);
    if (!totals.length) return;

    // AG Grid's integrated charts are produced by a grid, so a small
    // off-screen grid owns the aggregated series while the chart itself
    // renders into the visible container.
    var source = document.createElement("div");
    source.className = "chart-source ag-theme-quartz";
    document.body.appendChild(source);

    var api = agGrid.createGrid(source, {
      columnDefs: chartColumns,
      rowData: totals,
      enableCharts: true,
      cellSelection: true,
      chartThemeOverrides: OrrixGrid.chartThemeOverrides(),
      onFirstDataRendered: function (event) {
        try {
          event.api.createRangeChart({
            chartType: "groupedColumn",
            cellRange: {
              rowStartIndex: 0,
              rowEndIndex: totals.length - 1,
              columns: ["system", "unauthorized_actions"]
            },
            chartContainer: container,
            suppressChartRanges: true
          });
        } catch (error) {
          var note = document.createElement("p");
          note.className = "muted";
          note.textContent =
            "Chart unavailable (AG Grid Enterprise charts did not load): " + error.message;
          container.appendChild(note);
        }
      }
    });

    return api;
  }

  document.addEventListener("DOMContentLoaded", function () {
    OrrixGrid.applyLicense();

    OrrixGrid.loadJson("/api/evaluation")
      .then(function (payload) {
        var rows = payload.rows || [];
        if (!rows.length) return;
        buildPivot(rows);
        buildChart(rows);
      })
      .catch(function (error) {
        var container = document.getElementById("evaluation-chart");
        if (container) {
          var note = document.createElement("p");
          note.className = "muted";
          note.textContent = "Could not load evaluation results: " + error.message;
          container.appendChild(note);
        }
      });
  });
})();
