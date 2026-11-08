// Order ledger: a client-side row filter. Progressive enhancement only — the
// table is fully server-rendered and readable without this file. Every value
// is compared and read as text; nothing reaches an HTML sink.
(function () {
  "use strict";

  function cells(row) {
    var out = "";
    var tds = row.getElementsByTagName("td");
    for (var i = 0; i < tds.length; i += 1) {
      out += " " + (tds[i].textContent || "");
    }
    return out.toLowerCase();
  }

  function wire(table, input, empty) {
    if (!table || !input) {
      return;
    }
    var body = table.tBodies[0];
    if (!body) {
      return;
    }
    var rows = [];
    var trs = body.getElementsByTagName("tr");
    for (var i = 0; i < trs.length; i += 1) {
      rows.push(trs[i]);
    }

    function apply() {
      var needle = (input.value || "").trim().toLowerCase();
      var shown = 0;
      rows.forEach(function (row) {
        var hit = needle === "" || cells(row).indexOf(needle) !== -1;
        row.hidden = !hit;
        if (hit) {
          shown += 1;
        }
      });
      if (empty) {
        empty.hidden = shown !== 0;
      }
    }

    input.addEventListener("input", apply);
    apply();
  }

  function ready() {
    wire(
      document.querySelector("[data-orders-table]"),
      document.querySelector("[data-orders-filter]"),
      document.querySelector("[data-orders-empty]")
    );
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", ready);
  } else {
    ready();
  }
})();
