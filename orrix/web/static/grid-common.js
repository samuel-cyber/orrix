// Shared grid helpers. No data is ever assigned to innerHTML and nothing is
// evaluated as code: every value goes in through textContent.
var OrrixGrid = (function () {
  "use strict";

  // Single validated series hue (see docs: ΔE checks pass against the light
  // surface). Pass/fail is never carried by colour alone -- the bar labels
  // and the worded tiles above the chart say it in text.
  var SERIES_COLOR = "#1f5fd0";
  var INK = "#16191d";
  var INK_SOFT = "#5a6472";
  var GRID_LINE = "#eaeef3";

  function applyLicense() {
    var key = document.body.getAttribute("data-ag-grid-license");
    if (!key) return false;
    try {
      if (window.agGrid && agGrid.LicenseManager) {
        agGrid.LicenseManager.setLicenseKey(key);
        return true;
      }
    } catch (error) {
      // An invalid key must not take the page down; the grid still runs.
    }
    return false;
  }

  function csrfToken() {
    return document.body.getAttribute("data-csrf-token") || "";
  }

  // -- chips -------------------------------------------------------------

  function chip(text, className) {
    var span = document.createElement("span");
    span.className = "chip " + className;
    span.textContent = text == null ? "" : String(text);
    return span;
  }

  var COMPLETENESS_CLASS = {
    yes: "chip-confirmed",
    "seller-asserted": "chip-seller_asserted",
    no: "chip-unavailable"
  };

  function completenessChip(value) {
    return chip(value, COMPLETENESS_CLASS[value] || "chip-unavailable");
  }

  function statusChipClass(status) {
    if (status === "confirmed") return "chip-confirmed";
    if (status === "seller_asserted") return "chip-seller_asserted";
    if (status === "conflicting") return "chip-conflicting";
    return "chip-unavailable";
  }

  // Colour by how much time is left, with the text saying the same thing.
  // Thresholds are in hours: under three days is red, under seven is amber,
  // anything further out is mint, and an unknown deadline is grey.
  var HOURS_PER_DAY = 24;
  var URGENT_DAYS = 3;
  var SOON_DAYS = 7;

  function deadlineClass(hours) {
    if (hours == null) return "chip-deadline-unknown";
    if (hours <= 0) return "chip-deadline-passed";
    if (hours < URGENT_DAYS * HOURS_PER_DAY) return "chip-deadline-critical";
    if (hours < SOON_DAYS * HOURS_PER_DAY) return "chip-deadline-soon";
    return "chip-deadline-ok";
  }

  // chip-grid keeps the pill at 26px so it sits inside a 56px row instead of
  // being clipped by it.
  function deadlineChip(params) {
    var data = params.data || {};
    if (!data.due_label) return document.createTextNode("");
    var element = chip(data.due_label, deadlineClass(data.hours_left) + " chip-grid");
    if (data.due_date) element.title = data.due_date;
    return element;
  }

  // -- grid cell chips ---------------------------------------------------

  // A PayPal dispute state, as a chip rather than text that truncates to
  // "no..." in a narrow column.
  var STATE_CLASS = {
    REQUIRED_ACTION: "chip-seller_asserted",
    REQUIRED_OTHER_PARTY_ACTION: "chip-confirmed",
    UNDER_REVIEW: "chip-flag",
    RESOLVED: "chip-unavailable",
    OPEN: "chip-flag"
  };

  function stateChip(params) {
    var value = params.value == null ? "" : String(params.value);
    if (!value) return document.createTextNode("");
    var element = chip(
      value.replace(/_/g, " ").toLowerCase(),
      (STATE_CLASS[value] || "chip-unavailable") + " chip-grid"
    );
    element.title = value;
    return element;
  }

  // Review flags arrive as one comma-joined string. One readable chip plus
  // a "+n" count: two chips never fit this column's width, and a cut-off
  // second chip says less than a number does. The full list is the title.
  var FLAG_LIMIT = 1;

  function flagChips(params) {
    var raw = params.value == null ? "" : String(params.value);
    var flags = raw
      .split(",")
      .map(function (flag) {
        return flag.trim();
      })
      .filter(Boolean);

    if (!flags.length) {
      var none = document.createElement("span");
      none.className = "chip-more";
      none.textContent = "\u2014";
      return none;
    }

    var host = document.createElement("span");
    host.className = "chip-stack";
    host.title = flags.join(", ");

    flags.slice(0, FLAG_LIMIT).forEach(function (flag) {
      var tone = flag.indexOf("needs_human_review") === 0 ? "chip-conflicting" : "chip-flag";
      host.appendChild(chip(flag.replace(/_/g, " "), tone + " chip-grid"));
    });

    if (flags.length > FLAG_LIMIT) {
      var more = document.createElement("span");
      more.className = "chip-more";
      more.textContent = "+" + (flags.length - FLAG_LIMIT);
      host.appendChild(more);
    }
    return host;
  }

  // An amount with its currency beside it, right-aligned by the cell class.
  function amountCell(params) {
    var host = document.createElement("span");
    if (!params.value) {
      host.textContent = "";
      return host;
    }
    var value = document.createElement("span");
    value.textContent = String(params.value);
    host.appendChild(value);

    var currency = (params.data && params.data.currency) || "";
    if (currency) {
      var unit = document.createElement("span");
      unit.className = "amount-currency";
      unit.textContent = String(currency);
      host.appendChild(unit);
    }
    return host;
  }

  // The first-load fade-in. The class drives a staggered CSS animation and
  // is removed once it has played, so filtering does not replay it; under
  // prefers-reduced-motion the CSS does nothing at all.
  function playRowEntrance(host) {
    if (!host || host.getAttribute("data-entrance-played") === "1") return;
    host.setAttribute("data-entrance-played", "1");
    host.classList.add("orrix-grid--entering");
    window.setTimeout(function () {
      host.classList.remove("orrix-grid--entering");
    }, 500);
  }

  function originBadge(params) {
    var span = document.createElement("span");
    var tag = (params.data && params.data.origin_tag) || "";
    span.className = "origin origin-" + tag;
    span.textContent = params.value == null ? "" : String(params.value);
    return span;
  }

  // -- column state ------------------------------------------------------

  function persistColumnState(api, storageKey) {
    function save() {
      try {
        window.localStorage.setItem(storageKey, JSON.stringify(api.getColumnState()));
      } catch (error) {
        // Private mode, disabled storage, or a full quota. Column layout is
        // a convenience; losing it must never break the grid.
      }
    }
    return save;
  }

  function restoreColumnState(api, storageKey) {
    try {
      var stored = window.localStorage.getItem(storageKey);
      if (!stored) return;
      var state = JSON.parse(stored);
      if (Array.isArray(state) && state.length) {
        api.applyColumnState({ state: state, applyOrder: true });
      }
    } catch (error) {
      // Unreadable or stale state: fall back to the column definitions.
      try {
        window.localStorage.removeItem(storageKey);
      } catch (ignored) {}
    }
  }

  function clearColumnState(storageKey) {
    try {
      window.localStorage.removeItem(storageKey);
    } catch (error) {}
  }

  // -- fetch -------------------------------------------------------------

  function loadJson(url) {
    return fetch(url, { headers: { Accept: "application/json" } }).then(function (response) {
      if (!response.ok) throw new Error("status " + response.status);
      return response.json();
    });
  }

  function showNote(id, message) {
    var note = document.getElementById(id);
    if (!note) return;
    note.hidden = false;
    note.textContent = message;
  }

  // -- chart theme -------------------------------------------------------

  function chartThemeOverrides() {
    return {
      common: {
        title: { enabled: false },
        legend: { enabled: false },
        padding: { top: 8, right: 16, bottom: 8, left: 8 },
        axes: {
          category: {
            line: { stroke: GRID_LINE },
            tick: { stroke: GRID_LINE },
            label: { color: INK_SOFT, fontSize: 12 },
            gridLine: { enabled: false }
          },
          number: {
            line: { enabled: false },
            tick: { enabled: false },
            label: { color: INK_SOFT, fontSize: 12 },
            gridLine: { style: [{ stroke: GRID_LINE, lineDash: [] }] }
          }
        }
      },
      bar: {
        series: {
          fill: SERIES_COLOR,
          stroke: SERIES_COLOR,
          strokeWidth: 0,
          cornerRadius: 4,
          label: { enabled: true, color: INK, fontSize: 12 }
        }
      }
    };
  }

  return {
    SERIES_COLOR: SERIES_COLOR,
    applyLicense: applyLicense,
    csrfToken: csrfToken,
    chip: chip,
    completenessChip: completenessChip,
    statusChipClass: statusChipClass,
    deadlineChip: deadlineChip,
    deadlineClass: deadlineClass,
    stateChip: stateChip,
    flagChips: flagChips,
    amountCell: amountCell,
    playRowEntrance: playRowEntrance,
    originBadge: originBadge,
    persistColumnState: persistColumnState,
    restoreColumnState: restoreColumnState,
    clearColumnState: clearColumnState,
    loadJson: loadJson,
    showNote: showNote,
    chartThemeOverrides: chartThemeOverrides
  };
})();
