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
  function deadlineClass(hours) {
    if (hours == null) return "chip-deadline-unknown";
    if (hours <= 0) return "chip-deadline-passed";
    if (hours < 24) return "chip-deadline-critical";
    if (hours < 72) return "chip-deadline-soon";
    return "chip-deadline-ok";
  }

  function deadlineChip(params) {
    var data = params.data || {};
    if (!data.due_label) return document.createTextNode("");
    var element = chip(data.due_label, deadlineClass(data.hours_left));
    if (data.due_date) element.title = data.due_date;
    return element;
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
    originBadge: originBadge,
    persistColumnState: persistColumnState,
    restoreColumnState: restoreColumnState,
    clearColumnState: clearColumnState,
    loadJson: loadJson,
    showNote: showNote,
    chartThemeOverrides: chartThemeOverrides
  };
})();
