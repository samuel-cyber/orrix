/*
 * Attack Lab behaviour. Progressive enhancement only: the form posts and the
 * comparison renders without this file. Nothing is turned into markup and
 * nothing is evaluated as code -- values reach the DOM only through
 * textContent, so the CSP stays strict and the boundary tests stay green.
 */
(function () {
  "use strict";

  function reduceMotion() {
    return !!(
      window.matchMedia &&
      window.matchMedia("(prefers-reduced-motion: reduce)").matches
    );
  }

  // -- live character counter -------------------------------------------

  function wireCounter() {
    var textarea = document.querySelector("[data-lab-message]");
    var counter = document.querySelector("[data-lab-counter]");
    if (!textarea || !counter) {
      return;
    }
    var max = textarea.getAttribute("data-lab-max") || "";

    function update() {
      counter.textContent = String(textarea.value.length) + " / " + max;
    }

    textarea.addEventListener("input", update);
    update();
  }

  // -- preset select takes precedence over the message box ---------------

  function wirePreset() {
    var select = document.querySelector("[data-lab-preset]");
    var note = document.querySelector("[data-lab-preset-note]");
    if (!select || !note) {
      return;
    }

    function update() {
      var chosen = select.value !== "";
      note.textContent = chosen
        ? "This preset will be run; the message box is ignored."
        : "A chosen preset takes precedence over the message box.";
    }

    select.addEventListener("change", update);
    update();
  }

  // -- a gentle, motion-aware settle on the rendered result --------------

  function wireResult() {
    var lane = document.querySelector(".lane");
    if (!lane) {
      return;
    }
    // The state change is announced in text already; this is only a hint and
    // is skipped entirely when the reader prefers no motion.
    if (reduceMotion() || typeof lane.animate !== "function") {
      return;
    }
    lane.animate(
      [
        { opacity: 0, transform: "translateY(8px)" },
        { opacity: 1, transform: "none" }
      ],
      { duration: 260, easing: "ease-out" }
    );
  }

  function init() {
    wireCounter();
    wirePreset();
    wireResult();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
