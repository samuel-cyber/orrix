/*
 * App shell behaviour for the logged-in console.
 *
 * Everything here is progressive enhancement: the pages render and work
 * without it. It builds DOM with createElement and textContent only -- no
 * innerHTML anywhere, so the CSP stays strict and the boundary tests stay
 * green.
 *
 * Features: theme toggle, sidebar collapse, command palette (Ctrl/Cmd+K),
 * toasts, a live "polled Ns ago" ticker, count-up stat numbers, and
 * IntersectionObserver scroll-reveal.
 */
(function () {
  var THEME_KEY = "orrix.theme.v1";
  var SIDEBAR_KEY = "orrix.sidebar.collapsed.v1";

  function store(key, value) {
    try {
      window.localStorage.setItem(key, value);
    } catch (err) {
      /* Private mode, quota, or a locked-down browser. Not fatal. */
    }
  }

  function read(key) {
    try {
      return window.localStorage.getItem(key);
    } catch (err) {
      return null;
    }
  }

  function el(tag, className, text) {
    var node = document.createElement(tag);
    if (className) {
      node.className = className;
    }
    if (text !== undefined && text !== null) {
      node.textContent = text;
    }
    return node;
  }

  // -- theme ------------------------------------------------------------

  function currentTheme() {
    return document.documentElement.getAttribute("data-theme") === "light" ? "light" : "dark";
  }

  function applyTheme(theme, persist) {
    document.documentElement.setAttribute("data-theme", theme);
    document.documentElement.setAttribute("data-resolved-theme", theme);
    var toggles = document.querySelectorAll("[data-theme-toggle]");
    for (var i = 0; i < toggles.length; i += 1) {
      toggles[i].setAttribute("aria-pressed", theme === "light" ? "true" : "false");
      toggles[i].setAttribute("title", theme === "light" ? "Switch to dark theme" : "Switch to light theme");
    }
    if (persist) {
      store(THEME_KEY, theme);
    }
  }

  function wireTheme() {
    var toggles = document.querySelectorAll("[data-theme-toggle]");
    for (var i = 0; i < toggles.length; i += 1) {
      toggles[i].addEventListener("click", function () {
        applyTheme(currentTheme() === "light" ? "dark" : "light", true);
      });
    }
    applyTheme(currentTheme(), false);

    if (window.matchMedia) {
      var query = window.matchMedia("(prefers-color-scheme: light)");
      var onChange = function () {
        if (read(THEME_KEY) === null) {
          applyTheme(query.matches ? "light" : "dark", false);
        }
      };
      if (query.addEventListener) {
        query.addEventListener("change", onChange);
      } else if (query.addListener) {
        query.addListener(onChange);
      }
    }
  }

  // -- sidebar ----------------------------------------------------------

  function wireSidebar() {
    var shell = document.querySelector(".shell");
    var button = document.querySelector("[data-sidebar-toggle]");
    if (!shell || !button) {
      return;
    }
    if (read(SIDEBAR_KEY) === "1") {
      shell.classList.add("is-collapsed");
    }
    button.addEventListener("click", function () {
      var collapsed = shell.classList.toggle("is-collapsed");
      store(SIDEBAR_KEY, collapsed ? "1" : "0");
      button.setAttribute("aria-expanded", collapsed ? "false" : "true");
    });
  }

  // -- toasts -----------------------------------------------------------

  function toastContainer() {
    var region = document.getElementById("toasts");
    if (!region) {
      region = el("div", "toasts");
      region.id = "toasts";
      region.setAttribute("aria-live", "polite");
      region.setAttribute("role", "status");
      document.body.appendChild(region);
    }
    return region;
  }

  function showToast(message, kind) {
    var region = toastContainer();
    var toast = el("div", "toast" + (kind ? " " + kind : ""), message);
    region.appendChild(toast);
    window.setTimeout(function () {
      toast.classList.add("is-leaving");
      window.setTimeout(function () {
        if (toast.parentNode) {
          toast.parentNode.removeChild(toast);
        }
      }, 300);
    }, 4200);
  }

  // -- poll ticker ------------------------------------------------------

  function wirePollTicker() {
    var node = document.querySelector("[data-poll-seconds]");
    if (!node) {
      return;
    }
    var base = parseInt(node.getAttribute("data-poll-seconds"), 10);
    if (isNaN(base)) {
      return;
    }
    var enabled = node.getAttribute("data-poll-enabled") === "1";
    var seconds = base;
    var label = node.getAttribute("data-poll-label") || "";

    // Mirrors poll_age_label in orrix/web/services.py. Keep the two in step.
    function ageLabel(value) {
      if (value < 60) {
        return value + "s";
      }
      if (value < 3600) {
        return Math.floor(value / 60) + "m";
      }
      if (value < 86400) {
        return Math.floor(value / 3600) + "h";
      }
      return Math.floor(value / 86400) + "d";
    }

    function paint() {
      if (seconds >= 0) {
        label = "polled " + ageLabel(seconds) + " ago";
      }
      node.textContent = label;
      node.classList.toggle("stale", enabled && seconds >= 300);
    }
    paint();

    window.setInterval(function () {
      seconds += 1;
      paint();
    }, 1000);
  }

  // -- count-up ---------------------------------------------------------

  function countUp(node) {
    var target = node.getAttribute("data-count-to");
    if (target === null) {
      return;
    }
    var end = parseFloat(target);
    if (isNaN(end)) {
      return;
    }
    var reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (reduce) {
      node.textContent = node.getAttribute("data-count-text") || target;
      return;
    }
    var start = 0;
    var duration = 900;
    var began = null;
    function step(now) {
      if (began === null) {
        began = now;
      }
      var progress = Math.min((now - began) / duration, 1);
      var value = start + (end - start) * progress;
      var rounded = Math.round(value);
      node.textContent = String(rounded);
      if (progress < 1) {
        window.requestAnimationFrame(step);
      } else {
        node.textContent = node.getAttribute("data-count-text") || String(Math.round(end));
      }
    }
    window.requestAnimationFrame(step);
  }

  function wireCountUp() {
    var nodes = document.querySelectorAll("[data-count-to]");
    for (var i = 0; i < nodes.length; i += 1) {
      countUp(nodes[i]);
    }
  }

  // -- mini bars --------------------------------------------------------

  function wireBars() {
    // Bar widths come from a data attribute, not a template style attribute,
    // so our own markup still carries no inline styles.
    var bars = document.querySelectorAll("[data-fill]");
    for (var i = 0; i < bars.length; i += 1) {
      var pct = parseFloat(bars[i].getAttribute("data-fill"));
      if (isNaN(pct)) {
        continue;
      }
      bars[i].style.width = Math.max(0, Math.min(pct, 100)) + "%";
    }
  }

  // -- reveal on scroll -------------------------------------------------

  function wireReveal() {
    var nodes = document.querySelectorAll(".reveal");
    if (!nodes.length) {
      return;
    }
    if (!("IntersectionObserver" in window)) {
      document.documentElement.classList.add("no-observer");
      return;
    }
    var reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (reduce) {
      for (var j = 0; j < nodes.length; j += 1) {
        nodes[j].classList.add("is-visible");
      }
      return;
    }
    var observer = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting) {
          entry.target.classList.add("is-visible");
          observer.unobserve(entry.target);
        }
      });
    }, { threshold: 0.12, rootMargin: "0px 0px -8% 0px" });
    for (var k = 0; k < nodes.length; k += 1) {
      observer.observe(nodes[k]);
    }
  }

  // -- command palette --------------------------------------------------

  function buildPalette() {
    // Prefer the markup the server rendered into the shell, so the palette
    // exists (and is announced) even if this script never runs. Build a
    // fallback only when that markup is absent.
    var backdrop = document.getElementById("command-palette");
    if (!backdrop) {
      backdrop = el("div", "palette-backdrop");
      backdrop.id = "command-palette";
      backdrop.setAttribute("role", "dialog");
      backdrop.setAttribute("aria-modal", "true");
      backdrop.setAttribute("aria-label", "Command palette");
      backdrop.hidden = true;
      document.body.appendChild(backdrop);
    }

    var panel = backdrop.querySelector(".command-palette");
    if (!panel) {
      panel = el("div", "command-palette");
      backdrop.appendChild(panel);
    }

    var input = backdrop.querySelector(".palette-input");
    if (!input) {
      input = el("input", "palette-input");
      input.type = "text";
      input.setAttribute("placeholder", "Jump to a page, case or action…");
      panel.appendChild(input);
    }
    input.setAttribute("aria-label", "Search commands");
    input.autocomplete = "off";

    var list = backdrop.querySelector(".palette-list");
    if (!list) {
      list = el("div", "palette-list");
      panel.appendChild(list);
    }
    list.setAttribute("role", "listbox");

    backdrop.hidden = true;
    return { backdrop: backdrop, input: input, list: list };
  }

  function paletteCommands() {
    var commands = [];
    var navLinks = document.querySelectorAll(".sidebar-nav a[href]");
    for (var i = 0; i < navLinks.length; i += 1) {
      commands.push({
        label: navLinks[i].textContent.trim(),
        kind: "Page",
        run: (function (href) {
          return function () {
            window.location.href = href;
          };
        })(navLinks[i].getAttribute("href")),
      });
    }
    var rowLinks = document.querySelectorAll("[data-palette-case]");
    for (var j = 0; j < rowLinks.length; j += 1) {
      commands.push({
        label: rowLinks[j].getAttribute("data-palette-case"),
        kind: "Case",
        run: (function (href) {
          return function () {
            window.location.href = href;
          };
        })(rowLinks[j].getAttribute("href")),
      });
    }
    var actions = document.querySelectorAll("[data-palette-action]");
    for (var k = 0; k < actions.length; k += 1) {
      commands.push({
        label: actions[k].getAttribute("data-palette-action"),
        kind: "Action",
        run: (function (node) {
          return function () {
            node.click();
          };
        })(actions[k]),
      });
    }
    return commands;
  }

  function wirePalette() {
    var palette = buildPalette();
    var all = [];
    var filtered = [];
    var selected = 0;

    function render() {
      palette.list.textContent = "";
      if (!filtered.length) {
        palette.list.appendChild(el("div", "palette-empty", "No matches"));
        return;
      }
      filtered.forEach(function (command, index) {
        var item = el("div", "palette-item");
        item.setAttribute("role", "option");
        if (index === selected) {
          item.setAttribute("aria-selected", "true");
        }
        item.appendChild(el("span", "pi-label", command.label));
        item.appendChild(el("span", "pi-kind", command.kind));
        item.addEventListener("mousedown", function (event) {
          event.preventDefault();
          choose(index);
        });
        palette.list.appendChild(item);
      });
    }

    function filter(query) {
      var needle = query.trim().toLowerCase();
      filtered = all.filter(function (command) {
        return !needle || command.label.toLowerCase().indexOf(needle) !== -1;
      });
      if (selected >= filtered.length) {
        selected = 0;
      }
      render();
    }

    function choose(index) {
      var command = filtered[index];
      if (!command) {
        return;
      }
      close();
      command.run();
    }

    function open() {
      all = paletteCommands();
      selected = 0;
      palette.backdrop.hidden = false;
      palette.input.value = "";
      filter("");
      palette.input.focus();
    }

    function close() {
      palette.backdrop.hidden = true;
    }

    function move(delta) {
      if (!filtered.length) {
        return;
      }
      selected = (selected + delta + filtered.length) % filtered.length;
      render();
      var active = palette.list.children[selected];
      if (active && active.scrollIntoView) {
        active.scrollIntoView({ block: "nearest" });
      }
    }

    palette.input.addEventListener("input", function () {
      filter(palette.input.value);
    });

    palette.input.addEventListener("keydown", function (event) {
      if (event.key === "ArrowDown") {
        event.preventDefault();
        move(1);
      } else if (event.key === "ArrowUp") {
        event.preventDefault();
        move(-1);
      } else if (event.key === "Enter") {
        event.preventDefault();
        choose(selected);
      } else if (event.key === "Escape") {
        event.preventDefault();
        close();
      }
    });

    palette.backdrop.addEventListener("mousedown", function (event) {
      if (event.target === palette.backdrop) {
        close();
      }
    });

    document.addEventListener("keydown", function (event) {
      var isK = event.key === "k" || event.key === "K";
      if (isK && (event.metaKey || event.ctrlKey)) {
        event.preventDefault();
        if (palette.backdrop.hidden) {
          open();
        } else {
          close();
        }
      } else if (event.key === "Escape" && !palette.backdrop.hidden) {
        close();
      }
    });

    var triggers = document.querySelectorAll("[data-palette-open]");
    for (var i = 0; i < triggers.length; i += 1) {
      triggers[i].addEventListener("click", open);
    }
  }

  // -- page transitions -------------------------------------------------

  function wireViewTransitions() {
    // Native, progressive enhancement. Where the View Transitions API is
    // absent, or the visitor asked for reduced motion, navigation is left
    // completely alone: the browser loads the next page as it normally would.
    if (!("startViewTransition" in document)) {
      return;
    }
    if (window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
      return;
    }
    document.addEventListener("click", function (event) {
      if (event.defaultPrevented || event.button !== 0) {
        return;
      }
      if (event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) {
        return;
      }
      var link = event.target.closest ? event.target.closest("a[href]") : null;
      if (!link || link.target || link.hasAttribute("download")) {
        return;
      }
      var href = link.getAttribute("href");
      if (!href || href.charAt(0) === "#") {
        return;
      }
      var url = new URL(link.href, window.location.href);
      if (url.origin !== window.location.origin) {
        return;
      }
      event.preventDefault();
      document.startViewTransition(function () {
        window.location.href = url.href;
      });
    });
  }

  // -- boot -------------------------------------------------------------

  function boot() {
    wireTheme();
    wireSidebar();
    wirePollTicker();
    wireCountUp();
    wireBars();
    wireReveal();
    wirePalette();
    wireViewTransitions();

    var flash = document.getElementById("flash-message");
    if (flash && flash.getAttribute("data-flash")) {
      showToast(flash.getAttribute("data-flash"), flash.getAttribute("data-flash-kind") || "");
    }
  }

  window.OrrixShell = { showToast: showToast };

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
})();
