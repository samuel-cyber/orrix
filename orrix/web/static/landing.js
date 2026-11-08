/*
 * Landing page behaviour: scroll-reveal, count-up proof stats, and smooth
 * anchor scrolling. The trust-boundary diagram animates via CSS/SMIL; this
 * file only adds the progressive bits.
 *
 * Public page, so it loads nothing from the console shell. Everything is
 * guarded and works with scripting unavailable.
 */
(function () {
  function reduceMotion() {
    return window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  }

  function countUp(node) {
    var target = node.getAttribute("data-count-to");
    if (target === null) {
      return;
    }
    var end = parseFloat(target);
    if (isNaN(end)) {
      return;
    }
    if (reduceMotion()) {
      node.textContent = node.getAttribute("data-count-text") || target;
      return;
    }
    var duration = 1100;
    var began = null;
    function step(now) {
      if (began === null) {
        began = now;
      }
      var progress = Math.min((now - began) / duration, 1);
      node.textContent = String(Math.round(end * progress));
      if (progress < 1) {
        window.requestAnimationFrame(step);
      } else {
        node.textContent = node.getAttribute("data-count-text") || String(Math.round(end));
      }
    }
    window.requestAnimationFrame(step);
  }

  function wireReveal() {
    var nodes = document.querySelectorAll(".reveal");
    if (!nodes.length) {
      return;
    }
    if (!("IntersectionObserver" in window)) {
      document.documentElement.classList.add("no-observer");
      return;
    }
    if (reduceMotion()) {
      for (var i = 0; i < nodes.length; i += 1) {
        nodes[i].classList.add("is-visible");
      }
      return;
    }
    var observer = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting) {
          entry.target.classList.add("is-visible");
          if (entry.target.hasAttribute("data-count-to")) {
            countUp(entry.target);
          }
          observer.unobserve(entry.target);
        }
      });
    }, { threshold: 0.15, rootMargin: "0px 0px -6% 0px" });
    for (var j = 0; j < nodes.length; j += 1) {
      observer.observe(nodes[j]);
    }
  }

  function wireSmoothAnchors() {
    if (reduceMotion()) {
      return;
    }
    var links = document.querySelectorAll('a[href^="#"]');
    for (var i = 0; i < links.length; i += 1) {
      links[i].addEventListener("click", function (event) {
        var id = this.getAttribute("href").slice(1);
        var target = id ? document.getElementById(id) : null;
        if (!target) {
          return;
        }
        event.preventDefault();
        target.scrollIntoView({ behavior: "smooth", block: "start" });
      });
    }
  }

  function wireTheme() {
    var toggle = document.querySelector("[data-theme-toggle]");
    if (!toggle) {
      return;
    }
    function current() {
      return document.documentElement.getAttribute("data-theme") === "light" ? "light" : "dark";
    }
    toggle.addEventListener("click", function () {
      var next = current() === "light" ? "dark" : "light";
      document.documentElement.setAttribute("data-theme", next);
      document.documentElement.setAttribute("data-resolved-theme", next);
      try {
        window.localStorage.setItem("orrix.theme.v1", next);
      } catch (err) {
        /* Not fatal: the toggle still works for this page view. */
      }
      toggle.setAttribute("aria-pressed", next === "light" ? "true" : "false");
    });
    toggle.setAttribute("aria-pressed", current() === "light" ? "true" : "false");
  }

  function boot() {
    wireTheme();
    wireReveal();
    wireSmoothAnchors();
    // Stats already in view on a short screen never scroll, so kick them.
    var inline = document.querySelectorAll(".hero-stats [data-count-to]");
    for (var i = 0; i < inline.length; i += 1) {
      countUp(inline[i]);
    }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
})();
