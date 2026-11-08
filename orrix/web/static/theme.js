/*
 * Pre-paint theme setter.
 *
 * Loaded blocking in <head> so the correct theme is on <html> before the
 * first frame. An inline script would trip our own CSP rule, so this lives
 * in a file and is served from /static like every other asset here.
 *
 * Resolution order:
 *   1. A stored choice, if the browser lets us read it.
 *   2. The operating system preference via matchMedia.
 *   3. Dark, the default this console is designed for.
 *
 * The stored read is wrapped in try/catch because some privacy modes throw
 * on localStorage access. Failure just means "fall back to the OS".
 */
(function () {
  var STORAGE_KEY = "orrix.theme.v1";
  var root = document.documentElement;

  function readStored() {
    try {
      var value = window.localStorage.getItem(STORAGE_KEY);
      if (value === "light" || value === "dark") {
        return value;
      }
    } catch (err) {
      return null;
    }
    return null;
  }

  function systemPrefers() {
    if (window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches) {
      return "light";
    }
    return "dark";
  }

  var theme = readStored() || systemPrefers();
  root.setAttribute("data-theme", theme);
  root.setAttribute("data-resolved-theme", theme);
})();
