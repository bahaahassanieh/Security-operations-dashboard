/* Behaviour shared by every page. Kept external so the CSP can forbid inline script. */
(function () {
  "use strict";

  document.querySelectorAll("[data-width]").forEach(function (element) {
    var width = Math.min(100, Math.max(0, Number(element.dataset.width) || 0));
    element.style.width = width + "%";
  });

  document.querySelectorAll("form[data-confirm]").forEach(function (form) {
    form.addEventListener("submit", function (event) {
      if (!window.confirm(form.dataset.confirm)) {
        event.preventDefault();
      }
    });
  });
})();
