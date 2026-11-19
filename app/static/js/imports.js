/* Refuse oversized reports before the browser starts sending them. The server enforces the same limit. */
(function () {
  "use strict";

  var input = document.getElementById("report");
  if (!input) { return; }
  var error = document.getElementById("reportError");
  var limit = Number(input.dataset.maxBytes);

  function tooLarge() {
    var file = input.files[0];
    var invalid = Boolean(file) && file.size > limit;
    error.hidden = !invalid;
    return invalid;
  }

  input.addEventListener("change", tooLarge);
  input.form.addEventListener("submit", function (event) {
    if (tooLarge()) { event.preventDefault(); }
  });
})();
