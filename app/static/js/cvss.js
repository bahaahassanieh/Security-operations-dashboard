/* CVSS v3.1 calculator UI. The authoritative score is computed on the server. */
(function () {
  "use strict";
  var script = document.getElementById("cvssScript");
  var form = document.getElementById("cvssForm");
  var scoreEl = document.getElementById("cvssScore");
  var sevEl = document.getElementById("cvssSeverity");
  var vectorEl = document.getElementById("cvssVector");

  function highlight() {
    form.querySelectorAll("label.btn").forEach(function (label) {
      var input = label.querySelector("input");
      label.classList.toggle("active", input.checked);
    });
  }

  function recompute() {
    highlight();
    var payload = {};
    new FormData(form).forEach(function (value, key) { payload[key] = value; });
    fetch(script.dataset.scoreUrl, {
      method: "POST", credentials: "same-origin",
      headers: { "Content-Type": "application/json", "X-CSRFToken": document.querySelector('meta[name="csrf-token"]').content },
      body: JSON.stringify(payload)
    }).then(function (r) { return r.json(); }).then(function (data) {
      if (data.error) { return; }
      scoreEl.textContent = data.base_score.toFixed(1);
      sevEl.textContent = data.severity;
      sevEl.className = "val-badge val-" + (data.severity === "none" ? "false_positive" : (data.severity === "critical" || data.severity === "high" ? "retest_failed" : "detected"));
      vectorEl.value = data.vector;
    }).catch(function () {});
  }

  form.addEventListener("change", recompute);
  recompute();
})();
