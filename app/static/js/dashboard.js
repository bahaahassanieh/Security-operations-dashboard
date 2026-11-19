/* Dashboard charts. Data comes from the JSON API; labels are rendered as text by Chart.js. */
(function () {
  "use strict";

  var INK = "#9aa7c2";
  var GRID = "rgba(154, 167, 194, 0.14)";
  var SERIES = "#5b8def";
  var SEVERITY_COLORS = {
    critical: "#ff5c7a",
    high: "#ff9346",
    medium: "#f2c94c",
    low: "#4cc9f0",
    info: "#94a3b8"
  };
  var VALIDATION_LABELS = {
    detected: "Detected",
    needs_manual_review: "Needs review",
    confirmed: "Confirmed",
    false_positive: "False positive",
    accepted_risk: "Accepted risk",
    remediated: "Remediated",
    retest_failed: "Retest failed"
  };

  function capitalize(text) {
    return text.charAt(0).toUpperCase() + text.slice(1);
  }

  function truncate(text, length) {
    return text.length > length ? text.slice(0, length - 1) + "…" : text;
  }

  function horizontalBars(canvasId, labels, values, colors, valueLabel, fullLabels) {
    var canvas = document.getElementById(canvasId);
    if (!canvas || canvas.parentElement.dataset.chartEmpty === "true") {
      return;
    }
    new window.Chart(canvas, {
      type: "bar",
      data: {
        labels: labels,
        datasets: [{
          label: valueLabel,
          data: values,
          backgroundColor: colors,
          borderRadius: 4,
          borderSkipped: "start",
          maxBarThickness: 16,
          minBarLength: 2
        }]
      },
      options: {
        indexAxis: "y",
        maintainAspectRatio: false,
        responsive: true,
        plugins: {
          legend: { display: false },
          tooltip: {
            displayColors: false,
            callbacks: {
              title: function (items) {
                return fullLabels ? fullLabels[items[0].dataIndex] : items[0].label;
              }
            }
          }
        },
        scales: {
          x: {
            beginAtZero: true,
            border: { display: false },
            grid: { color: GRID },
            ticks: { color: INK, precision: 0 }
          },
          y: {
            border: { display: false },
            grid: { display: false },
            ticks: { color: INK }
          }
        }
      }
    });
  }

  function render(summary) {
    var levels = Object.keys(SEVERITY_COLORS);
    horizontalBars(
      "severityChart",
      levels.map(capitalize),
      levels.map(function (level) { return summary.findings.severity[level]; }),
      levels.map(function (level) { return SEVERITY_COLORS[level]; }),
      "Findings"
    );

    var statuses = Object.keys(VALIDATION_LABELS);
    horizontalBars(
      "validationChart",
      statuses.map(function (status) { return VALIDATION_LABELS[status]; }),
      statuses.map(function (status) { return summary.findings.validation[status]; }),
      SERIES,
      "Findings"
    );

    var applications = summary.most_vulnerable;
    horizontalBars(
      "vulnerableChart",
      applications.map(function (item) { return truncate(item.name, 22); }),
      applications.map(function (item) { return item.risk_score; }),
      SERIES,
      "Weighted risk score",
      applications.map(function (item) { return item.name + " (" + item.findings + " findings)"; })
    );
  }

  var script = document.getElementById("dashboardScript");
  fetch(script.dataset.summaryUrl, { credentials: "same-origin", headers: { Accept: "application/json" } })
    .then(function (response) {
      if (!response.ok) { throw new Error("HTTP " + response.status); }
      return response.json();
    })
    .then(render)
    .catch(function () {
      document.querySelectorAll(".chart-box").forEach(function (box) {
        box.dataset.chartEmpty = "true";
        box.querySelector(".chart-empty").textContent = "Chart data could not be loaded.";
      });
    });
})();
