/* Live job monitoring. All server text is inserted with textContent, never as HTML. */
(function () {
  "use strict";

  var log = document.getElementById("jobLog");
  var runs = document.getElementById("toolRuns");
  var statusBadge = document.getElementById("jobStatus");
  var bar = document.querySelector("#jobProgress .progress-bar");
  var progress = document.getElementById("jobProgress");
  var lastEvent = 0;
  var FINISHED = ["completed", "failed", "cancelled"];

  function cell(row, text) {
    var td = document.createElement("td");
    td.textContent = text;
    row.appendChild(td);
    return td;
  }

  function addEvent(event) {
    var line = document.createElement("div");
    line.className = "log-" + event.level;
    var time = document.createElement("span");
    time.className = "log-time";
    time.textContent = event.time;
    line.appendChild(time);
    line.appendChild(document.createTextNode((event.module ? "[" + event.module + "] " : "") + event.message));
    log.appendChild(line);
    log.scrollTop = log.scrollHeight;
    lastEvent = event.id;
  }

  function renderRuns(items) {
    runs.replaceChildren();
    items.forEach(function (item) {
      var row = document.createElement("tr");
      cell(row, item.tool);
      cell(row, item.target || "—").className = "cell-wrap";
      cell(row, item.status);
      cell(row, item.exit_code === null ? "—" : String(item.exit_code));
      cell(row, item.duration_ms === null ? "—" : (item.duration_ms / 1000).toFixed(1) + "s");
      var output = cell(row, "");
      if (runs.dataset.canDownload === "true" && item.status !== "running") {
        var link = document.createElement("a");
        link.href = runs.dataset.outputUrl.replace("/0/", "/" + item.id + "/");
        link.textContent = "Download";
        output.appendChild(link);
      }
      runs.appendChild(row);
    });
  }

  function updateControls(job) {
    var finished = FINISHED.indexOf(job.status) !== -1;
    document.querySelectorAll("[data-job-action]").forEach(function (button) {
      var action = button.dataset.jobAction;
      button.disabled = finished ||
        (action === "pause" && (job.status !== "running" || job.pause_requested)) ||
        (action === "resume" && !job.pause_requested) ||
        (action === "cancel" && job.cancel_requested);
    });
  }

  function poll() {
    fetch(log.dataset.statusUrl + "?after=" + lastEvent, { credentials: "same-origin" })
      .then(function (response) {
        if (!response.ok) { throw new Error("HTTP " + response.status); }
        return response.json();
      })
      .then(function (job) {
        statusBadge.textContent = job.status;
        statusBadge.className = "badge job-" + job.status;
        bar.style.width = job.progress + "%";
        progress.setAttribute("aria-valuenow", job.progress);
        job.events.forEach(addEvent);
        renderRuns(job.tool_runs);
        updateControls(job);
        if (FINISHED.indexOf(job.status) === -1 || job.events.length === 200) {
          window.setTimeout(poll, 2500);
        }
      })
      .catch(function () { window.setTimeout(poll, 5000); });
  }

  poll();
})();
