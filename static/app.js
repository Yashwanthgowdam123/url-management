(function () {
  // confirm before destructive actions
  document.addEventListener("submit", function (e) {
    var m = e.target.getAttribute("data-confirm");
    if (m && !window.confirm(m)) e.preventDefault();
  });

  // avatar colours + auto-submitting filters
  document.querySelectorAll("[data-hue]").forEach(function (el) { el.style.setProperty("--h", el.getAttribute("data-hue")); });
  document.querySelectorAll("[data-autosubmit]").forEach(function (el) {
    el.addEventListener("change", function () { el.form.submit(); });
  });

  // add / edit dialog
  var dlg = document.getElementById("entryDialog");
  var fields = ["name", "url", "category", "environment", "owner", "tags", "description"];
  document.addEventListener("click", function (e) {
    var b = e.target.closest("[data-open]");
    if (b) {
      var mode = b.getAttribute("data-open");
      if (mode === "add" || mode === "edit") {
        var form = dlg.querySelector("form");
        form.reset();
        if (mode === "add") {
          form.action = dlg.getAttribute("data-add-url");
          dlg.querySelector("[data-title]").textContent = "Add URL";
          dlg.querySelector("[data-submit]").textContent = "Add URL";
        } else {
          form.action = b.getAttribute("data-action");
          fields.forEach(function (f) { form.elements[f].value = b.getAttribute("data-" + f) || ""; });
          dlg.querySelector("[data-title]").textContent = "Edit URL";
          dlg.querySelector("[data-submit]").textContent = "Save changes";
        }
        dlg.showModal();
      } else {
        var other = document.getElementById(mode);
        if (other) other.showModal();
      }
      return;
    }
    var c = e.target.closest("[data-close]");
    if (c) { c.closest("dialog").close(); return; }
    if (e.target.tagName === "DIALOG") e.target.close(); // click on backdrop
  });
})();
