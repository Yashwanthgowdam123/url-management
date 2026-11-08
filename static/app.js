document.addEventListener("submit", function (e) {
  var m = e.target.getAttribute("data-confirm");
  if (m && !window.confirm(m)) e.preventDefault();
});
