// "Copy" buttons next to generated Terraform snippets: <button data-copy="#id">.
(function () {
  "use strict";
  document.addEventListener("click", function (ev) {
    var btn = ev.target.closest("button[data-copy]");
    if (!btn) return;
    var src = document.querySelector(btn.getAttribute("data-copy"));
    if (!src || !navigator.clipboard) return;
    navigator.clipboard.writeText(src.textContent).then(function () {
      var label = btn.textContent;
      btn.textContent = "Copied";
      setTimeout(function () { btn.textContent = label; }, 1200);
    });
  });
})();
