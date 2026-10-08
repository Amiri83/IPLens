// Render server timestamps in the browser's local time zone.
// The server emits <time class="localtime" datetime="YYYY-MM-DDTHH:MM:SSZ">…UTC</time>;
// the UTC text is only a no-JavaScript fallback and the ISO value stays in the tooltip.
(function () {
  "use strict";
  var fmt = new Intl.DateTimeFormat(undefined, {
    year: "numeric", month: "short", day: "2-digit",
    hour: "2-digit", minute: "2-digit", second: "2-digit",
    timeZoneName: "short",
  });

  function render(root) {
    root.querySelectorAll("time.localtime[datetime]").forEach(function (el) {
      var d = new Date(el.getAttribute("datetime"));
      if (!isNaN(d.getTime())) el.textContent = fmt.format(d);
    });
  }

  window.iplensLocalTime = { format: function (d) { return fmt.format(d); }, render: render };
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", function () { render(document); });
  } else {
    render(document);
  }
})();
