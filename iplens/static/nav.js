// The top menu's "More" dropdown is a plain <details>: it opens and closes by mouse and
// keyboard (Enter / Space on the summary) without this file. This only adds what <details>
// lacks: Escape closes it (focus back on the summary), and so does a click or focus outside.
(() => {
  const menus = Array.from(document.querySelectorAll("details.nav-more"));
  if (!menus.length) return;

  document.addEventListener("keydown", (e) => {
    if (e.key !== "Escape") return;
    for (const d of menus) {
      if (!d.open) continue;
      d.open = false;
      d.querySelector("summary").focus();
    }
  });

  document.addEventListener("click", (e) => {
    for (const d of menus) {
      if (d.open && !d.contains(e.target)) d.open = false;
    }
  });

  for (const d of menus) {
    // Tabbing past the last item closes it. A null relatedTarget (a click that moves focus
    // nowhere, e.g. Safari on a link) is left to the click handler.
    d.addEventListener("focusout", (e) => {
      if (d.open && e.relatedTarget && !d.contains(e.relatedTarget)) d.open = false;
    });
  }
})();
