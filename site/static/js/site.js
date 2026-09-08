// Small enough to be plausible on a hand-made site, and it does one real
// thing: marks the current page in the nav. No analytics, matching the
// claim in the footer.
(function () {
    "use strict";
    var here = window.location.pathname.replace(/index\.html$/, "");
    var links = document.querySelectorAll("nav a");
    for (var i = 0; i < links.length; i++) {
        if (links[i].getAttribute("href") === here) {
            links[i].setAttribute("aria-current", "page");
        }
    }
})();
