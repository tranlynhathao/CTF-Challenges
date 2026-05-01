/* EggRoll Silent Orchard — vanilla JS (no deps).
   Handles copy buttons, host substitution in commands, and a tiny status ping. */
(function () {
  "use strict";

  // ---- host/port substitution ------------------------------------------------
  // Server-side templates may emit `__HOST__` and `__TCP_PORT__` placeholders so
  // commands always reflect the host the player is actually browsing.
  var host = window.location.hostname || "HOST";
  var webPort = window.location.port || (window.location.protocol === "https:" ? "443" : "80");
  // The vault TCP port is mapped at the docker-compose layer; default 41337.
  var tcpPort = (document.body && document.body.dataset && document.body.dataset.tcpPort) || "41337";

  function substitute(text) {
    if (!text) return text;
    return text
      .replace(/__HOST__/g, host)
      .replace(/__WEB_PORT__/g, webPort)
      .replace(/__TCP_PORT__/g, tcpPort);
  }

  document.querySelectorAll("[data-cmd]").forEach(function (el) {
    el.textContent = substitute(el.textContent);
    el.setAttribute("data-cmd", substitute(el.getAttribute("data-cmd") || ""));
  });

  // ---- copy buttons ----------------------------------------------------------
  document.querySelectorAll("button.copy").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var target = btn.getAttribute("data-target");
      var text = "";
      if (target) {
        var el = document.getElementById(target);
        if (el) text = el.textContent.trim();
      }
      if (!text) {
        var sib = btn.parentElement && btn.parentElement.querySelector("[data-cmd]");
        if (sib) text = sib.textContent.trim();
      }
      if (!text) return;
      var ok = function () {
        var prev = btn.textContent;
        btn.classList.add("ok");
        btn.textContent = "Copied";
        setTimeout(function () {
          btn.classList.remove("ok");
          btn.textContent = prev;
        }, 1200);
      };
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(ok).catch(fallbackCopy);
      } else {
        fallbackCopy();
      }
      function fallbackCopy() {
        var ta = document.createElement("textarea");
        ta.value = text;
        ta.style.position = "fixed";
        ta.style.left = "-9999px";
        document.body.appendChild(ta);
        ta.select();
        try { document.execCommand("copy"); ok(); } catch (e) { /* noop */ }
        document.body.removeChild(ta);
      }
    });
  });

  // ---- live status badges ----------------------------------------------------
  // A best-effort ping of /api/health to confirm the web surface is online.
  var status = document.querySelector("[data-status]");
  if (status) {
    fetch("/api/health", { cache: "no-store" })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (j) {
        if (j && j.ok) {
          status.textContent = "WEB ONLINE";
          status.classList.add("ok");
        } else {
          status.textContent = "WEB DEGRADED";
        }
      })
      .catch(function () { status.textContent = "WEB OFFLINE"; });
  }

})();
