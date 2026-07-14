/*
 * jwt-inspector — decode & inspect JWTs entirely in the browser.
 * No dependencies, no network calls. The token never leaves this page.
 */
(function () {
  "use strict";

  /* ---------------------------------------------------------------------- *
   * Base64url helpers (pure JS, no libraries)
   * ---------------------------------------------------------------------- */

  // Decode a base64url string to a UTF-8 string.
  function base64urlDecode(input) {
    if (typeof input !== "string" || input.length === 0) {
      throw new Error("empty segment");
    }
    // base64url -> base64
    var b64 = input.replace(/-/g, "+").replace(/_/g, "/");
    // pad to a multiple of 4
    var pad = b64.length % 4;
    if (pad === 1) throw new Error("invalid base64url length");
    if (pad) b64 += "====".slice(pad);

    var binary;
    try {
      binary = atob(b64);
    } catch (e) {
      throw new Error("not valid base64url");
    }

    // Convert the binary string into UTF-8 text.
    var bytes = new Uint8Array(binary.length);
    for (var i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    try {
      return new TextDecoder("utf-8", { fatal: false }).decode(bytes);
    } catch (e) {
      // Fallback for environments without TextDecoder.
      return decodeURIComponent(escape(binary));
    }
  }

  // Encode a UTF-8 string to base64url (used only to build the demo token).
  function base64urlEncode(str) {
    var utf8;
    try {
      utf8 = unescape(encodeURIComponent(str));
    } catch (e) {
      utf8 = str;
    }
    return btoa(utf8).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  /* ---------------------------------------------------------------------- *
   * JWT parsing
   * ---------------------------------------------------------------------- */

  function parseJwt(token) {
    var trimmed = String(token).trim();
    if (!trimmed) return { empty: true };

    // Strip an optional "Bearer " prefix people often paste.
    trimmed = trimmed.replace(/^Bearer\s+/i, "");

    var parts = trimmed.split(".");
    if (parts.length !== 3) {
      throw new Error(
        "A JWT must have 3 parts separated by dots (header.payload.signature). Found " +
          parts.length +
          "."
      );
    }

    var header, payload;
    try {
      header = JSON.parse(base64urlDecode(parts[0]));
    } catch (e) {
      throw new Error("Could not decode the header: " + e.message + ".");
    }
    try {
      payload = JSON.parse(base64urlDecode(parts[1]));
    } catch (e) {
      throw new Error("Could not decode the payload: " + e.message + ".");
    }

    return {
      header: header,
      payload: payload,
      signature: parts[2],
    };
  }

  /* ---------------------------------------------------------------------- *
   * JSON pretty-print with light syntax highlighting
   * ---------------------------------------------------------------------- */

  function escapeHtml(s) {
    return String(s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;");
  }

  function highlightJson(obj) {
    var json = JSON.stringify(obj, null, 2);
    // Tokenize: strings (incl. keys), numbers, booleans, null, punctuation.
    return escapeHtml(json).replace(
      /("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false)\b|\bnull\b|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)/g,
      function (match) {
        var cls = "tok-number";
        if (/^"/.test(match)) {
          cls = /:\s*$/.test(match) ? "tok-key" : "tok-string";
        } else if (/true|false/.test(match)) {
          cls = "tok-boolean";
        } else if (/null/.test(match)) {
          cls = "tok-null";
        }
        return '<span class="' + cls + '">' + match + "</span>";
      }
    );
  }

  /* ---------------------------------------------------------------------- *
   * Time / expiry helpers
   * ---------------------------------------------------------------------- */

  function isEpoch(v) {
    return typeof v === "number" && isFinite(v);
  }

  function formatLocal(epochSeconds) {
    var d = new Date(epochSeconds * 1000);
    if (isNaN(d.getTime())) return "invalid date";
    try {
      return d.toLocaleString(undefined, {
        year: "numeric",
        month: "short",
        day: "2-digit",
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
        timeZoneName: "short",
      });
    } catch (e) {
      return d.toString();
    }
  }

  // Human relative duration, e.g. "2 hours 5 minutes".
  function humanizeDuration(totalSeconds) {
    var s = Math.abs(Math.floor(totalSeconds));
    var units = [
      ["day", 86400],
      ["hour", 3600],
      ["minute", 60],
      ["second", 1],
    ];
    var out = [];
    for (var i = 0; i < units.length && out.length < 2; i++) {
      var name = units[i][0];
      var size = units[i][1];
      var qty = Math.floor(s / size);
      if (qty > 0) {
        out.push(qty + " " + name + (qty === 1 ? "" : "s"));
        s -= qty * size;
      }
    }
    return out.length ? out.join(" ") : "0 seconds";
  }

  // Returns { state: 'valid'|'expired'|'nbf'|'none', text, className }
  function expiryStatus(payload) {
    var now = Math.floor(Date.now() / 1000);
    var exp = isEpoch(payload.exp) ? payload.exp : null;
    var nbf = isEpoch(payload.nbf) ? payload.nbf : null;

    if (nbf !== null && now < nbf) {
      return {
        state: "nbf",
        className: "badge-nbf",
        text: "not yet valid — starts in " + humanizeDuration(nbf - now),
      };
    }
    if (exp !== null) {
      if (now >= exp) {
        return {
          state: "expired",
          className: "badge-expired",
          text: "expired " + humanizeDuration(now - exp) + " ago",
        };
      }
      return {
        state: "valid",
        className: "badge-valid",
        text: "valid — expires in " + humanizeDuration(exp - now),
        exp: exp,
      };
    }
    return { state: "none" };
  }

  /* ---------------------------------------------------------------------- *
   * Claims table
   * ---------------------------------------------------------------------- */

  var STRING_CLAIMS = [
    ["iss", "Issuer"],
    ["sub", "Subject"],
    ["aud", "Audience"],
    ["azp", "Authorized party"],
    ["scope", "Scope"],
    ["jti", "JWT ID"],
  ];

  var TIME_CLAIMS = [
    ["exp", "Expiration"],
    ["iat", "Issued at"],
    ["nbf", "Not before"],
  ];

  function stringifyClaim(v) {
    if (Array.isArray(v)) return v.join(", ");
    if (v === null || typeof v === "object") return JSON.stringify(v);
    return String(v);
  }

  function buildClaimRow(label, code, valueHtml) {
    var tr = document.createElement("tr");
    var tdKey = document.createElement("td");
    tdKey.innerHTML =
      '<span class="claim-label">' +
      escapeHtml(label) +
      '</span> <span class="claim-code">' +
      escapeHtml(code) +
      "</span>";
    var tdVal = document.createElement("td");
    tdVal.className = "claim-value";
    tdVal.innerHTML = valueHtml;
    tr.appendChild(tdKey);
    tr.appendChild(tdVal);
    return tr;
  }

  function renderClaims(payload) {
    var body = els.claimsBody;
    body.innerHTML = "";
    var count = 0;

    STRING_CLAIMS.forEach(function (c) {
      var key = c[0];
      if (payload[key] === undefined) return;
      body.appendChild(
        buildClaimRow(c[1], key, escapeHtml(stringifyClaim(payload[key])))
      );
      count++;
    });

    TIME_CLAIMS.forEach(function (c) {
      var key = c[0];
      var v = payload[key];
      if (v === undefined) return;
      var valueHtml;
      if (isEpoch(v)) {
        valueHtml =
          escapeHtml(String(v)) +
          '<span class="human">' +
          escapeHtml(formatLocal(v)) +
          "</span>";
      } else {
        valueHtml = escapeHtml(stringifyClaim(v));
      }
      body.appendChild(buildClaimRow(c[1], key, valueHtml));
      count++;
    });

    els.noClaims.hidden = count > 0;
  }

  /* ---------------------------------------------------------------------- *
   * Live countdown for valid tokens
   * ---------------------------------------------------------------------- */

  var countdownTimer = null;

  function stopCountdown() {
    if (countdownTimer) {
      clearInterval(countdownTimer);
      countdownTimer = null;
    }
  }

  function renderExpiryBadge(payload) {
    stopCountdown();
    var status = expiryStatus(payload);
    var badge = els.expBadge;

    if (status.state === "none") {
      badge.hidden = true;
      return;
    }

    badge.hidden = false;
    badge.className = "badge " + status.className;
    badge.textContent = status.text;

    if (status.state === "valid" && typeof status.exp === "number") {
      countdownTimer = setInterval(function () {
        var now = Math.floor(Date.now() / 1000);
        if (now >= status.exp) {
          renderExpiryBadge(payload); // flip to expired
          return;
        }
        badge.textContent = "valid — expires in " + humanizeDuration(status.exp - now);
      }, 1000);
    }
  }

  /* ---------------------------------------------------------------------- *
   * Rendering
   * ---------------------------------------------------------------------- */

  var lastDecoded = { header: null, payload: null };

  function showError(message) {
    els.error.hidden = false;
    els.error.textContent = message;
    els.results.hidden = true;
    stopCountdown();
  }

  function clearError() {
    els.error.hidden = true;
    els.error.textContent = "";
  }

  function render(token) {
    if (!token || !token.trim()) {
      clearError();
      els.results.hidden = true;
      stopCountdown();
      return;
    }

    var result;
    try {
      result = parseJwt(token);
    } catch (e) {
      showError(e.message);
      return;
    }

    if (result.empty) {
      els.results.hidden = true;
      clearError();
      return;
    }

    clearError();
    lastDecoded.header = result.header;
    lastDecoded.payload = result.payload;

    els.headerJson.innerHTML = highlightJson(result.header);
    els.payloadJson.innerHTML = highlightJson(result.payload);
    els.signature.textContent = result.signature || "(no signature)";

    // alg badge
    var alg = result.header && result.header.alg;
    if (alg) {
      els.algBadge.hidden = false;
      els.algBadge.textContent = "alg: " + alg;
    } else {
      els.algBadge.hidden = true;
    }

    renderClaims(result.payload);
    renderExpiryBadge(result.payload);

    els.results.hidden = false;
  }

  /* ---------------------------------------------------------------------- *
   * Demo token — BUILT AT RUNTIME (no hardcoded token literal on disk)
   * ---------------------------------------------------------------------- */

  function buildSampleToken() {
    var now = Math.floor(Date.now() / 1000);
    var header = { alg: "HS256", typ: "JWT" };
    var payload = {
      iss: "https://auth.devya.dev",
      sub: "user_8f3a12c9",
      aud: "jwt-inspector",
      azp: "devya-web-client",
      scope: "openid profile email",
      name: "Ada Lovelace",
      email: "ada@example.com",
      roles: ["admin", "engineer"],
      iat: now - 300, // issued 5 minutes ago
      nbf: now - 300,
      exp: now + 3600, // valid for the next hour
    };
    // A fake, clearly-non-real signature segment (not a cryptographic value).
    var fakeSig = base64urlEncode("demo-signature-not-verified");
    return (
      base64urlEncode(JSON.stringify(header)) +
      "." +
      base64urlEncode(JSON.stringify(payload)) +
      "." +
      fakeSig
    );
  }

  /* ---------------------------------------------------------------------- *
   * Clipboard
   * ---------------------------------------------------------------------- */

  function copyToClipboard(text, btn) {
    var done = function () {
      var original = btn.textContent;
      btn.textContent = "Copied";
      btn.classList.add("copied");
      setTimeout(function () {
        btn.textContent = original;
        btn.classList.remove("copied");
      }, 1400);
    };

    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(done, function () {
        legacyCopy(text, done);
      });
    } else {
      legacyCopy(text, done);
    }
  }

  function legacyCopy(text, done) {
    var ta = document.createElement("textarea");
    ta.value = text;
    ta.setAttribute("readonly", "");
    ta.style.position = "absolute";
    ta.style.left = "-9999px";
    document.body.appendChild(ta);
    ta.select();
    try {
      document.execCommand("copy");
      done();
    } catch (e) {
      /* no-op */
    }
    document.body.removeChild(ta);
  }

  /* ---------------------------------------------------------------------- *
   * Wire-up
   * ---------------------------------------------------------------------- */

  var els = {};

  function cacheEls() {
    els.input = document.getElementById("token-input");
    els.results = document.getElementById("results");
    els.error = document.getElementById("error-box");
    els.headerJson = document.getElementById("header-json");
    els.payloadJson = document.getElementById("payload-json");
    els.signature = document.getElementById("signature-value");
    els.algBadge = document.getElementById("alg-badge");
    els.expBadge = document.getElementById("exp-badge");
    els.claimsBody = document.getElementById("claims-body");
    els.noClaims = document.getElementById("no-claims");
    els.sampleBtn = document.getElementById("sample-btn");
    els.clearBtn = document.getElementById("clear-btn");
  }

  function init() {
    cacheEls();

    els.input.addEventListener("input", function () {
      render(els.input.value);
    });

    els.sampleBtn.addEventListener("click", function () {
      els.input.value = buildSampleToken();
      render(els.input.value);
      els.input.focus();
    });

    els.clearBtn.addEventListener("click", function () {
      els.input.value = "";
      render("");
      els.input.focus();
    });

    document.querySelectorAll(".btn-copy").forEach(function (btn) {
      btn.addEventListener("click", function () {
        var which = btn.getAttribute("data-copy");
        var data = which === "header" ? lastDecoded.header : lastDecoded.payload;
        if (data == null) return;
        copyToClipboard(JSON.stringify(data, null, 2), btn);
      });
    });

    // Decode anything already in the field (e.g. browser autofill / restore).
    if (els.input.value) render(els.input.value);
  }

  if (typeof document !== "undefined") {
    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", init);
    } else {
      init();
    }
  }

  // Expose pure helpers for testing in Node (no effect in the browser).
  if (typeof module !== "undefined" && module.exports) {
    module.exports = {
      base64urlDecode: base64urlDecode,
      base64urlEncode: base64urlEncode,
      parseJwt: parseJwt,
      expiryStatus: expiryStatus,
      humanizeDuration: humanizeDuration,
    };
  }
})();
