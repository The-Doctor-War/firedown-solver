// =============================================================================
// YouTube N-Parameter Solver — Remote Module v13
// Hosted at: https://github.com/solarizeddev/firedown-solver
//
// Design principle: minimize structural assumptions about the player source.
// YouTube rotates base.js frequently — every assumption we make is a future
// breakage waiting to happen. This solver relies on RUNTIME behavior (calling
// candidate functions and checking outputs) rather than source-code pattern
// matching wherever possible.
//
// v9:  Runtime-based candidate detection via func.toString()
// v10: Bit-reversal r-scan (no maxR), r-outer loop, cipher !_newCh filter
// v11: Runtime candidate enumeration, brace-walk IIFE detection, dual-quote
//      'use strict', arithmetic-agnostic base scan.
// v12: N-param architecture changed in player 1bb6ee63 (Apr 2026) — the
//      standalone `f(r, p, x)` n-transform is gone. URL-class discovery as
//      primary strategy. Call-site literal extraction for cipher.
// v13: Stop the player from registering callbacks on the host's real event
//      loop. Previously SETUP_CODE used `if (typeof globalThis.setTimeout
//      === "undefined")` guards on its timer mocks. In Gecko's extension
//      sandbox setTimeout already exists, so the guards skipped installation
//      and the real timers were used. The player's IIFE registered callbacks
//      that fired AFTER our probe finished, generating code via new Function
//      / eval that referenced identifiers not present in our mocked env —
//      producing a SyntaxError every ~4ms, forever, in the host console.
//
//      Fix: install no-op timer mocks unconditionally. The player can't
//      schedule anything, so no residual callbacks survive the probe.
//
//      Note: TypeError spam from URL-class probing (`y.U.call is not a
//      function` etc.) is NOT addressed here — those are caught inside
//      _testCtor but Gecko logs them anyway as a runtime behavior. Cannot
//      be suppressed from JS. They're cosmetic; the solver still works.
// =============================================================================
var SOLVER_VERSION = 13;

var SETUP_CODE = [
    'if(typeof globalThis.XMLHttpRequest==="undefined"){globalThis.XMLHttpRequest={prototype:{}};}',
    'globalThis.location={hash:"",host:"www.youtube.com",hostname:"www.youtube.com",',
    'href:"https://www.youtube.com/watch?v=yt-dlp-wins",origin:"https://www.youtube.com",password:"",',
    'pathname:"/watch",port:"",protocol:"https:",search:"?v=yt-dlp-wins",username:"",',
    'assign:function(){},replace:function(){},reload:function(){},toString:function(){return this.href;}};',
    'var window=globalThis;',
    'if(typeof globalThis.document==="undefined"){globalThis.document=Object.create(null);}',
    'if(typeof globalThis.navigator==="undefined"){globalThis.navigator={userAgent:""};}',
    'if(typeof globalThis.self==="undefined"){globalThis.self=globalThis;}',
    'if(typeof globalThis.addEventListener==="undefined"){globalThis.addEventListener=function(){};}',
    'if(typeof globalThis.removeEventListener==="undefined"){globalThis.removeEventListener=function(){};}',
    // Timer mocks: UNCONDITIONAL replacement (no `typeof === "undefined"` guard).
    // The host environment (Gecko extension sandbox) provides real timers, but
    // we don't want them — any callback the player schedules during IIFE
    // execution would fire on the host event loop AFTER our probe completes,
    // generating console-spamming SyntaxErrors as the player tries to JIT code
    // in our minimal mocked environment. Replacing with no-ops makes timer
    // registrations silently disappear.
    'globalThis.setTimeout=function(){return 0;};',
    'globalThis.clearTimeout=function(){};',
    'globalThis.setInterval=function(){return 0;};',
    'globalThis.clearInterval=function(){};',
    'globalThis.requestAnimationFrame=function(){return 0;};',
    'globalThis.cancelAnimationFrame=function(){};',
    // queueMicrotask also silently dropped — same rationale.
    'globalThis.queueMicrotask=function(){};',
    'if(typeof globalThis.getComputedStyle==="undefined"){globalThis.getComputedStyle=function(){return{opacity:"1"};};}',
].join('\n');

/**
 * Find 'use strict' in either quote style.
 */
function findUseStrict(data) {
    var single = data.indexOf("'use strict';");
    var dbl = data.indexOf('"use strict";');
    if (single === -1) return dbl;
    if (dbl === -1) return single;
    return Math.min(single, dbl);
}

function useStrictLen(data, idx) {
    if (idx < 0) return 0;
    if (data.substring(idx, idx + 13) === "'use strict';") return 13;
    if (data.substring(idx, idx + 13) === '"use strict";') return 13;
    return 0;
}

/**
 * Find the string table variable and the index of "split" in it.
 * Used only by the XOR fallback probe — the URL-class path doesn't need it.
 */
function findStringTable(data) {
    var chunk = data.substring(0, 5000);
    var splitCalls = chunk.matchAll(/\.split\((['"])(.)(\1)\)/g);
    for (var sc of splitCalls) {
        var delimiter = sc[2], splitPos = sc.index;
        var before = data.substring(0, splitPos);
        var lastVar = null;
        for (var vm of before.matchAll(/var\s+(\w+)=(['"])/g)) lastVar = vm;
        if (!lastVar) continue;
        var content = data.substring(lastVar.index + lastVar[0].length, splitPos);
        var quote = lastVar[2];
        if (content.endsWith(quote)) content = content.slice(0, -1);
        content = content.replace(new RegExp('\\\\' + quote.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g'), quote);
        var entries = content.split(delimiter);
        var si = entries.indexOf('split');
        if (si >= 0 && entries.length > 10) return { tableVar: lastVar[1], splitIdx: si };
    }
    var arrRx = /var\s+(\w+)=\[/g, am;
    while ((am = arrRx.exec(chunk)) !== null) {
        var start = am.index + am[0].length - 1;
        var arrChunk = data.substring(start, start + 2000);
        var d = 0, p = 0;
        while (p < arrChunk.length) { if (arrChunk[p] === '[') d++; else if (arrChunk[p] === ']') { d--; if (d === 0) break; } p++; }
        var entries = [], sm, strRx = /"((?:[^"\\]|\\.)*)"/g;
        while ((sm = strRx.exec(arrChunk.substring(0, p))) !== null) entries.push(sm[1]);
        if (entries.length > 10) { var si = entries.indexOf('split'); if (si >= 0) return { tableVar: am[1], splitIdx: si }; }
    }
    return null;
}

/**
 * Find all literal (INT, INT, ...) call sites for every short identifier in
 * the source. Returns `{ name -> [[V, Y], ...] }`.
 *
 * Single-pass optimization: one regex scans the entire source, matching any
 * `NAME(INT, INT, ...)` pattern where NAME is ≤8 chars. This runs in ~25ms
 * on a 2.7MB base.js. Alternative per-name scanning (4891 names) took 11s.
 *
 * Rationale: on player 1bb6ee63, the cipher helper kp is invoked as
 * `kp(1, 7337, s)`, `kp(4, 7340, s)`, `kp(10, 7330, s)` — literal pairs
 * embedded at the call site. The earlier probe tried to derive Y from XOR
 * constants in the function body (`Y ^ V ^ NNNN = target_m_index`), but with
 * `T = Y ^ V` as the actual dispatch key and `Y` itself never appearing in
 * the body, that derivation is impossible.
 *
 * Call-site extraction gives us the exact literal pairs YouTube's code uses,
 * so we only need to test a handful of (V, Y) per candidate instead of
 * brute-forcing 256 × N bases.
 *
 * The `names` argument is ignored beyond the short-identifier filter — we
 * return sites for any identifier found, and the probe's `_resolveFn` handles
 * name-to-function lookup at runtime.
 */
function findCallSites(data, names) {
    var rx = /\b([a-zA-Z_$][\w$]{0,7})\s*\(\s*(-?\d+)\s*,\s*(-?\d+)\s*,/g;
    var byName = Object.create(null);
    var m;
    while ((m = rx.exec(data)) !== null) {
        var name = m[1];
        var V = parseInt(m[2]);
        var Y = parseInt(m[3]);
        if (!byName[name]) byName[name] = new Set();
        byName[name].add(V + ',' + Y);
    }
    // Materialize to arrays of [V, Y] tuples.
    var out = {};
    var keys = Object.keys(byName);
    for (var i = 0; i < keys.length; i++) {
        var k = keys[i];
        var arr = Array.from(byName[k]).map(function(s) {
            var p = s.split(',');
            return [parseInt(p[0]), parseInt(p[1])];
        });
        if (arr.length > 0) out[k] = arr;
    }
    return out;
}

/**
 * Find the largest var chain in the IIFE scope — static helper for fallback.
 */
function findVarChain(data) {
    var varIdx = 0;
    var biggest = { start: -1, count: 0, end: 0 };
    while (true) {
        var nextVar = data.indexOf('var ', varIdx);
        if (nextVar === -1 || nextVar > 25000) break;
        var pos = nextVar + 4;
        var commas = 0, bd = 0, pd = 0, inStr = false, sq = '';
        while (pos < data.length && pos - nextVar < 200000) {
            var ch = data[pos];
            if (inStr) { if (ch === sq && data[pos - 1] !== '\\') inStr = false; }
            else {
                if (ch === '"' || ch === "'") { inStr = true; sq = ch; }
                else if (ch === '{') bd++;
                else if (ch === '}') bd--;
                else if (ch === '(') pd++;
                else if (ch === ')') pd--;
                else if (ch === ',' && bd === 0 && pd === 0) commas++;
                else if (ch === ';' && bd === 0 && pd === 0) break;
            }
            pos++;
        }
        if (commas > biggest.count) biggest = { start: nextVar, count: commas, end: pos };
        varIdx = nextVar + 4;
    }

    if (biggest.count >= 50) {
        var chain = data.substring(biggest.start + 4, biggest.end);
        var names = [], depth = 0, start = 0, inStr = false, sq = '';
        for (var i = 0; i < chain.length; i++) {
            var ch = chain[i];
            if (inStr) { if (ch === sq && chain[i - 1] !== '\\') inStr = false; }
            else {
                if (ch === '"' || ch === "'") { inStr = true; sq = ch; }
                else if (ch === '{' || ch === '(' || ch === '[') depth++;
                else if (ch === '}' || ch === ')' || ch === ']') depth--;
                else if (ch === ',' && depth === 0) {
                    var name = chain.substring(start, i).trim();
                    var eq = name.indexOf('=');
                    if (eq !== -1) name = name.substring(0, eq).trim();
                    if (name && /^[\w$]+$/.test(name)) names.push(name);
                    start = i + 1;
                }
            }
        }
        var last = chain.substring(start).trim();
        var eq = last.indexOf('=');
        if (eq !== -1) last = last.substring(0, eq).trim();
        if (last && /^[\w$]+$/.test(last)) names.push(last);
        if (names.length > 0) return names;
    }

    var fallbackNames = new Set();
    var patterns = [
        /(?:^|[^a-zA-Z0-9_$])([a-zA-Z_$][\w$]*)\s*=\s*function\s*\(/g,
        /function\s+([a-zA-Z_$][\w$]*)\s*\(/g,
        /(?:^|[^a-zA-Z0-9_$])var\s+([a-zA-Z_$][\w$]*)\s*=\s*function\s*\(/g
    ];
    for (var pi = 0; pi < patterns.length; pi++) {
        var rx = patterns[pi], fm;
        while ((fm = rx.exec(data)) !== null) {
            if (fm[1] && fm[1].length <= 8) fallbackNames.add(fm[1]);
        }
    }
    return fallbackNames.size > 0 ? Array.from(fallbackNames) : [];
}

/**
 * Find the IIFE close position — walks known wrapper patterns, falls back
 * to generic `})(` matching.
 */
function findIifeClose(data) {
    var patterns = [
        '})(_yt_player)',
        ').call(this)',
        '}).call(this)',
        '})(this)',
        '})()',
        '})('
    ];
    for (var i = 0; i < patterns.length; i++) {
        var idx = data.lastIndexOf(patterns[i]);
        if (idx !== -1) return idx;
    }
    return -1;
}

/**
 * Build runtime probe for n-param discovery.
 *
 * Strategy order (inside the probe):
 *
 *   Phase A — URL-class discovery (primary for modern players):
 *     Walk _yt_player, globalThis, and nested namespaces up to depth 2.
 *     For each function whose toString() is short (<200 chars, no Promise/
 *     yield/async markers) and whose arity is 2, instantiate it with a
 *     googlevideo URL carrying a test `n` value and call `.get("n")` on
 *     the instance. Accept if the result is deterministic, input-dependent,
 *     and doesn't contain the input as a substring. This finds the URL
 *     parser class regardless of its name.
 *
 *   Phase B — XOR dispatcher fallback (legacy players):
 *     Only runs if Phase A found nothing. Enumerates candidate functions
 *     via static var-chain names + runtime globalThis/_yt_player walk,
 *     scans toString() for table-access patterns (XOR, sub, add), then
 *     bit-reversal r-scan across 0–255 testing each candidate/base pair.
 *     Accepts only when the output passes all of:
 *       - typeof === "string"
 *       - deterministic across repeated calls
 *       - new chars appear (not a passthrough)
 *       - input is NOT a substring of output  ← v12 fix
 *       - output doesn't start with "undefined"/"null"/"NaN"/"[object"
 *
 * The cache fast-path now records which strategy was used so we skip
 * straight to the correct one on subsequent calls with the same player.
 *
 * @param {string} mode - "n" or "sig"
 * @param {string[]} varNames - static var-chain names (may be empty)
 * @param {string} tableVar - XOR string table var name (for fallback probe)
 * @param {number} splitIdx - index of "split" in string table (for fallback)
 * @param {object} callSites - map of candidate name → [[V,Y], ...] literal pairs
 * @param {object|null} cache - { strategy, funcName, r, p, ctorPath } from prior solve
 */
function buildRuntimeProbe(mode, varNames, tableVar, splitIdx, callSites, cache) {
    var isNParam = mode !== 'sig';
    var resultKey = isNParam ? 'n' : 'sig';
    var nameKey = isNParam ? '_nName' : '_sigName';

    // ----- Cache fast-path ------------------------------------------------
    if (cache && cache.strategy === 'url-class' && cache.ctorPath && isNParam) {
        return _buildUrlClassFastPath(cache.ctorPath);
    }
    // Legacy v7-shaped caches (no `strategy` field but `funcName` present)
    // are treated as implicit XOR. Lets existing cached entries in storage.local
    // keep working after the solver upgrade, instead of silently falling through
    // to full re-solve on every first load post-upgrade.
    if (cache && cache.funcName && (cache.strategy === 'xor' || !cache.strategy)) {
        return _buildXorFastPath(mode, cache);
    }

    // ----- Phase A: URL-class discovery (n-param only) --------------------
    var phaseA = isNParam ? _buildUrlClassScan() : '';

    // ----- Phase B: XOR fallback ------------------------------------------
    var phaseB = _buildXorScan(mode, varNames, tableVar, splitIdx, callSites);

    // Skip Phase B if Phase A found something (n-param only)
    if (isNParam) {
        return phaseA + '\nif(!_result.' + resultKey + '){\n' + phaseB + '\n}\n';
    }
    return phaseB;
}

/**
 * Phase A: walk runtime objects, find URL-class constructor.
 * Produces a probe body that sets `_result.n` and `_result._nName` on success.
 */
function _buildUrlClassScan() {
    return [
        '// ===== Phase A: URL-class discovery =====',
        'var _T1="wapK3U_wOyBVm5K", _T2="ABCDEFGH12345678";',
        'var _URL1="https://rr1.googlevideo.com/videoplayback?n="+_T1;',
        'var _URL2="https://rr1.googlevideo.com/videoplayback?n="+_T2;',
        '// Pre-filter: looks like a short URL-parser constructor.',
        'function _looksLikeUrlCtor(c){',
        '  try {',
        '    if (typeof c !== "function") return false;',
        '    if (c.length !== 2) return false;',
        '    var s = Function.prototype.toString.call(c);',
        '    if (s.length > 200) return false;',
        '    if (/Promise|yield|async|generator|this\\.W\\./.test(s)) return false;',
        '    return true;',
        '  } catch(e) { return false; }',
        '}',
        '// Junk markers — outputs starting with these are stringified undefined/null/objects.',
        'var _JUNK=["undefined","null","NaN","[object"];',
        'function _isJunk(v){ for (var j=0;j<_JUNK.length;j++) if (v.indexOf(_JUNK[j])===0) return true; return false; }',
        '// Full behavioral test.',
        'function _testCtor(c){',
        '  if (!_looksLikeUrlCtor(c)) return null;',
        '  var i1,n1;',
        '  try { i1 = new c(_URL1, true); } catch(e) { return null; }',
        '  try {',
        '    if (!i1 || typeof i1.get !== "function") return null;',
        '    n1 = i1.get("n");',
        '    if (typeof n1 !== "string" || n1.length < 5 || n1.length > 200) return null;',
        '    if (n1 === _T1 || n1.indexOf(_T1) !== -1 || _isJunk(n1)) return null;',
        '  } catch(e) { return null; }',
        '  try {',
        '    var n1b = new c(_URL1, true).get("n");',
        '    if (n1 !== n1b) return null;',
        '    var n2 = new c(_URL2, true).get("n");',
        '    if (typeof n2 !== "string" || n2 === n1 || n2 === _T2) return null;',
        '    if (n2.indexOf(_T2) !== -1 || _isJunk(n2)) return null;',
        '    return n1;',
        '  } catch(e) { return null; }',
        '}',
        '// Walk runtime objects looking for a ctor that passes _testCtor.',
        'var _scanned = new Set(); var _foundA = null;',
        'function _walkA(obj, path, depth) {',
        '  if (!obj || depth > 2 || _foundA) return;',
        '  if (_scanned.has(obj)) return; _scanned.add(obj);',
        '  var keys; try { keys = Object.keys(obj); } catch(e) { return; }',
        '  for (var i=0; i<keys.length && !_foundA; i++) {',
        '    var k = keys[i], v;',
        '    try { v = obj[k]; } catch(e) { continue; }',
        '    if (typeof v === "function") {',
        '      var r; try { r = _testCtor(v); } catch(e) { r = null; }',
        '      if (r !== null) { _foundA = { ctor: v, path: path+k, sample: r }; return; }',
        '    } else if (typeof v === "object" && v !== null && depth < 2) {',
        '      _walkA(v, path+k+".", depth+1);',
        '    }',
        '  }',
        '}',
        '// Try _yt_player first (most likely home), then globalThis.',
        'try { if (typeof _yt_player !== "undefined") _walkA(_yt_player, "_yt_player.", 1); } catch(e) {}',
        'if (!_foundA) { try { _walkA(globalThis, "", 0); } catch(e) {} }',
        'if (_foundA) {',
        '  (function(c){',
        '    _result.n = function(x){',
        '      try { return new c("https://rr1.googlevideo.com/videoplayback?n="+x, true).get("n"); }',
        '      catch(e) { return null; }',
        '    };',
        '  })(_foundA.ctor);',
        '  _result._nName = "UrlClass(" + _foundA.path + ")";',
        '  _result._nStrategy = "url-class";',
        '  _result._nCtorPath = _foundA.path;',
        '  // Unified cache object — background.js can store this directly without',
        '  // parsing _nName. Includes strategy tag so the right fast-path is used.',
        '  _result._nCache = { strategy: "url-class", ctorPath: _foundA.path };',
        '}'
    ].join('\n');
}

/**
 * Cache fast-path for URL-class: re-resolve the constructor by path and
 * wrap it, without re-walking. Falls through to phase A scan if resolution
 * fails (e.g. the player was rebuilt with different names).
 */
function _buildUrlClassFastPath(ctorPath) {
    return [
        '// ===== URL-class fast-path =====',
        'try {',
        '  var _parts = ' + JSON.stringify(ctorPath) + '.split(".");',
        '  var _obj = null;',
        '  if (_parts[0] === "_yt_player") { _obj = _yt_player; _parts.shift(); }',
        '  else { _obj = globalThis; }',
        '  for (var _i=0; _i<_parts.length && _obj; _i++) {',
        '    _obj = _obj[_parts[_i]];',
        '  }',
        '  if (typeof _obj === "function") {',
        '    // Validate it still works',
        '    var _t = new _obj("https://rr1.googlevideo.com/videoplayback?n=wapK3U_wOyBVm5K", true);',
        '    var _n1 = _t.get("n");',
        '    if (typeof _n1 === "string" && _n1 !== "wapK3U_wOyBVm5K" && _n1.indexOf("wapK3U_wOyBVm5K") === -1 && _n1.indexOf("undefined") !== 0) {',
        '      (function(c){',
        '        _result.n = function(x){',
        '          try { return new c("https://rr1.googlevideo.com/videoplayback?n="+x, true).get("n"); }',
        '          catch(e) { return null; }',
        '        };',
        '      })(_obj);',
        '      _result._nName = "UrlClass(" + ' + JSON.stringify(ctorPath) + ' + ")";',
        '      _result._nStrategy = "url-class";',
        '      _result._nCtorPath = ' + JSON.stringify(ctorPath) + ';',
        '      _result._nCache = { strategy: "url-class", ctorPath: ' + JSON.stringify(ctorPath) + ' };',
        '    }',
        '  }',
        '} catch(e) {}',
        // If fast-path failed, fall through to full phase A discovery
        'if (!_result.n) {',
        _buildUrlClassScan(),
        '}'
    ].join('\n');
}

/**
 * Phase B: candidate probe for XOR-dispatched functions.
 *
 * Two sub-strategies, tried in order:
 *
 *   B.1 Call-site literal extraction (primary):
 *       For each candidate, test each literal (V, Y) pair extracted from
 *       the source. This is fast (tens of calls total) and deterministic —
 *       if YouTube ships `kp(1, 7337, s)` in the player source, we find it
 *       immediately without guessing Y.
 *
 *   B.2 Bit-reversal base scan (fallback):
 *       v10/v11 logic — iterate r ∈ 0..255, for each candidate try
 *       p = base ^ r for every extracted NNNN base. Still useful for older
 *       players where call sites weren't literal or the candidate was
 *       inlined.
 *
 * Both sub-strategies use the same validators:
 *   - typeof === "string"
 *   - deterministic across repeated calls
 *   - input is NOT a substring of output (kills the "undefined"+input false
 *     positive from player 1bb6ee63's TP)
 *   - output doesn't start with "undefined"/"null"/"NaN"/"[object"
 *   - n-param: new chars appear; cipher: same charset (permutation)
 */
function _buildXorScan(mode, varNames, tableVar, splitIdx, callSites) {
    var resultKey = mode === 'sig' ? 'sig' : 'n';
    var nameKey = mode === 'sig' ? '_sigName' : '_nName';
    var isNParam = mode !== 'sig';
    var namesJSON = JSON.stringify(varNames || []);
    var callSitesJSON = JSON.stringify(callSites || {});

    // Test inputs: must differ in every position or near-every position,
    // otherwise a cipher that happens to scramble away the overlapping middle
    // produces identical outputs for both and fails the `_v3 !== _v1` check.
    // v11 used strings that shared the middle — that's why kp(10,7330) on the
    // new player was silently rejected.
    var t1 = isNParam
        ? 'ABCDEFGHabcdefg1'
        : 'AOq0QJ8wRAIgTXjVbFq4RE0_C3YYzJ-j-rVqGi25Oj_bm9c3x2CiqKICIFfBKjR5Q3iBvFHIqZLqhY1jQ9o5a_FV8WNi9Z2v3BdMAhIARbCqF0FHn4';
    var t2 = isNParam
        ? 'ZYXWVUTS98765432'
        : 'Zz9aB8cD7eF6gH5iJ4kL3mN2oP1qR0sT-_ZY9XW8VU7TS6RQ5PO4NM3LK2JI1HG0FEDCBA-_abcdefghijklmnopqrstuvwxyz012345AABbCc9XZw';
    var minBases = isNParam ? 1 : 5;
    var minSrcLen = isNParam ? 100 : 500;

    // Content validator per mode. Shared by B.1 and B.2.
    var validate;
    if (isNParam) {
        validate = '&&_newCh(_t1,_v1)&&_v1.indexOf(_t1)===-1&&!_isJunkB(_v1)&&_v3.indexOf(_t2)===-1&&!_isJunkB(_v3)';
    } else {
        validate = '&&_v1.length>=20&&_v1.length<=_t1.length&&_v1.length>=_t1.length-10&&!_newCh(_t1,_v1)&&!_isJunkB(_v1)';
    }

    return [
        '// ===== Phase B: XOR-dispatch candidate probe =====',
        'var _vn=' + namesJSON + ';',
        'var _cs=' + callSitesJSON + ';',
        'var _tv=' + JSON.stringify(tableVar) + ';',
        'var _si=' + splitIdx + ';',
        'var _t1="' + t1 + '",_t2="' + t2 + '";',
        'function _newCh(a,b){var s=new Set(a.split(""));for(var i=0;i<b.length;i++)if(!s.has(b[i]))return true;return false;}',
        'var _JUNKB=["undefined","null","NaN","[object"];',
        'function _isJunkB(v){ for (var j=0;j<_JUNKB.length;j++) if (v.indexOf(_JUNKB[j])===0) return true; return false; }',
        'function _br8(n){n=((n&240)>>4)|((n&15)<<4);n=((n&204)>>2)|((n&51)<<2);return((n&170)>>1)|((n&85)<<1);}',
        'function _resolveFn(name){',
        '  try{var f=eval(name);if(typeof f==="function")return f;}catch(e){}',
        '  try{if(typeof _yt_player!=="undefined"&&_yt_player&&typeof _yt_player[name]==="function")return _yt_player[name];}catch(e){}',
        '  try{if(typeof globalThis[name]==="function")return globalThis[name];}catch(e){}',
        '  return null;',
        '}',
        // Output-shape validator: centralizes the check used by both sub-strategies.
        'function _checkOutput(f, r, p) {',
        '  try {',
        '    var _v1 = f(r, p, _t1);',
        '    if (typeof _v1 !== "string" || _v1 === _t1 || _v1.length === 0 || _v1.length > 300) return false;',
        '    var _v2 = f(r, p, _t1);',
        '    if (_v1 !== _v2) return false;',
        '    var _v3 = f(r, p, _t2);',
        '    if (typeof _v3 !== "string" || _v3 === _v1) return false;',
        '    return true' + validate + ';',
        '  } catch(e) { return false; }',
        '}',
        '',
        '// ----- B.1: Call-site literal extraction -----',
        'var _csKeys = Object.keys(_cs);',
        'for (var _csi = 0; _csi < _csKeys.length && !_result.' + resultKey + '; _csi++) {',
        '  var _nm = _csKeys[_csi];',
        '  var _f = _resolveFn(_nm);',
        '  if (!_f) continue;',
        '  var _pairs = _cs[_nm];',
        '  for (var _pi = 0; _pi < _pairs.length; _pi++) {',
        '    var _V = _pairs[_pi][0], _Y = _pairs[_pi][1];',
        '    if (_checkOutput(_f, _V, _Y)) {',
        '      (function(f, r, p) { _result.' + resultKey + ' = function(x) { return f(r, p, x); }; })(_f, _V, _Y);',
        '      _result.' + nameKey + ' = _nm + "(" + _V + "," + _Y + ",x) [call-site]";',
        (isNParam ? '      _result._nStrategy = "xor-callsite";' : '      _result._sigStrategy = "xor-callsite";'),
        '      _result._' + (isNParam ? 'n' : 'sig') + 'FuncName = _nm;',
        '      _result._' + (isNParam ? 'n' : 'sig') + 'R = _V;',
        '      _result._' + (isNParam ? 'n' : 'sig') + 'P = _Y;',
        '      _result._' + (isNParam ? 'n' : 'sig') + 'Cache = { strategy: "xor", funcName: _nm, r: _V, p: _Y };',
        '      break;',
        '    }',
        '  }',
        '}',
        '',
        '// ----- B.2: Bit-reversal base scan (fallback) -----',
        'if (!_result.' + resultKey + ') {',
        '  function _getBases(src){',
        '    var bases=new Set(),m;',
        '    var rxXor=new RegExp(_tv+"\\\\[\\\\w+\\\\^(\\\\d+)\\\\]","g");',
        '    var rxXorRev=new RegExp(_tv+"\\\\[(\\\\d+)\\\\^\\\\w+\\\\]","g");',
        '    var rxSub=new RegExp(_tv+"\\\\[\\\\w+\\\\-(\\\\d+)\\\\]","g");',
        '    var rxAdd=new RegExp(_tv+"\\\\[\\\\w+\\\\+(\\\\d+)\\\\]","g");',
        '    while((m=rxXor.exec(src))!==null)bases.add(parseInt(m[1])^_si);',
        '    while((m=rxXorRev.exec(src))!==null)bases.add(parseInt(m[1])^_si);',
        '    while((m=rxSub.exec(src))!==null)bases.add(parseInt(m[1]));',
        '    while((m=rxAdd.exec(src))!==null)bases.add(parseInt(m[1]));',
        '    // Also include raw constants (no XOR with _si) for call-site-style patterns.',
        '    var rxRaw=/\\^(\\d+)/g;',
        '    while((m=rxRaw.exec(src))!==null){var n=parseInt(m[1]);if(n<20000)bases.add(n);}',
        '    return bases;',
        '  }',
        '  function _getCandidateNames(){',
        '    var names=_vn.slice();',
        '    var seen=new Set(names);',
        '    try{',
        '      if(typeof _yt_player!=="undefined"&&_yt_player){',
        '        for(var k in _yt_player){if(!seen.has(k)){names.push(k);seen.add(k);}}',
        '      }',
        '    }catch(e){}',
        '    try{',
        '      for(var k2 in globalThis){if(!seen.has(k2)){names.push(k2);seen.add(k2);}}',
        '    }catch(e){}',
        '    return names;',
        '  }',
        '',
        '  var _cands=[];',
        '  var _allNames=_getCandidateNames();',
        '  var _seenFns=new Set();',
        '  for(var _i=0;_i<_allNames.length;_i++){',
        '    var _ff=_resolveFn(_allNames[_i]);',
        '    if(!_ff||_ff.length<3)continue;',
        '    if(_seenFns.has(_ff))continue;',
        '    _seenFns.add(_ff);',
        '    var _s;try{_s=_ff.toString();}catch(e){continue;}',
        '    if(_s.length<' + minSrcLen + ')continue;',
        '    var _bs=_getBases(_s);',
        '    if(_bs.size<' + minBases + ')continue;',
        '    _cands.push({f:_ff,nm:_allNames[_i],bs:Array.from(_bs)});',
        '  }',
        '',
        '  for(var _ri=0;_ri<256&&!_result.' + resultKey + ';_ri++){',
        '    var _r=_br8(_ri);',
        '    for(var _ci=0;_ci<_cands.length&&!_result.' + resultKey + ';_ci++){',
        '      var _c=_cands[_ci];',
        '      for(var _bi=0;_bi<_c.bs.length;_bi++){',
        '        var _p=_c.bs[_bi]^_r;',
        '        if (_checkOutput(_c.f, _r, _p)) {',
        '          (function(f,r,p){_result.' + resultKey + '=function(x){return f(r,p,x);};})(_c.f,_r,_p);',
        '          _result.' + nameKey + '=_c.nm+"("+_r+","+_p+",x) [bit-scan]";',
        (isNParam ? '          _result._nStrategy="xor-scan";' : '          _result._sigStrategy="xor-scan";'),
        '          _result._' + (isNParam ? 'n' : 'sig') + 'FuncName=_c.nm;',
        '          _result._' + (isNParam ? 'n' : 'sig') + 'R=_r;',
        '          _result._' + (isNParam ? 'n' : 'sig') + 'P=_p;',
        '          _result._' + (isNParam ? 'n' : 'sig') + 'Cache = { strategy: "xor", funcName: _c.nm, r: _r, p: _p };',
        '          break;',
        '        }',
        '      }',
        '    }',
        '  }',
        '}'
    ].filter(Boolean).join('\n');
}

/**
 * Cache fast-path for XOR dispatcher.
 */
function _buildXorFastPath(mode, cache) {
    var isNParam = mode !== 'sig';
    var resultKey = isNParam ? 'n' : 'sig';
    var nameKey = isNParam ? '_nName' : '_sigName';
    var testVal = isNParam
        ? '"ABCDEFGHabcdefg1"'
        : '"AOq0QJ8wRAIgTXjVbFq4RE0_C3YYzJ-j-rVqGi25Oj_bm9c3x2CiqKICIFfBKjR5Q3iBvFHIqZLqhY1jQ9o5a_FV8WNi9Z2v3BdMAhIARbCqF0FHn4"';
    var testVal2 = isNParam
        ? '"ZYXWVUTS98765432"'
        : '"Zz9aB8cD7eF6gH5iJ4kL3mN2oP1qR0sT-_ZY9XW8VU7TS6RQ5PO4NM3LK2JI1HG0FEDCBA-_abcdefghijklmnopqrstuvwxyz012345AABbCc9XZw"';
    return [
        '// ===== XOR fast-path =====',
        'try{',
        '  var _cf=(function(n){try{return eval(n);}catch(e){return null;}})("' + cache.funcName + '");',
        '  if(!_cf){_cf=(typeof _yt_player!=="undefined"&&_yt_player&&_yt_player["' + cache.funcName + '"])||null;}',
        '  if(typeof _cf==="function"){',
        '    var _cv1=_cf(' + cache.r + ',' + cache.p + ',' + testVal + ');',
        '    var _cv2=_cf(' + cache.r + ',' + cache.p + ',' + testVal + ');',
        '    var _cv3=_cf(' + cache.r + ',' + cache.p + ',' + testVal2 + ');',
        // Substring + junk rejection inside the fast-path too, so a stale
        // cache doesn't silently promote a bad function after a player rotation.
        (isNParam
            ? '    var _ok = typeof _cv1==="string"&&_cv1===_cv2&&_cv1!==' + testVal + '&&_cv3!==_cv1&&_cv1.indexOf(' + testVal + '.slice(1,-1))===-1&&_cv1.indexOf("undefined")!==0&&_cv1.indexOf("null")!==0;'
            : '    var _ok = typeof _cv1==="string"&&_cv1===_cv2&&_cv1!==' + testVal + '&&_cv3!==_cv1&&_cv1.indexOf("undefined")!==0;'),
        '    if(_ok){',
        '      _result.' + resultKey + '=function(x){return _cf(' + cache.r + ',' + cache.p + ',x);};',
        '      _result.' + nameKey + '="' + cache.funcName + '(' + cache.r + ',' + cache.p + ',x)";',
        (isNParam
            ? '      _result._nStrategy="xor"; _result._nFuncName="' + cache.funcName + '"; _result._nR=' + cache.r + '; _result._nP=' + cache.p + '; _result._nCache = { strategy: "xor", funcName: "' + cache.funcName + '", r: ' + cache.r + ', p: ' + cache.p + ' };'
            : '      _result._sigStrategy="xor"; _result._sigFuncName="' + cache.funcName + '"; _result._sigR=' + cache.r + '; _result._sigP=' + cache.p + '; _result._sigCache = { strategy: "xor", funcName: "' + cache.funcName + '", r: ' + cache.r + ', p: ' + cache.p + ' };'),
        '    }',
        '  }',
        '}catch(e){}'
    ].filter(Boolean).join('\n');
}

/**
 * Assemble executable code: SETUP + player + probe.
 */
function assembleCode(data, probeBody) {
    var iifeCloseIdx = findIifeClose(data);
    if (iifeCloseIdx === -1) {
        return SETUP_CODE + '\n' + data + '\n;(function(){' + probeBody + '})();';
    }
    var strictIdx = findUseStrict(data);
    var strictLen = useStrictLen(data, strictIdx);
    var afterStrict = strictIdx !== -1 ? strictIdx + strictLen : data.indexOf('{') + 1;
    return {
        direct: SETUP_CODE + '\n' +
            data.substring(0, iifeCloseIdx) + '\n' +
            probeBody + '\n' +
            data.substring(iifeCloseIdx),
        wrapped: SETUP_CODE + '\n' +
            data.substring(0, afterStrict) + '\ntry{\n' +
            data.substring(afterStrict, iifeCloseIdx) + '\n}catch(_e){}\n' +
            probeBody + '\n' +
            data.substring(iifeCloseIdx)
    };
}

/**
 * Main entry point for n-parameter solving.
 * @param {string} data - Full player.js source.
 * @param {object|null} solvedCache - Cache from previous solve:
 *     { strategy: "url-class", ctorPath: "..." } or
 *     { strategy: "xor", funcName: "...", r: N, p: N }
 * @returns {string} Code ready for Function("_result", code)(resultObj)
 */
function preprocessPlayer(data, solvedCache) {
    var table = findStringTable(data);
    if (!table) {
        var usIdx = findUseStrict(data);
        if (usIdx > 0 && usIdx < 10000) table = findStringTable(data.substring(usIdx));
    }
    var varNames = findVarChain(data) || [];
    // Extract literal call sites for every candidate name. Cheap (a single
    // regex per name), covers the typical `kp(1, 7337, s)` invocation pattern.
    var callSites = findCallSites(data, varNames);
    // URL-class path doesn't need the string table at all, so we proceed even
    // if the fallback is unusable.
    var tableVar = table ? table.tableVar : '';
    var splitIdx = table ? table.splitIdx : 0;

    var probeBody = buildRuntimeProbe('n', varNames, tableVar, splitIdx, callSites, solvedCache);
    var code = assembleCode(data, probeBody);

    if (typeof code === 'string') return code;
    var usIdx = findUseStrict(data);
    return (usIdx > 1000 && usIdx < 10000) ? code.direct : code.wrapped;
}

/**
 * Cipher entry point — unchanged approach (XOR dispatcher scan), but with
 * the same substring/junk validators so a multi-dispatch helper that
 * happens to have the right shape can't get through.
 */
function preprocessCipher(data, cipherCache) {
    var table = findStringTable(data);
    if (!table) {
        var usIdx = findUseStrict(data);
        if (usIdx > 0 && usIdx < 10000) table = findStringTable(data.substring(usIdx));
    }
    var varNames = findVarChain(data) || [];
    var callSites = findCallSites(data, varNames);
    if (!table) return SETUP_CODE + '\n' + data + '\n/* solver: no string table */';

    var probeBody = buildRuntimeProbe('sig', varNames, table.tableVar, table.splitIdx, callSites, cipherCache);
    var code = assembleCode(data, probeBody);
    if (typeof code === 'string') return code;

    var usIdx = findUseStrict(data);
    return (usIdx > 1000 && usIdx < 10000) ? code.direct : code.wrapped;
}
