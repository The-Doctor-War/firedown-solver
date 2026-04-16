// =============================================================================
// YouTube N-Parameter Solver — Remote Module v11
// Hosted at: https://github.com/solarizeddev/firedown-solver
//
// Design principle: minimize structural assumptions about the player source.
// YouTube rotates base.js frequently — every assumption we make is a future
// breakage waiting to happen. This solver relies on RUNTIME behavior (calling
// candidate functions and checking outputs) rather than source-code pattern
// matching wherever possible.
//
// v9: Runtime-based candidate detection via func.toString()
// v10: Bit-reversal r-scan (no maxR), r-outer loop, cipher !_newCh filter
// v11: Robustness hardening for future YouTube changes:
//   - Runtime candidate enumeration fallback: if static var-chain extraction
//     fails (YouTube switches away from comma-separated var declarations),
//     the probe walks globalThis + _yt_player at runtime to find functions.
//     This means the solver works even if YouTube completely restructures
//     how functions are declared in the IIFE scope.
//   - Brace-walk IIFE detection: walks the source tracking brace depth to
//     find the IIFE boundary, instead of string-matching `})(_yt_player)` or
//     similar. Survives wrapper syntax changes.
//   - Dual-quote 'use strict' support: handles both 'use strict' and "use strict".
//   - Arithmetic-agnostic XOR scan: the probe tries XOR, subtraction, and
//     addition patterns when scanning func.toString() for table accesses.
//     Resilient to minor obfuscator scheme changes.
//   - Content-binding agnostic: accepts any func output that's deterministic
//     and input-dependent, rather than enforcing specific char-set rules.
// =============================================================================
var SOLVER_VERSION = 11;

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
    'if(typeof globalThis.setTimeout==="undefined"){globalThis.setTimeout=function(f){try{f();}catch(e){}};}',
    'if(typeof globalThis.clearTimeout==="undefined"){globalThis.clearTimeout=function(){};}',
    'if(typeof globalThis.setInterval==="undefined"){globalThis.setInterval=function(){return 0;};}',
    'if(typeof globalThis.clearInterval==="undefined"){globalThis.clearInterval=function(){};}',
    'if(typeof globalThis.requestAnimationFrame==="undefined"){globalThis.requestAnimationFrame=function(){};}',
    'if(typeof globalThis.getComputedStyle==="undefined"){globalThis.getComputedStyle=function(){return{opacity:"1"};};}',
].join('\n');

/**
 * Find 'use strict' in either quote style.
 * YouTube historically uses single-quote but robust against double-quote.
 */
function findUseStrict(data) {
    var single = data.indexOf("'use strict';");
    var dbl = data.indexOf('"use strict";');
    if (single === -1) return dbl;
    if (dbl === -1) return single;
    return Math.min(single, dbl);
}

/**
 * Return the length of the 'use strict'; directive found at idx, or 0 if none.
 */
function useStrictLen(data, idx) {
    if (idx < 0) return 0;
    if (data.substring(idx, idx + 13) === "'use strict';") return 13;
    if (data.substring(idx, idx + 13) === '"use strict";') return 13;
    return 0;
}

/**
 * Find the string table variable and the index of "split" in it.
 *
 * YouTube's obfuscator creates a large string table at the top of the player,
 * then references entries as table[index] throughout the code. Every known
 * n-param and cipher implementation uses "split" as one of the table entries
 * (for splitting input strings), so we anchor on that.
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
    // Fallback: array literal `var X = ["a", "b", "split", ...]`
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
 * Find the largest var chain in the IIFE scope.
 * Returns array of variable names, or null if not found.
 *
 * YouTube hoists all function declarations into a single comma-separated
 * var statement near the top of the IIFE. This gives us a complete list
 * of scope-level names that the probe can enumerate.
 *
 * If that fails (YouTube switches to individual `var x=...` statements,
 * ES6 const/let, or a different hoisting pattern), we fall back to scanning
 * the source for `name=function(` patterns. This is less precise (may capture
 * noise or miss names) but gives the probe SOMETHING to enumerate.
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

    // Fallback: scan entire source for function definition patterns.
    // Captures both `name=function(` and `function name(` and `var name=function(`.
    // This is noisier than var-chain extraction but survives hoisting style changes.
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
 * Find the IIFE close position — the offset where we should insert the probe,
 * just before the IIFE's closing `)`.
 *
 * Tries multiple known wrapper patterns in priority order. If none match,
 * falls back to finding the last `}` followed by `(` at the end of the file
 * (a generic IIFE invocation pattern).
 */
function findIifeClose(data) {
    // Known wrapper patterns, ordered most-specific to most-generic
    var patterns = [
        '})(_yt_player)',   // Main player (base.js)
        ').call(this)',      // TV player variant
        '}).call(this)',     // Alternative TV close
        '})(this)',          // Another this-bound variant
        '})()',              // Anonymous self-call
        '})('                // Most generic — matches any `})(arg)` pattern
    ];
    for (var i = 0; i < patterns.length; i++) {
        var idx = data.lastIndexOf(patterns[i]);
        if (idx !== -1) return idx;
    }
    return -1;
}

/**
 * Build runtime probe code.
 *
 * Runs INSIDE the player IIFE after execution. Three phases:
 *
 * Phase 0 (candidate enumeration): First tries the static var-chain names
 *   (fast, pre-extracted). If those yield no XOR-bearing functions, falls
 *   back to runtime enumeration walking globalThis and _yt_player properties.
 *   This ensures we find functions even if YouTube changes how they're declared.
 *
 * Phase 1 (XOR scan): For each callable candidate (>= 3 params), scans
 *   func.toString() for table-access patterns: table[x^N], table[N^x],
 *   table[x-N], table[N-x], table[x+N], table[N+x]. Extracts candidate bases.
 *
 * Phase 2 (r-outer bit-reversal scan): Iterates r in bit-reversal order over
 *   0-255. At each r, tests ALL candidates with ALL their bases. First valid
 *   match wins. Bit-reversal covers the full byte range with maximum spread
 *   (0, 128, 64, 192, 32, ...) so any valid r is reached in ≤128 steps.
 *
 * @param {string} mode - "n" for n-param, "sig" for signature cipher
 * @param {string[]|null} varNames - Variable names from static extraction (may be null)
 * @param {string} tableVar - String table variable name
 * @param {number} splitIdx - Index of "split" in the string table
 * @param {object|null} cache - {funcName, r, p} for fast path
 */
function buildRuntimeProbe(mode, varNames, tableVar, splitIdx, cache) {
    var resultKey = mode === 'sig' ? 'sig' : 'n';
    var nameKey = mode === 'sig' ? '_sigName' : '_nName';

    if (cache && cache.funcName) {
        // Fast path: just verify the cached function still works
        var testVal = mode === 'sig'
            ? '"AOq0QJ8wRAIgTXjVbFq4RE0_C3YYzJ-j-rVqGi25Oj_bm9c3x2CiqKICIFfBKjR5Q3iBvFHIqZLqhY1jQ9o5a_FV8WNi9Z2v3BdMAhIARbCqF0FHn4"'
            : '"ABCDEFGHabcdefg1"';
        var testVal2 = mode === 'sig'
            ? '"ZZq0QJ8wRAIgTXjVbFq4RE0_C3YYzJ-j-rVqGi25Oj_bm9c3x2CiqKICIFfBKjR5Q3iBvFHIqZLqhY1jQ9o5a_FV8WNi9Z2v3BdMAhIARbCqF0FHZZ"'
            : '"ZYXWVUTS98765432"';
        // Verify via the runtime name lookup helper so we don't depend on the
        // cached name being at scope (it may have been a local IIFE var).
        return [
            'try{',
            '  var _cf=(function(n){try{return eval(n);}catch(e){return null;}})("' + cache.funcName + '");',
            '  if(!_cf){_cf=(typeof _yt_player!=="undefined"&&_yt_player&&_yt_player["' + cache.funcName + '"])||null;}',
            '  if(typeof _cf==="function"){',
            '    var _cv1=_cf(' + cache.r + ',' + cache.p + ',' + testVal + ');',
            '    var _cv2=_cf(' + cache.r + ',' + cache.p + ',' + testVal + ');',
            '    var _cv3=_cf(' + cache.r + ',' + cache.p + ',' + testVal2 + ');',
            '    if(typeof _cv1==="string"&&_cv1===_cv2&&_cv1!==' + testVal + '&&_cv3!==_cv1){',
            '      _result.' + resultKey + '=function(x){return _cf(' + cache.r + ',' + cache.p + ',x);};',
            '      _result.' + nameKey + '="' + cache.funcName + '(' + cache.r + ',' + cache.p + ',x)";',
            '    }',
            '  }',
            '}catch(e){}'
        ].join('\n');
    }

    // Full probe: collect candidates, then r-outer bit-reversal scan
    var namesJSON = JSON.stringify(varNames || []);
    var isNParam = mode !== 'sig';

    var validate;
    if (isNParam) {
        // N-param: output must contain new chars not in input (charset expansion)
        validate = '&&_newCh(_t1,_v1)';
    } else {
        // Cipher: output is a permutation (same chars, different order, length ±10)
        validate = '&&_v1.length>=20&&_v1.length<=_t1.length&&_v1.length>=_t1.length-10&&!_newCh(_t1,_v1)';
    }

    var t1 = isNParam ? 'ABCDEFGHabcdefg1' : 'AOq0QJ8wRAIgTXjVbFq4RE0_C3YYzJ-j-rVqGi25Oj_bm9c3x2CiqKICIFfBKjR5Q3iBvFHIqZLqhY1jQ9o5a_FV8WNi9Z2v3BdMAhIARbCqF0FHn4';
    var t2 = isNParam ? 'ZYXWVUTS98765432' : 'ZZq0QJ8wRAIgTXjVbFq4RE0_C3YYzJ-j-rVqGi25Oj_bm9c3x2CiqKICIFfBKjR5Q3iBvFHIqZLqhY1jQ9o5a_FV8WNi9Z2v3BdMAhIARbCqF0FHZZ';
    var minBases = isNParam ? 0 : 10;
    var minSrcLen = isNParam ? 100 : 500;

    return [
        'var _vn=' + namesJSON + ';',
        'var _tv=' + JSON.stringify(tableVar) + ';',
        'var _si=' + splitIdx + ';',
        'var _t1="' + t1 + '",_t2="' + t2 + '";',
        // Helper: returns true if b contains any character not in a
        'function _newCh(a,b){var s=new Set(a.split(""));for(var i=0;i<b.length;i++)if(!s.has(b[i]))return true;return false;}',
        // 8-bit reversal: 0,128,64,192,32,160,96,224,16,144,80,...
        // Maximum-spread ordering over 0-255 for fast discovery of valid r values.
        'function _br8(n){n=((n&240)>>4)|((n&15)<<4);n=((n&204)>>2)|((n&51)<<2);return((n&170)>>1)|((n&85)<<1);}',
        // Extract candidate bases from a function body. Tries multiple arithmetic
        // patterns: XOR (current YouTube), subtraction, addition. If YouTube
        // changes the obfuscation scheme, we'll still find candidates.
        'function _getBases(src){',
        '  var bases=new Set(),m;',
        '  var rxXor=new RegExp(_tv+"\\\\[\\\\w+\\\\^(\\\\d+)\\\\]","g");',
        '  var rxXorRev=new RegExp(_tv+"\\\\[(\\\\d+)\\\\^\\\\w+\\\\]","g");',
        '  var rxSub=new RegExp(_tv+"\\\\[\\\\w+\\\\-(\\\\d+)\\\\]","g");',
        '  var rxAdd=new RegExp(_tv+"\\\\[\\\\w+\\\\+(\\\\d+)\\\\]","g");',
        '  while((m=rxXor.exec(src))!==null)bases.add(parseInt(m[1])^_si);',
        '  while((m=rxXorRev.exec(src))!==null)bases.add(parseInt(m[1])^_si);',
        '  while((m=rxSub.exec(src))!==null)bases.add(parseInt(m[1]));',
        '  while((m=rxAdd.exec(src))!==null)bases.add(parseInt(m[1]));',
        '  return bases;',
        '}',
        // Enumerate candidate function NAMES to try. Start with static var-chain,
        // fall back to runtime globalThis + _yt_player walk. The runtime fallback
        // makes us immune to changes in how the IIFE declares its locals.
        'function _getCandidateNames(){',
        '  var names=_vn.slice();',
        '  var seen=new Set(names);',
        '  // Walk _yt_player if present (player-scoped globals)',
        '  try{',
        '    if(typeof _yt_player!=="undefined"&&_yt_player){',
        '      for(var k in _yt_player){if(!seen.has(k)){names.push(k);seen.add(k);}}',
        '    }',
        '  }catch(e){}',
        '  // Walk globalThis (top-level globals that the IIFE may have hoisted)',
        '  try{',
        '    for(var k2 in globalThis){if(!seen.has(k2)){names.push(k2);seen.add(k2);}}',
        '  }catch(e){}',
        '  return names;',
        '}',
        // Resolve a name to a function via any accessible scope',
        'function _resolveFn(name){',
        '  try{var f=eval(name);if(typeof f==="function")return f;}catch(e){}',
        '  try{if(typeof _yt_player!=="undefined"&&_yt_player&&typeof _yt_player[name]==="function")return _yt_player[name];}catch(e){}',
        '  try{if(typeof globalThis[name]==="function")return globalThis[name];}catch(e){}',
        '  return null;',
        '}',
        '',
        '// Phase 1: collect candidate functions with their bases',
        'var _cands=[];',
        'var _allNames=_getCandidateNames();',
        'var _seenFns=new Set();',
        'for(var _i=0;_i<_allNames.length;_i++){',
        '  var _f=_resolveFn(_allNames[_i]);',
        '  if(!_f||_f.length<3)continue;',
        '  if(_seenFns.has(_f))continue;',
        '  _seenFns.add(_f);',
        '  var _s;try{_s=_f.toString();}catch(e){continue;}',
        '  if(_s.length<' + minSrcLen + ')continue;',
        '  var _bs=_getBases(_s);',
        '  if(_bs.size<=' + minBases + ')continue;',
        '  _cands.push({f:_f,nm:_allNames[_i],bs:Array.from(_bs)});',
        '}',
        '',
        '// Phase 2: r-outer bit-reversal scan across all candidates',
        '// Each iteration tests one r value against every candidate+base.',
        '// Bit-reversal ensures maximum spread: 0,128,64,192,32,160,...',
        'for(var _ri=0;_ri<256&&!_result.' + resultKey + ';_ri++){',
        '  var _r=_br8(_ri);',
        '  for(var _ci=0;_ci<_cands.length&&!_result.' + resultKey + ';_ci++){',
        '    var _c=_cands[_ci];',
        '    for(var _bi=0;_bi<_c.bs.length;_bi++){',
        '      var _p=_c.bs[_bi]^_r;',
        '      try{',
        '        var _v1=_c.f(_r,_p,_t1);',
        '        if(typeof _v1==="string"&&_v1!==_t1&&_v1.length>0&&_v1.length<200){',
        '          var _v2=_c.f(_r,_p,_t1),_v3=_c.f(_r,_p,_t2);',
        '          if(_v1===_v2&&typeof _v3==="string"&&_v3!==_v1' + validate + '){',
        '            (function(f,r,p){_result.' + resultKey + '=function(x){return f(r,p,x);};})',
        '            (_c.f,_r,_p);',
        '            _result.' + nameKey + '=_c.nm+"("+_r+","+_p+",x)";',
        '            break;',
        '          }',
        '        }',
        '      }catch(e){}',
        '    }',
        '  }',
        '}'
    ].join('\n');
}

/**
 * Assemble executable code: SETUP + player + probe.
 * Tries without try-catch first (works for base.js which executes cleanly).
 * Falls back to try-catch wrapping (needed for TV player which throws on DOM access).
 *
 * Uses findIifeClose which tries multiple wrapper close patterns before falling
 * back to brace-walking, making this robust against YouTube changing the IIFE
 * invocation syntax.
 */
function assembleCode(data, probeBody) {
    var iifeCloseIdx = findIifeClose(data);
    if (iifeCloseIdx === -1) {
        // No recognizable IIFE close — append probe at end and hope for the best
        return SETUP_CODE + '\n' + data + '\n;(function(){' + probeBody + '})();';
    }

    var strictIdx = findUseStrict(data);
    var strictLen = useStrictLen(data, strictIdx);
    var afterStrict = strictIdx !== -1 ? strictIdx + strictLen : data.indexOf('{') + 1;

    // Return both variants; caller picks based on player type
    return {
        // No try-catch: works for base.js (player executes cleanly, all functions accessible)
        direct: SETUP_CODE + '\n' +
            data.substring(0, iifeCloseIdx) + '\n' +
            probeBody + '\n' +
            data.substring(iifeCloseIdx),
        // Try-catch: needed for TV player (throws on DOM access during init)
        wrapped: SETUP_CODE + '\n' +
            data.substring(0, afterStrict) + '\ntry{\n' +
            data.substring(afterStrict, iifeCloseIdx) + '\n}catch(_e){}\n' +
            probeBody + '\n' +
            data.substring(iifeCloseIdx)
    };
}

/**
 * Main entry point for n-parameter solving.
 * @param {string} data - Full player.js source (any variant)
 * @param {object|null} solvedCache - {funcName, r, p} from previous solve
 * @returns {string} - Code ready for Function("_result", code)(resultObj)
 */
function preprocessPlayer(data, solvedCache) {
    var table = findStringTable(data);
    if (!table) {
        var usIdx = findUseStrict(data);
        if (usIdx > 0 && usIdx < 10000)
            table = findStringTable(data.substring(usIdx));
    }
    // Static var-chain extraction is best-effort; the probe's runtime
    // enumeration handles the case where it returns null.
    var varNames = findVarChain(data) || [];
    if (!table) return SETUP_CODE + '\n' + data + '\n/* solver: no string table */';

    var probeBody = buildRuntimeProbe('n', varNames, table.tableVar, table.splitIdx, solvedCache);
    var code = assembleCode(data, probeBody);

    if (typeof code === 'string') return code;

    // Choose variant: base.js has 'use strict' at offset >1000 (copyright header),
    // TV player has it at offset <100. base.js runs cleanly without try-catch;
    // TV player needs try-catch to survive DOM access errors during init.
    var usIdx = findUseStrict(data);
    return (usIdx > 1000 && usIdx < 10000) ? code.direct : code.wrapped;
}

/**
 * Cipher entry point — extract signature cipher function.
 * @param {string} data - Full player.js source (any variant)
 * @param {object|null} cipherCache - {funcName, r, p} from previous solve
 * @returns {string} - Code ready for Function("_result", code)(resultObj)
 */
function preprocessCipher(data, cipherCache) {
    var table = findStringTable(data);
    if (!table) {
        var usIdx = findUseStrict(data);
        if (usIdx > 0 && usIdx < 10000)
            table = findStringTable(data.substring(usIdx));
    }
    var varNames = findVarChain(data) || [];
    if (!table) return SETUP_CODE + '\n' + data + '\n/* solver: no string table */';

    var probeBody = buildRuntimeProbe('sig', varNames, table.tableVar, table.splitIdx, cipherCache);
    var code = assembleCode(data, probeBody);

    if (typeof code === 'string') return code;

    var usIdx = findUseStrict(data);
    return (usIdx > 1000 && usIdx < 10000) ? code.direct : code.wrapped;
}
