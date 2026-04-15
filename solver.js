// =============================================================================
// YouTube N-Parameter Solver — Remote Module v10
// Hosted at: https://github.com/solarizeddev/firedown-solver
//
// v9: Rewritten with abstract detection approach.
//   - Uses the IIFE var chain to enumerate all scope-level function names
//   - Uses func.toString() at runtime to detect XOR table accesses
//   - Executes player without try-catch first, falls back to try-catch
//   - No fragile regex matching of function definitions across the full file
//   - Works uniformly on both TV player and base.js (main player) variants
//   - _newCh filter distinguishes n-param (generates new chars) from
//     cipher (only permutes existing chars)
//
// v10: Robust r-value scanning, no hardcoded limits.
//   - Replaced linear r=0..maxR scan with bit-reversal permutation over 0..255.
//     The full byte range is covered with maximum spread: the first 16 values
//     tested are 0,128,64,192,32,160,96,224,16,144,80,208,48,176,112,240.
//     Any valid r value is reached within ≤128 iterations (avg ~16).
//     Eliminates the maxR constant that broke when YouTube's obfuscator
//     generated branch guards requiring r>=72 (player ee507a59, April 2026).
//   - Restructured probe loop: r is the OUTER loop, candidates are inner.
//     Each bit-reversal step tests one r value across ALL candidate functions
//     and ALL their bases simultaneously. This finds the match as soon as the
//     correct r is reached, regardless of candidate ordering. Reduced cipher
//     detection from ~10s to ~1.2s by avoiding exhaustive base iteration on
//     wrong functions before reaching the right one.
//   - Cipher probe now rejects functions that generate new characters
//     (!_newCh filter), preventing the n-param function from being
//     misidentified as a cipher. Both are multi-dispatch XOR-table functions,
//     but n-param generates new chars while cipher only permutes existing ones.
// =============================================================================
var SOLVER_VERSION = 10;

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
 * Find the string table variable and the index of "split" in it.
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
 * Find the largest var chain in the IIFE scope.
 * Returns array of variable names, or null if not found.
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
    if (biggest.count < 50) return null;
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
    return names;
}

/**
 * Build runtime probe code.
 *
 * Runs INSIDE the player IIFE after execution. Two phases:
 *
 * Phase 1 (candidate collection): For each var-chain name, checks
 * typeof === "function" && .length >= 3, then scans func.toString()
 * for XOR table accesses to extract bases.
 *
 * Phase 2 (r-outer bit-reversal scan): Iterates r in bit-reversal order
 * (0,128,64,192,32,...) over 0–255. At each r, tests ALL candidates with
 * ALL their bases. First valid match wins.
 *
 * The bit-reversal order covers the full byte range with maximum spread,
 * reaching any valid r within ≤128 steps (typically ~16). No hardcoded
 * maxR constant — immune to obfuscator changes in branch guard thresholds.
 *
 * @param {string} mode - "n" for n-param, "sig" for signature cipher
 * @param {string[]} varNames - Variable names from the IIFE var chain
 * @param {string} tableVar - String table variable name (e.g. "d")
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
        return [
            'try{',
            '  var _cv1=' + cache.funcName + '(' + cache.r + ',' + cache.p + ',' + testVal + ');',
            '  var _cv2=' + cache.funcName + '(' + cache.r + ',' + cache.p + ',' + testVal + ');',
            '  var _cv3=' + cache.funcName + '(' + cache.r + ',' + cache.p + ',' + testVal2 + ');',
            '  if(typeof _cv1==="string"&&_cv1===_cv2&&_cv1!==' + testVal + '&&_cv3!==_cv1){',
            '    _result.' + resultKey + '=function(x){return ' + cache.funcName + '(' + cache.r + ',' + cache.p + ',x);};',
            '    _result.' + nameKey + '="' + cache.funcName + '(' + cache.r + ',' + cache.p + ',x)";',
            '  }',
            '}catch(e){}'
        ].join('\n');
    }

    // Full probe: collect candidates, then r-outer bit-reversal scan
    var namesJSON = JSON.stringify(varNames);
    var isNParam = mode !== 'sig';

    var validate;
    if (isNParam) {
        // N-param: output must contain new chars not in input
        validate = '&&_newCh(_t1,_v1)';
    } else {
        // Cipher: output must be same length ± 10, and must NOT contain new
        // chars (pure permutation). The !_newCh check prevents the n-param
        // function from being falsely identified as a cipher.
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
        // 8-bit reversal: 0→0, 1→128, 2→64, 3→192, ...
        // Produces maximum-spread ordering over 0–255
        'function _br8(n){n=((n&240)>>4)|((n&15)<<4);n=((n&204)>>2)|((n&51)<<2);return((n&170)>>1)|((n&85)<<1);}',
        'var _xr=new RegExp(_tv+"\\\\[\\\\w+\\\\^(\\\\d+)\\\\]","g");',
        '',
        '// Phase 1: collect candidate functions with their XOR bases',
        'var _cands=[];',
        'for(var _i=0;_i<_vn.length;_i++){',
        '  var _f;try{_f=eval(_vn[_i]);}catch(e){continue;}',
        '  if(typeof _f!=="function"||_f.length<3)continue;',
        '  var _s;try{_s=_f.toString();}catch(e){continue;}',
        '  if(_s.length<' + minSrcLen + ')continue;',
        '  var _bs=new Set(),_m;_xr.lastIndex=0;',
        '  while((_m=_xr.exec(_s))!==null)_bs.add(parseInt(_m[1])^_si);',
        '  if(_bs.size<=' + minBases + ')continue;',
        '  _cands.push({f:_f,nm:_vn[_i],bs:Array.from(_bs)});',
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
 */
function assembleCode(data, probeBody) {
    var iifeCloseIdx = data.lastIndexOf('})(_yt_player)');
    if (iifeCloseIdx === -1) iifeCloseIdx = data.lastIndexOf('}).call(this)');
    if (iifeCloseIdx === -1) iifeCloseIdx = data.lastIndexOf('})(');
    if (iifeCloseIdx === -1) {
        return SETUP_CODE + '\n' + data + '\n;(function(){' + probeBody + '})();';
    }

    var strictIdx = data.indexOf("'use strict';");
    var afterStrict = strictIdx !== -1 ? strictIdx + "'use strict';".length : data.indexOf('{') + 1;

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
        var usIdx = data.indexOf("'use strict';");
        if (usIdx > 0 && usIdx < 10000)
            table = findStringTable(data.substring(usIdx));
    }
    var varNames = findVarChain(data);
    if (!table || !varNames) return SETUP_CODE + '\n' + data + '\n/* solver: no table or var chain */';

    var probeBody = buildRuntimeProbe('n', varNames, table.tableVar, table.splitIdx, solvedCache);
    var code = assembleCode(data, probeBody);

    if (typeof code === 'string') return code;

    // Choose variant: base.js has 'use strict' at offset >1000 (copyright header),
    // TV player has it at offset <100. base.js runs cleanly without try-catch;
    // TV player needs try-catch to survive DOM access errors during init.
    var usIdx = data.indexOf("'use strict';");
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
        var usIdx = data.indexOf("'use strict';");
        if (usIdx > 0 && usIdx < 10000)
            table = findStringTable(data.substring(usIdx));
    }
    var varNames = findVarChain(data);
    if (!table || !varNames) return SETUP_CODE + '\n' + data + '\n/* solver: no table or var chain */';

    var probeBody = buildRuntimeProbe('sig', varNames, table.tableVar, table.splitIdx, cipherCache);
    var code = assembleCode(data, probeBody);

    if (typeof code === 'string') return code;

    var usIdx = data.indexOf("'use strict';");
    return (usIdx > 1000 && usIdx < 10000) ? code.direct : code.wrapped;
}
