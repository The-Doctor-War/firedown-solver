// =============================================================================
// YouTube N-Parameter Solver — Remote Module v4
// Hosted at: https://github.com/solarizeddev/firedown-solver
// The background.js shell fetches, caches, and executes this module.
// =============================================================================
var SOLVER_VERSION = 5;

var SETUP_CODE = [
    'if(typeof globalThis.XMLHttpRequest==="undefined"){globalThis.XMLHttpRequest={prototype:{}};}',
    'var window=Object.create(null);',
    'if(typeof URL==="undefined"){window.location={hash:"",host:"www.youtube.com",hostname:"www.youtube.com",',
    'href:"https://www.youtube.com/watch?v=yt-dlp-wins",origin:"https://www.youtube.com",password:"",',
    'pathname:"/watch",port:"",protocol:"https:",search:"?v=yt-dlp-wins",username:""};}',
    'else{window.location=new URL("https://www.youtube.com/watch?v=yt-dlp-wins");}',
    'if(typeof globalThis.document==="undefined"){globalThis.document=Object.create(null);}',
    'if(typeof globalThis.navigator==="undefined"){globalThis.navigator=Object.create(null);}',
    'if(typeof globalThis.self==="undefined"){globalThis.self=globalThis;}'
].join('\n');

/**
 * Find the string table variable and the index of "split" in it.
 * Handles: "...".split(";"), '...'.split("}"), ["...","..."]
 */
function findStringTable(data) {
    var chunk = data.substring(0, 2000);
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
    // Fallback: array literal
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
 * Find candidate dispatch functions with XOR table accesses.
 * Returns array of { funcName, bases: number[] }
 */
function findCandidates(data, tableVar, splitIdx) {
    var earlyChunk = data.substring(0, Math.min(data.length, 30000));
    var funcDefs = earlyChunk.matchAll(/(?:^|[^a-zA-Z0-9_$])(?:var\s+)?(\w+)=function\((\w+(?:,\w+){2,})\)\{/g);
    var candidates = [];
    for (var fd of funcDefs) {
        var funcName = fd[1];
        var defPos = data.indexOf(funcName + '=function(');
        if (defPos === -1) continue;
        // Isolate function body via brace matching to avoid picking up
        // XOR accesses from neighboring functions
        var bodyStart = data.indexOf('{', defPos);
        var funcBody = null;
        if (bodyStart !== -1) {
            var depth = 0, pos = bodyStart;
            while (pos < data.length) {
                if (data[pos] === '{') depth++;
                else if (data[pos] === '}') { depth--; if (depth === 0) { funcBody = data.substring(bodyStart, pos + 1); break; } }
                pos++;
            }
        }
        // If brace matching fails (e.g. } in string literals), fall back to a
        // conservative 2000-char window from defPos
        var searchText = funcBody || data.substring(defPos, Math.min(defPos + 2000, data.length));
        var xorRx = new RegExp(tableVar.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\[\\w+\\^(\\d+)\\]', 'g');
        var bases = new Set(), xm;
        while ((xm = xorRx.exec(searchText)) !== null) bases.add(parseInt(xm[1]) ^ splitIdx);
        if (bases.size > 0) candidates.push({ funcName: funcName, bases: Array.from(bases) });
    }
    candidates.sort(function(a, b) { return b.bases.length - a.bases.length; });
    return candidates;
}

/**
 * Build probe code that tests candidates BY NAME (no _df injection needed).
 * Functions survive because try-catch prevents the player from reaching
 * the code that would overwrite them.
 */
function buildProbe(candidates, testEntries) {
    var fnArr = candidates.map(function(c) { return c.funcName; }).join(',');
    var nameArr = candidates.map(function(c) { return '"' + c.funcName + '"'; }).join(',');
    var paramArr = testEntries.map(function(e) { return '[' + e.fi + ',' + e.r + ',' + e.p + ']'; }).join(',');
    return [
        'var _fns=[' + fnArr + '],_names=[' + nameArr + '];',
        'var _params=[' + paramArr + '];',
        'var _tI="ABCDEFGHabcdefg1",_tI2="ZYXWVUTS98765432";',
        'for(var _i=0;_i<_params.length;_i++){',
        '  var _fi=_params[_i][0],_r=_params[_i][1],_p=_params[_i][2];',
        '  try{',
        '    var _res=_fns[_fi](_r,_p,_tI);',
        '    if(typeof _res==="string"&&_res!==_tI&&_res.length>0&&_res.length<200){',
        '      var _res2=_fns[_fi](_r,_p,_tI),_res3=_fns[_fi](_r,_p,_tI2);',
        '      if(_res===_res2&&typeof _res3==="string"&&_res3!==_res){',
        '        (function(fi,r,p){_result.n=function(n){return _fns[fi](r,p,n);};})',
        '        (_fi,_r,_p);',
        '        _result._nName=_names[_fi]+"("+_r+","+_p+",n)";',
        '        break;',
        '      }',
        '    }',
        '  }catch(e){}',
        '}'
    ].join('\n');
}

/**
 * Build probe for a single cached function (fast path).
 */
function buildCachedProbe(funcName, r, p) {
    return [
        'var _tI="ABCDEFGHabcdefg1",_tI2="ZYXWVUTS98765432";',
        'try{',
        '  var _res=' + funcName + '(' + r + ',' + p + ',_tI);',
        '  if(typeof _res==="string"&&_res!==_tI&&_res.length>0&&_res.length<200){',
        '    var _res2=' + funcName + '(' + r + ',' + p + ',_tI);',
        '    var _res3=' + funcName + '(' + r + ',' + p + ',_tI2);',
        '    if(_res===_res2&&typeof _res3==="string"&&_res3!==_res){',
        '      _result.n=function(n){return ' + funcName + '(' + r + ',' + p + ',n);};',
        '      _result._nName="' + funcName + '(' + r + ',' + p + ',n)";',
        '    }',
        '  }',
        '}catch(e){}'
    ].join('\n');
}

/**
 * Main entry point.
 * @param {string} data - Full player.js source
 * @param {object|null} solvedCache - {funcName, r, p} from previous solve
 * @returns {string} - Code ready for Function("_result", code)(resultObj)
 */
function preprocessPlayer(data, solvedCache) {
    // --- Find candidates or use cache ---
    var probeBody;
    if (solvedCache && solvedCache.funcName) {
        probeBody = buildCachedProbe(solvedCache.funcName, solvedCache.r, solvedCache.p);
    } else {
        var table = findStringTable(data);
        if (table) {
            var candidates = findCandidates(data, table.tableVar, table.splitIdx);
            if (candidates.length > 0) {
                var testEntries = [], seen = {};
                for (var fi = 0; fi < candidates.length; fi++) {
                    for (var bi = 0; bi < candidates[fi].bases.length; bi++) {
                        var base = candidates[fi].bases[bi];
                        for (var r = 0; r <= 30; r++) {
                            var p = base ^ r;
                            var key = fi + ':' + r + ',' + p;
                            if (!seen[key]) { seen[key] = true; testEntries.push({ fi: fi, r: r, p: p }); }
                        }
                    }
                }
                probeBody = buildProbe(candidates, testEntries);
            }
        }
    }
    if (!probeBody) probeBody = '/* no candidates found */';

    // --- Wrap player in try-catch, append probe ---
    // No _df injection, no brace matching, no comma insertion.
    // The probe references functions BY NAME. Functions survive because
    // the try-catch prevents the player from reaching overwrite code.
    var iifeCloseIdx = data.lastIndexOf('}).call(this)');
    if (iifeCloseIdx === -1) iifeCloseIdx = data.lastIndexOf('})(_yt_player)');
    if (iifeCloseIdx === -1) iifeCloseIdx = data.lastIndexOf('})(');

    if (iifeCloseIdx !== -1) {
        var strictIdx = data.indexOf("'use strict';");
        var afterStrict = strictIdx !== -1 ? strictIdx + "'use strict';".length : data.indexOf('{') + 1;
        return SETUP_CODE + '\n' +
            data.substring(0, afterStrict) + '\ntry{\n' +
            data.substring(afterStrict, iifeCloseIdx) + '\n}catch(_e){}\n' +
            probeBody + '\n' +
            data.substring(iifeCloseIdx);
    }

    return SETUP_CODE + '\n' + data + '\n;(function(){' + probeBody + '})();';
}
