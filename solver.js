// =============================================================================
// YouTube N-Parameter Solver — Remote Module
// Hosted at: https://firedown.app/yt/solver.js
// Updated server-side when YouTube changes player obfuscation.
// The background.js shell fetches, caches, and executes this module.
// =============================================================================
// SOLVER_VERSION is checked by the shell to know when to update.
// Bump this number whenever this file is modified.
var SOLVER_VERSION = 2;

// Browser environment shims so player.js can execute in a Function() sandbox
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
 * YouTube TV players always have a string table in the first ~2KB.
 * Formats observed:
 *   var X="...".split(";")     — semicolon delimiter, double quotes
 *   var X='...'.split("}")     — } delimiter, single quotes with escapes
 *   var X=["...","..."]        — array literal
 *
 * Returns { tableVar, splitIdx } or null.
 */
function findStringTable(data) {
    // Strategy: find .split("X") calls in the first 2KB, trace back to var
    var chunk = data.substring(0, 2000);
    var splitCalls = chunk.matchAll(/\.split\((['"])(.)(\1)\)/g);
    for (var sc of splitCalls) {
        var delimiter = sc[2];
        var splitPos = sc.index;
        var before = data.substring(0, splitPos);
        var varMatch = before.match(/var\s+(\w+)=(['"])[^]*$/);
        if (!varMatch) continue;
        var varName = varMatch[1];
        var quote = varMatch[2];
        var contentStart = before.lastIndexOf(varMatch[0]) + varMatch[0].length;
        var content = data.substring(contentStart, splitPos);
        if (content.endsWith(quote)) content = content.slice(0, -1);
        content = content.replace(new RegExp('\\\\' + quote.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g'), quote);
        var entries = content.split(delimiter);
        var si = entries.indexOf('split');
        if (si >= 0 && entries.length > 10) {
            return { tableVar: varName, splitIdx: si };
        }
    }

    // Fallback: array literal  var X=["...", "..."]
    var arrRegex = /var\s+(\w+)=\[/g;
    var am;
    while ((am = arrRegex.exec(chunk)) !== null) {
        var start = am.index + am[0].length - 1;
        var arrChunk = data.substring(start, start + 2000);
        var depth = 0, p = 0;
        while (p < arrChunk.length) {
            if (arrChunk[p] === '[') depth++;
            else if (arrChunk[p] === ']') { depth--; if (depth === 0) break; }
            p++;
        }
        var entries = [];
        var sm;
        var strRx = /"((?:[^"\\]|\\.)*)"/g;
        while ((sm = strRx.exec(arrChunk.substring(0, p))) !== null) entries.push(sm[1]);
        if (entries.length > 10) {
            var si = entries.indexOf('split');
            if (si >= 0) return { tableVar: am[1], splitIdx: si };
        }
    }

    return null;
}

/**
 * Find candidate dispatch functions and their possible XOR bases.
 * Scans the first 30KB for functions with 3+ params whose bodies
 * contain TABLE[VAR^NUM] accesses.
 *
 * Returns array of { funcName, bases: number[] }
 */
function findCandidates(data, tableVar, splitIdx) {
    var earlyChunk = data.substring(0, Math.min(data.length, 30000));
    var funcDefs = earlyChunk.matchAll(/(?:var\s+)?(\w+)=function\((\w+(?:,\w+){2,})\)\{/g);
    var candidates = [];

    for (var fd of funcDefs) {
        var funcName = fd[1];
        var defPos = data.indexOf(fd[0]);
        var bodyStart = data.indexOf('{', defPos + fd[0].length - 1);
        var depth = 0, pos = bodyStart;
        while (pos < data.length) {
            if (data[pos] === '{') depth++;
            else if (data[pos] === '}') { depth--; if (depth === 0) break; }
            pos++;
        }
        var funcBody = data.substring(bodyStart, pos + 1);
        var xorRegex = new RegExp(tableVar.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\[\\w+\\^(\\d+)\\]', 'g');
        var bases = new Set();
        var xm;
        while ((xm = xorRegex.exec(funcBody)) !== null) {
            bases.add(parseInt(xm[1]) ^ splitIdx);
        }
        if (bases.size > 0) {
            candidates.push({ funcName: funcName, bases: Array.from(bases) });
        }
    }

    // Sort by number of XOR accesses descending (dispatch tends to have the most)
    candidates.sort(function(a, b) { return b.bases.length - a.bases.length; });
    return candidates;
}

/**
 * Find the end of a function body via brace matching.
 * Returns the position of the closing }, or -1.
 */
function findFuncEnd(src, defIdx) {
    var bodyStart = src.indexOf('{', defIdx);
    if (bodyStart === -1) return -1;
    var depth = 0, pos = bodyStart;
    while (pos < src.length) {
        if (src[pos] === '{') depth++;
        else if (src[pos] === '}') { depth--; if (depth === 0) return pos; }
        pos++;
    }
    return -1;
}

/**
 * Build the probe code string that tests candidate functions.
 * When executed inside the player IIFE, this code probes each _dfN
 * variable with the given (r, p) params and sets _result.n on success.
 */
function buildMultiProbe(candidates, testEntries) {
    var funcVars = candidates.map(function(_, i) { return '_df' + i; }).join(',');
    var namesList = candidates.map(function(c) { return '"' + c.funcName + '"'; }).join(',');
    var paramsList = testEntries.map(function(e) { return '[' + e.fi + ',' + e.r + ',' + e.p + ']'; }).join(',');

    return [
        'var _tI="ABCDEFGHabcdefg1",_tI2="ZYXWVUTS98765432";',
        'var _fns=[' + funcVars + '],_names=[' + namesList + '];',
        'var _params=[' + paramsList + '];',
        'for(var _i=0;_i<_params.length;_i++){',
        '  var _fi=_params[_i][0],_r=_params[_i][1],_p=_params[_i][2];',
        '  var _fn=_fns[_fi];',
        '  if(typeof _fn!=="function")continue;',
        '  try{',
        '    var _res=_fn(_r,_p,_tI);',
        '    if(typeof _res==="string"&&_res!==_tI&&_res.length>0&&_res.length<200){',
        '      var _res2=_fn(_r,_p,_tI),_res3=_fn(_r,_p,_tI2);',
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
 * Build probe code for a single cached function.
 */
function buildSingleProbe(funcName, testParams) {
    var paramsList = testParams.map(function(tp) { return '[' + tp[0] + ',' + tp[1] + ']'; }).join(',');

    return [
        'var _tI="ABCDEFGHabcdefg1",_tI2="ZYXWVUTS98765432";',
        'if(typeof _df0==="function"){',
        '  var _params=[' + paramsList + '];',
        '  for(var _i=0;_i<_params.length;_i++){',
        '    var _r=_params[_i][0],_p=_params[_i][1];',
        '    try{',
        '      var _res=_df0(_r,_p,_tI);',
        '      if(typeof _res==="string"&&_res!==_tI&&_res.length>0&&_res.length<200){',
        '        var _res2=_df0(_r,_p,_tI),_res3=_df0(_r,_p,_tI2);',
        '        if(_res===_res2&&typeof _res3==="string"&&_res3!==_res){',
        '          (function(r,p){_result.n=function(n){return _df0(r,p,n);};})',
        '          (_r,_p);',
        '          _result._nName="' + funcName + '("+_r+","+_p+",n)";',
        '          break;',
        '        }',
        '      }',
        '    }catch(e){}',
        '  }',
        '}'
    ].join('\n');
}

/**
 * Main entry point. Called by the background.js shell.
 *
 * @param {string} data - The full player.js source code
 * @param {object|null} solvedCache - Cached {funcName, r, p} from previous solve, or null
 * @returns {string} - Modified player source with probe code injected, ready for Function() execution
 */
function preprocessPlayer(data, solvedCache) {
    var solvedParams = null;

    // --- Fast path: use cached params ---
    if (solvedCache && solvedCache.funcName) {
        solvedParams = {
            funcName: solvedCache.funcName,
            testParams: [[solvedCache.r, solvedCache.p]],
        };
    }

    // --- Full solve path ---
    if (!solvedParams) {
        var table = findStringTable(data);
        if (table) {
            var candidates = findCandidates(data, table.tableVar, table.splitIdx);

            // Build test params: candidate × base × r in [0..30]
            var testEntries = [];
            var seen = {};
            for (var fi = 0; fi < candidates.length; fi++) {
                for (var bi = 0; bi < candidates[fi].bases.length; bi++) {
                    var base = candidates[fi].bases[bi];
                    for (var r = 0; r <= 30; r++) {
                        var p = base ^ r;
                        var key = fi + ':' + r + ',' + p;
                        if (!seen[key]) {
                            seen[key] = true;
                            testEntries.push({ fi: fi, r: r, p: p });
                        }
                    }
                }
            }

            if (candidates.length > 0) {
                solvedParams = { candidates: candidates, testEntries: testEntries };
            }
        }
    }

    // --- Build probe code ---
    var probeBody;
    if (solvedParams && solvedParams.candidates) {
        probeBody = buildMultiProbe(solvedParams.candidates, solvedParams.testEntries);
    } else if (solvedParams) {
        probeBody = buildSingleProbe(solvedParams.funcName, solvedParams.testParams);
    } else {
        probeBody = '/* no candidates found */';
    }

    // --- Inject _df references after each candidate's definition ---
    var modified = data;

    if (solvedParams && solvedParams.candidates) {
        var injections = [];
        for (var i = 0; i < solvedParams.candidates.length; i++) {
            var c = solvedParams.candidates[i];
            var defIdx = modified.indexOf(c.funcName + '=function(');
            if (defIdx === -1) continue;
            var funcEnd = findFuncEnd(modified, defIdx);
            if (funcEnd === -1) continue;
            var semiPos = modified.indexOf(';', funcEnd);
            if (semiPos !== -1) {
                injections.push({ pos: semiPos + 1, code: '\nvar _df' + i + '=' + c.funcName + ';\n' });
            }
        }
        injections.sort(function(a, b) { return b.pos - a.pos; });
        for (var j = 0; j < injections.length; j++) {
            var inj = injections[j];
            modified = modified.substring(0, inj.pos) + inj.code + modified.substring(inj.pos);
        }
    } else if (solvedParams) {
        var defIdx = modified.indexOf(solvedParams.funcName + '=function(');
        if (defIdx !== -1) {
            var funcEnd = findFuncEnd(modified, defIdx);
            if (funcEnd !== -1) {
                var semiPos = modified.indexOf(';', funcEnd);
                if (semiPos !== -1) {
                    modified = modified.substring(0, semiPos + 1) + '\nvar _df0=' + solvedParams.funcName + ';\n' + modified.substring(semiPos + 1);
                }
            }
        }
    }

    // --- Inject probe at IIFE close ---
    var iifeCloseIdx = modified.lastIndexOf('}).call(this)');
    if (iifeCloseIdx === -1) iifeCloseIdx = modified.lastIndexOf('})(_yt_player)');
    if (iifeCloseIdx === -1) iifeCloseIdx = modified.lastIndexOf('})(');

    if (iifeCloseIdx !== -1) {
        modified = modified.substring(0, iifeCloseIdx) + '\n' + probeBody + '\n' + modified.substring(iifeCloseIdx);
        return SETUP_CODE + '\n' + modified;
    }

    return SETUP_CODE + '\n' + modified + '\n;(function(){' + probeBody + '})();';
}
