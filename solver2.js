// =============================================================================
// YouTube N-Parameter Solver — Remote Module v6 (solver2.js)
// Hosted at: https://github.com/solarizeddev/firedown-solver
// Compatible with both "main" and "tv" player variants.
//
// Strategy:
//   1. Call-site pattern matching (works on main + tv)
//      - Find the nsig call site in the player (where n-param is transformed)
//      - Extract the function name from the call site
//      - Extract the full function body + dependencies
//      - Eval and test behaviorally
//   2. Fallback: string table + XOR candidate detection (legacy, tv only)
// =============================================================================
var SOLVER_VERSION = 6;

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

// ─── Strategy 1: Call-site pattern matching ─────────────────────────────────

/**
 * Find the n-challenge function name by looking for the call site pattern
 * in the player JS. YouTube's player calls the n-function in a recognizable
 * wrapper pattern that yt-dlp also uses for detection.
 *
 * Known patterns (across player versions):
 *   - &&(b=a.get("n"))&&(b=FUNCNAME(b),a.set("n",b))
 *   - &&(b=a.get("n"))&&(b=FUNCNAME[IDX](b),a.set("n",b))
 *   - var h=a.sp.get("n");if(h){...FUNCNAME(h)...a.sp.set("n",...)
 *
 * Returns { funcName, isArray, arrayIdx } or null
 */
function findNFunctionCallSite(data) {
    // Pattern 1: Direct function call — &&(b=a.get("n"))&&(b=FUNC(b)
    var patterns = [
        // b=a.get("n"))&&(b=FUNC(b),a.set("n",b)
        /\b([a-zA-Z0-9_$]+)\s*=\s*[a-zA-Z0-9_$]+\.get\("n"\)\s*\)\s*&&\s*\(\s*\1\s*=\s*([a-zA-Z0-9_$]+)\s*\(\s*\1\s*\)/,
        // b=a.get("n"))&&(b=FUNC[IDX](b),a.set("n",b)
        /\b([a-zA-Z0-9_$]+)\s*=\s*[a-zA-Z0-9_$]+\.get\("n"\)\s*\)\s*&&\s*\(\s*\1\s*=\s*([a-zA-Z0-9_$]+)\[(\d+)\]\s*\(\s*\1\s*\)/,
        // c=a.get("n")  ... c=FUNC(c)  ... a.set("n",c)  (multi-line pattern)
        /[a-zA-Z0-9_$]+\s*=\s*[a-zA-Z0-9_$]+\.get\("n"\)[\s\S]{0,200}?([a-zA-Z0-9_$]+)\s*=\s*([a-zA-Z0-9_$]+)\s*\(\s*\1\s*\)[\s\S]{0,100}?\.set\("n"\s*,/,
        // set("n", FUNC(b)) pattern
        /\.set\(\s*"n"\s*,\s*([a-zA-Z0-9_$]+)\s*\(\s*([a-zA-Z0-9_$]+)\s*\)\s*\)/,
    ];

    for (var i = 0; i < patterns.length; i++) {
        var m = data.match(patterns[i]);
        if (m) {
            if (patterns[i].source.indexOf('[') !== -1 && m[3] !== undefined) {
                // Array access pattern: FUNC[IDX](b)
                return { funcName: m[2], isArray: true, arrayIdx: parseInt(m[3]) };
            }
            // Direct function pattern — the function name is in group 2 for most patterns
            var fname = m[2] || m[1];
            // Sanity: function name should be short and not a keyword
            if (fname && fname.length < 80 && !/^(if|for|while|return|var|let|const|function|true|false|null|undefined)$/.test(fname)) {
                return { funcName: fname, isArray: false, arrayIdx: -1 };
            }
        }
    }
    return null;
}

/**
 * If funcName is actually an array variable (FUNC[IDX]), resolve to the actual
 * function name by finding the array definition.
 */
function resolveArrayFunc(data, arrayName, idx) {
    // var ARRAY = [func1, func2, ...];
    var re = new RegExp('var\\s+' + arrayName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\s*=\\s*\\[([^\\]]{1,2000})\\]');
    var m = data.match(re);
    if (!m) return null;
    var elements = m[1].split(',').map(function(s) { return s.trim(); });
    if (idx < elements.length) return elements[idx];
    return null;
}

/**
 * Extract a function body by name, including nested dependencies.
 * Returns the full function code as a string, or null.
 */
function extractFunctionCode(data, funcName) {
    // Try: var FUNC=function(a){...}  or  function FUNC(a){...}
    var patterns = [
        new RegExp('(?:var\\s+)?' + funcName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\s*=\\s*function\\s*\\([^)]*\\)\\s*\\{'),
        new RegExp('function\\s+' + funcName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\s*\\([^)]*\\)\\s*\\{'),
    ];

    for (var pi = 0; pi < patterns.length; pi++) {
        var m = patterns[pi].exec(data);
        if (!m) continue;
        var start = m.index;
        var braceStart = data.indexOf('{', start + m[0].length - 1);
        if (braceStart === -1) continue;

        // Brace-match to find end of function
        var depth = 0, pos = braceStart;
        while (pos < data.length) {
            if (data[pos] === '{') depth++;
            else if (data[pos] === '}') {
                depth--;
                if (depth === 0) break;
            }
            pos++;
        }
        if (depth === 0) {
            return data.substring(start, pos + 1);
        }
    }
    return null;
}

/**
 * Build eval code using call-site detection.
 * Wraps the entire player in try-catch and tests the detected function.
 */
function buildCallSiteProbe(funcName) {
    return [
        'var _tI="ABCDEFGHabcdefg1",_tI2="ZYXWVUTS98765432";',
        'try{',
        '  if(typeof ' + funcName + '==="function"){',
        '    var _res=' + funcName + '(_tI);',
        '    if(typeof _res==="string"&&_res!==_tI&&_res.length>0&&_res.length<200){',
        '      var _res2=' + funcName + '(_tI);',
        '      var _res3=' + funcName + '(_tI2);',
        '      if(_res===_res2&&typeof _res3==="string"&&_res3!==_res){',
        '        _result.n=function(n){return ' + funcName + '(n);};',
        '        _result._nName="' + funcName + '(n)";',
        '      }',
        '    }',
        '  }',
        '}catch(e){}'
    ].join('\n');
}

/**
 * Build probe for array-style call: ARRAY[IDX](n)
 */
function buildArrayProbe(arrayName, idx) {
    return [
        'var _tI="ABCDEFGHabcdefg1",_tI2="ZYXWVUTS98765432";',
        'try{',
        '  var _fn=' + arrayName + '[' + idx + '];',
        '  if(typeof _fn==="function"){',
        '    var _res=_fn(_tI);',
        '    if(typeof _res==="string"&&_res!==_tI&&_res.length>0&&_res.length<200){',
        '      var _res2=_fn(_tI);',
        '      var _res3=_fn(_tI2);',
        '      if(_res===_res2&&typeof _res3==="string"&&_res3!==_res){',
        '        _result.n=function(n){return ' + arrayName + '[' + idx + '](n);};',
        '        _result._nName="' + arrayName + '[' + idx + '](n)";',
        '      }',
        '    }',
        '  }',
        '}catch(e){}'
    ].join('\n');
}


// ─── Strategy 2: String table + XOR candidates (legacy, TV variant) ─────────

function findStringTable(data) {
    var chunk = data.substring(0, 2000);
    var splitCalls = chunk.matchAll(/\.split\((['"])(.)\1\)/g);
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

function findCandidates(data, tableVar, splitIdx) {
    var earlyChunk = data.substring(0, Math.min(data.length, 30000));
    var funcDefs = earlyChunk.matchAll(/(?:^|[^a-zA-Z0-9_$])(?:var\s+)?(\w+)=function\((\w+(?:,\w+){2,})\)\{/g);
    var candidates = [];
    for (var fd of funcDefs) {
        var funcName = fd[1];
        var defPos = data.indexOf(funcName + '=function(');
        if (defPos === -1) continue;
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
        var searchText = funcBody || data.substring(defPos, Math.min(defPos + 2000, data.length));
        var xorRx = new RegExp(tableVar.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\[\\w+\\^(\\d+)\\]', 'g');
        var bases = new Set(), xm;
        while ((xm = xorRx.exec(searchText)) !== null) bases.add(parseInt(xm[1]) ^ splitIdx);
        if (bases.size > 0) candidates.push({ funcName: funcName, bases: Array.from(bases) });
    }
    candidates.sort(function(a, b) { return b.bases.length - a.bases.length; });
    return candidates;
}

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

function buildDfProbe(candidates, testEntries) {
    var fnArr = candidates.map(function(_, i) { return '_df' + i; }).join(',');
    var nameArr = candidates.map(function(c) { return '"' + c.funcName + '"'; }).join(',');
    var paramArr = testEntries.map(function(e) { return '[' + e.fi + ',' + e.r + ',' + e.p + ']'; }).join(',');
    return [
        'var _fns2=[' + fnArr + '],_names2=[' + nameArr + '];',
        'var _params2=[' + paramArr + '];',
        'var _tI3="ABCDEFGHabcdefg1",_tI4="ZYXWVUTS98765432";',
        'for(var _j=0;_j<_params2.length;_j++){',
        '  var _fj=_params2[_j][0],_rj=_params2[_j][1],_pj=_params2[_j][2];',
        '  if(typeof _fns2[_fj]!=="function")continue;',
        '  try{',
        '    var _rr=_fns2[_fj](_rj,_pj,_tI3);',
        '    if(typeof _rr==="string"&&_rr!==_tI3&&_rr.length>0&&_rr.length<200){',
        '      var _rr2=_fns2[_fj](_rj,_pj,_tI3),_rr3=_fns2[_fj](_rj,_pj,_tI4);',
        '      if(_rr===_rr2&&typeof _rr3==="string"&&_rr3!==_rr){',
        '        (function(fj,rj,pj){_result.n=function(n){return _fns2[fj](rj,pj,n);};})',
        '        (_fj,_rj,_pj);',
        '        _result._nName=_names2[_fj]+"("+_rj+","+_pj+",n)";',
        '        break;',
        '      }',
        '    }',
        '  }catch(e){}',
        '}'
    ].join('\n');
}

function buildCachedProbe(funcName, r, p) {
    // Detect if this is a single-arg cached func (call-site style) vs 3-arg (legacy)
    if (r === undefined || r === null) {
        // Single-arg call-site style: FUNC(n)
        return [
            'var _tI="ABCDEFGHabcdefg1",_tI2="ZYXWVUTS98765432";',
            'try{',
            '  var _res=' + funcName + '(_tI);',
            '  if(typeof _res==="string"&&_res!==_tI&&_res.length>0&&_res.length<200){',
            '    var _res2=' + funcName + '(_tI);',
            '    var _res3=' + funcName + '(_tI2);',
            '    if(_res===_res2&&typeof _res3==="string"&&_res3!==_res){',
            '      _result.n=function(n){return ' + funcName + '(n);};',
            '      _result._nName="' + funcName + '(n)";',
            '    }',
            '  }',
            '}catch(e){}'
        ].join('\n');
    }
    // Legacy 3-arg style: FUNC(r, p, n)
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


// ─── Main entry point ───────────────────────────────────────────────────────

/**
 * @param {string} data - Full player.js source
 * @param {object|null} solvedCache - {funcName, r, p} from previous solve
 * @returns {string} - Code ready for Function("_result", code)(resultObj)
 */
function preprocessPlayer(data, solvedCache) {
    var probeBody = null;
    var candidates = null;
    var testEntries = null;
    var callSiteResult = null;

    // ── Cached path ──
    if (solvedCache && solvedCache.funcName) {
        probeBody = buildCachedProbe(solvedCache.funcName, solvedCache.r, solvedCache.p);
    }

    // ── Strategy 1: Call-site pattern matching ──
    if (!probeBody) {
        callSiteResult = findNFunctionCallSite(data);
        if (callSiteResult) {
            var targetFunc = callSiteResult.funcName;
            if (callSiteResult.isArray) {
                var resolved = resolveArrayFunc(data, callSiteResult.funcName, callSiteResult.arrayIdx);
                if (resolved) targetFunc = resolved;
                else {
                    // Can't resolve array — build array probe instead
                    probeBody = buildArrayProbe(callSiteResult.funcName, callSiteResult.arrayIdx);
                }
            }
            if (!probeBody) {
                probeBody = buildCallSiteProbe(targetFunc);
            }
        }
    }

    // ── Strategy 2: String table + XOR (legacy TV variant) ──
    if (!probeBody) {
        var table = findStringTable(data);
        if (table) {
            candidates = findCandidates(data, table.tableVar, table.splitIdx);
            if (candidates.length > 0) {
                testEntries = [];
                var seen = {};
                for (var fi = 0; fi < candidates.length; fi++) {
                    for (var bi = 0; bi < candidates[fi].bases.length; bi++) {
                        var base = candidates[fi].bases[bi];
                        for (var r = 0; r <= 50; r++) {
                            var p = base ^ r;
                            var key = fi + ':' + r + ',' + p;
                            if (!seen[key]) { seen[key] = true; testEntries.push({ fi: fi, r: r, p: p }); }
                        }
                    }
                }
                var directProbe = buildProbe(candidates, testEntries);
                var dfProbe = buildDfProbe(candidates, testEntries);
                probeBody = directProbe + '\nif(!_result.n){\n' + dfProbe + '\n}';
            }
        }
    }

    if (!probeBody) probeBody = '/* no candidates found */';

    // ── Inject _df captures (for legacy strategy 2 only) ──
    var modified = data;
    if (candidates && candidates.length > 0) {
        var tableDelimiter = null;
        var delimMatch = data.substring(0, 2000).match(/\.split\((['"])(.)\1\)/);
        if (delimMatch) tableDelimiter = delimMatch[2];

        if (tableDelimiter !== '}') {
            var commaInjections = [];
            for (var i = 0; i < candidates.length; i++) {
                var c = candidates[i];
                var defIdx = modified.indexOf(c.funcName + '=function(');
                if (defIdx === -1) continue;
                var bodyStart = modified.indexOf('{', defIdx);
                if (bodyStart === -1) continue;
                var depth = 0, pos = bodyStart;
                while (pos < modified.length) {
                    if (modified[pos] === '{') depth++;
                    else if (modified[pos] === '}') { depth--; if (depth === 0) break; }
                    pos++;
                }
                if (depth === 0) {
                    commaInjections.push({ pos: pos + 1, code: ',_df' + i + '=' + c.funcName });
                }
            }
            commaInjections.sort(function(a, b) { return b.pos - a.pos; });
            for (var j = 0; j < commaInjections.length; j++) {
                var inj = commaInjections[j];
                modified = modified.substring(0, inj.pos) + inj.code + modified.substring(inj.pos);
            }
        }

        var chainInjections = [];
        for (var i = 0; i < candidates.length; i++) {
            var c = candidates[i];
            var defIdx = modified.indexOf(c.funcName + '=function(');
            if (defIdx === -1) continue;
            var searchFrom = defIdx;
            var chainEnd = -1;
            while (searchFrom < modified.length) {
                var nextSemiNl = modified.indexOf(';\n', searchFrom);
                if (nextSemiNl === -1) break;
                var afterSemi = modified.substring(nextSemiNl + 2, nextSemiNl + 12);
                if (afterSemi.indexOf('function ') === 0 || afterSemi.indexOf('var ') === 0) {
                    chainEnd = nextSemiNl + 1;
                    break;
                }
                searchFrom = nextSemiNl + 2;
            }
            if (chainEnd !== -1) {
                chainInjections.push({ pos: chainEnd, code: '\ntry{_df' + i + '=' + c.funcName + ';}catch(e){}' });
            }
        }
        var mergedByPos = {};
        for (var j = 0; j < chainInjections.length; j++) {
            var p = chainInjections[j].pos;
            if (!mergedByPos[p]) mergedByPos[p] = '';
            mergedByPos[p] += chainInjections[j].code;
        }
        var sorted = Object.keys(mergedByPos).map(Number).sort(function(a, b) { return b - a; });
        for (var j = 0; j < sorted.length; j++) {
            var pos = sorted[j];
            modified = modified.substring(0, pos) + mergedByPos[pos] + modified.substring(pos);
        }
    }

    // ── Wrap player in try-catch, append probe ──
    var iifeCloseIdx = modified.lastIndexOf('}).call(this)');
    if (iifeCloseIdx === -1) iifeCloseIdx = modified.lastIndexOf('})(_yt_player)');
    if (iifeCloseIdx === -1) iifeCloseIdx = modified.lastIndexOf('})(');

    if (iifeCloseIdx !== -1) {
        var strictIdx = modified.indexOf("'use strict';");
        var afterStrict = strictIdx !== -1 ? strictIdx + "'use strict';".length : modified.indexOf('{') + 1;

        var dfDecl = '';
        if (candidates && candidates.length > 0) {
            var dfNames = [];
            for (var i = 0; i < candidates.length; i++) dfNames.push('_df' + i);
            dfDecl = '\nvar ' + dfNames.join(',') + ';\n';
        }

        return SETUP_CODE + '\n' +
            modified.substring(0, afterStrict) + dfDecl + '\ntry{\n' +
            modified.substring(afterStrict, iifeCloseIdx) + '\n}catch(_e){}\n' +
            probeBody + '\n' +
            modified.substring(iifeCloseIdx);
    }

    return SETUP_CODE + '\n' + modified + '\n;(function(){' + probeBody + '})();';
}
