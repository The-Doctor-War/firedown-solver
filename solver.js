// =============================================================================
// YouTube N-Parameter Solver — Remote Module v4 -> v8
// Hosted at: https://github.com/solarizeddev/firedown-solver
// The background.js shell fetches, caches, and executes this module.
//
// v6 additions: preprocessCipher() for signature cipher detection on base.js
// The cipher function is obfuscated with the same string table + XOR pattern
// as the n-param function, but lives in the 'main' player variant (base.js)
// rather than the TV variant.
//
// v7 additions: preprocessPlayer() now supports base.js (main player variant)
// The TV player no longer contains the n-param challenge function as of
// player version ace4b2f8 (March 2026). findStringTable search window
// increased to 5000 chars and 'use strict' fallback added to preprocessPlayer
// to handle base.js copyright header offset.
//
// v8 fixes: Full base.js support for n-param solving.
//   - findCandidates now searches the FULL file (not just first 60K)
//   - Function name regex uses [\w$] to match $ in JS identifiers (G$, y$, etc.)
//   - Property assignments (g.vu=function) are filtered out
//   - Chain-boundary injection pattern matches [\w$]+=function identifiers
//   - base.js executes WITHOUT try-catch wrapping (required for dispatch table
//     initialization; base.js completes without error unlike TV player)
//   - Probe prefers n-param over cipher results by checking for new chars
//     in output (n-param generates new chars; cipher only permutes input chars)
// =============================================================================
var SOLVER_VERSION = 8;

var SETUP_CODE = [
    'if(typeof globalThis.XMLHttpRequest==="undefined"){globalThis.XMLHttpRequest={prototype:{}};}',
    // base.js does 'var window=this' inside its IIFE, making window=globalThis.
    // Location must be on globalThis so the player can access window.location.hostname etc.
    'globalThis.location={hash:"",host:"www.youtube.com",hostname:"www.youtube.com",',
    'href:"https://www.youtube.com/watch?v=yt-dlp-wins",origin:"https://www.youtube.com",password:"",',
    'pathname:"/watch",port:"",protocol:"https:",search:"?v=yt-dlp-wins",username:"",',
    'assign:function(){},replace:function(){},reload:function(){},toString:function(){return this.href;}};',
    // Also set window as a plain object for TV player (which does 'var window=Object.create(null)')
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
 * Handles: "...".split(";"), '...'.split("}"), ["...","..."]
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
 *
 * v8: Searches the FULL file. Uses [\w$] for JS identifier matching.
 *     Skips property assignments (g.X=function). Uses brace-matching for
 *     function body isolation when safe (non-} delimiter), falls back to
 *     fixed 2000-char window otherwise.
 */
function findCandidates(data, tableVar, splitIdx) {
    // Detect if } is the string table delimiter (brace matching is unreliable then)
    var delimMatch = data.substring(0, 10000).match(/\.split\((['"])(.)(\1)\)/);
    var unsafeBraces = delimMatch && delimMatch[2] === '}';
    // v8: [\w$] matches $ in function names like G$, y$
    var funcDefs = data.matchAll(/(?:^|[^a-zA-Z0-9_$.])(?:var\s+)?([\w$]+)=function\(([\w$]+(?:,[\w$]+){2,})\)\{/g);
    var candidates = [];
    for (var fd of funcDefs) {
        var funcName = fd[1];
        var defPos = data.indexOf(funcName + '=function(', fd.index);
        if (defPos === -1) continue;
        // v8: Skip property assignments like g.vu=function(
        if (defPos > 0 && data[defPos - 1] === '.') continue;
        // Isolate function body via brace matching (when delimiter isn't })
        var bodyStart = data.indexOf('{', defPos);
        var funcBody = null;
        if (!unsafeBraces && bodyStart !== -1) {
            var depth = 0, pos = bodyStart;
            while (pos < data.length) {
                if (data[pos] === '{') depth++;
                else if (data[pos] === '}') { depth--; if (depth === 0) { funcBody = data.substring(bodyStart, pos + 1); break; } }
                pos++;
            }
        }
        // v8: Fall back to 2000-char window when brace matching is unsafe or fails
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
 *
 * v8: Added _hasNewChars check to prefer n-param results over cipher results.
 * The n-param transform generates new characters not in the input, while
 * the cipher function only rearranges existing characters.
 */
function buildProbe(candidates, testEntries) {
    var fnArr = candidates.map(function(c) { return c.funcName; }).join(',');
    var nameArr = candidates.map(function(c) { return '"' + c.funcName + '"'; }).join(',');
    var paramArr = testEntries.map(function(e) { return '[' + e.fi + ',' + e.r + ',' + e.p + ']'; }).join(',');
    return [
        'var _fns=[' + fnArr + '],_names=[' + nameArr + '];',
        'var _params=[' + paramArr + '];',
        'var _tI="ABCDEFGHabcdefg1",_tI2="ZYXWVUTS98765432";',
        // v8: helper to check if output contains chars not in input
        'function _hasNewChars(a,b){var s=new Set(a.split(""));for(var i=0;i<b.length;i++)if(!s.has(b[i]))return true;return false;}',
        'for(var _i=0;_i<_params.length;_i++){',
        '  var _fi=_params[_i][0],_r=_params[_i][1],_p=_params[_i][2];',
        '  try{',
        '    var _res=_fns[_fi](_r,_p,_tI);',
        '    if(typeof _res==="string"&&_res!==_tI&&_res.length>0&&_res.length<200){',
        '      var _res2=_fns[_fi](_r,_p,_tI),_res3=_fns[_fi](_r,_p,_tI2);',
        '      if(_res===_res2&&typeof _res3==="string"&&_res3!==_res',
        // v8: prefer n-param (has new chars) over cipher (only permutes)
        '        &&_hasNewChars(_tI,_res)){',
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
 * Build probe using _df captured vars (fallback when direct names are overwritten).
 */
function buildDfProbe(candidates, testEntries) {
    var fnArr = candidates.map(function(_, i) { return '_df' + i; }).join(',');
    var nameArr = candidates.map(function(c) { return '"' + c.funcName + '"'; }).join(',');
    var paramArr = testEntries.map(function(e) { return '[' + e.fi + ',' + e.r + ',' + e.p + ']'; }).join(',');
    return [
        'var _fns2=[' + fnArr + '],_names2=[' + nameArr + '];',
        'var _params2=[' + paramArr + '];',
        'var _tI3="ABCDEFGHabcdefg1",_tI4="ZYXWVUTS98765432";',
        'function _hasNewChars2(a,b){var s=new Set(a.split(""));for(var i=0;i<b.length;i++)if(!s.has(b[i]))return true;return false;}',
        'for(var _j=0;_j<_params2.length;_j++){',
        '  var _fj=_params2[_j][0],_rj=_params2[_j][1],_pj=_params2[_j][2];',
        '  if(typeof _fns2[_fj]!=="function")continue;',
        '  try{',
        '    var _rr=_fns2[_fj](_rj,_pj,_tI3);',
        '    if(typeof _rr==="string"&&_rr!==_tI3&&_rr.length>0&&_rr.length<200){',
        '      var _rr2=_fns2[_fj](_rj,_pj,_tI3),_rr3=_fns2[_fj](_rj,_pj,_tI4);',
        '      if(_rr===_rr2&&typeof _rr3==="string"&&_rr3!==_rr',
        '        &&_hasNewChars2(_tI3,_rr)){',
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
 * Detect whether the player is a base.js (main) variant or TV player variant.
 * base.js uses }).call(this) to close its IIFE and has a copyright header
 * before 'use strict'. TV player uses })(_yt_player).
 *
 * base.js executes without error in the sandbox (no DOM dependencies during init),
 * so it does NOT need try-catch wrapping. In fact, try-catch wrapping breaks
 * base.js because it prevents initialization of functions referenced in the
 * n-param dispatch table.
 */
function isBaseJsVariant(data) {
    // base.js has a copyright header before 'use strict', pushing it to ~3KB offset.
    // TV player has 'use strict' at or very near the start (offset 0-100).
    // This is the most reliable distinguisher since both variants use })(_yt_player).
    var usIdx = data.indexOf("'use strict';");
    if (usIdx > 1000 && usIdx < 10000) return true;
    return false;
}

/**
 * Main entry point for n-parameter solving.
 * @param {string} data - Full player.js source (TV variant or base.js)
 * @param {object|null} solvedCache - {funcName, r, p} from previous solve
 * @returns {string} - Code ready for Function("_result", code)(resultObj)
 */
function preprocessPlayer(data, solvedCache) {
    // --- Find candidates or use cache ---
    var probeBody;
    var candidates = null;
    var testEntries = null;

    if (solvedCache && solvedCache.funcName) {
        probeBody = buildCachedProbe(solvedCache.funcName, solvedCache.r, solvedCache.p);
    } else {
        var table = findStringTable(data);
        // base.js has its string table after copyright comments (~3KB in),
        // so try findStringTable on the source starting from 'use strict'
        if (!table) {
            var usIdx = data.indexOf("'use strict';");
            if (usIdx > 0 && usIdx < 10000) {
                table = findStringTable(data.substring(usIdx));
            }
        }
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
                // Build two-layer probe: try direct names first, then _df fallback
                var directProbe = buildProbe(candidates, testEntries);
                var dfProbe = buildDfProbe(candidates, testEntries);
                probeBody = directProbe + '\nif(!_result.n){\n' + dfProbe + '\n}';
            }
        }
    }
    if (!probeBody) probeBody = '/* no candidates found */';

    // --- Detect player variant ---
    var baseJs = isBaseJsVariant(data);

    // --- Inject _df captures using multiple strategies ---
    // v8: Skip _df injection for base.js (not needed without try-catch)
    var modified = data;
    if (!baseJs && candidates && candidates.length > 0) {
        // Strategy 1: Comma injection inside var chains (most reliable)
        var tableDelimiter = null;
        var delimMatch = data.substring(0, 2000).match(/\.split\((['"])(.)(\1)\)/);
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

        // Strategy 2: Chain-boundary injection (fallback for } delimiter players)
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
                // v8: limit search distance to avoid runaway scanning
                if (nextSemiNl - defIdx > 10000) break;
                var afterSemi = modified.substring(nextSemiNl + 2, nextSemiNl + 32);
                // v8: [\w$] to match $ in identifiers like $EN
                if (/^(?:function |var |[\w$]+=function\()/.test(afterSemi)) {
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

    // --- Wrap player and append probe ---
    var iifeCloseIdx = modified.lastIndexOf('}).call(this)');
    if (iifeCloseIdx === -1) iifeCloseIdx = modified.lastIndexOf('})(_yt_player)');
    if (iifeCloseIdx === -1) iifeCloseIdx = modified.lastIndexOf('})(');

    if (iifeCloseIdx !== -1) {
        var strictIdx = modified.indexOf("'use strict';");
        var afterStrict = strictIdx !== -1 ? strictIdx + "'use strict';".length : modified.indexOf('{') + 1;

        if (baseJs) {
            // v8: base.js — NO try-catch wrapping.
            // base.js executes fully without error in the sandbox. Wrapping in
            // try-catch would prevent initialization of functions in the n-param
            // dispatch table, causing the transform to fail silently.
            // Probe code is injected just before the IIFE close, within the
            // IIFE scope where all functions are accessible.
            return SETUP_CODE + '\n' +
                modified.substring(0, iifeCloseIdx) + '\n' +
                probeBody + '\n' +
                modified.substring(iifeCloseIdx);
        }

        // TV player: wrap in try-catch (existing behavior)
        // Declare _df vars before try (accessible in probe after catch)
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

// =============================================================================
// SIGNATURE CIPHER DETECTION — v6 addition
// =============================================================================

/**
 * Find cipher candidates — searches the FULL file for multi-param functions
 * with XOR table accesses.
 *
 * v8: Uses [\w$] for identifier matching, skips property assignments.
 */
function findCipherCandidates(data, tableVar, splitIdx) {
    var escaped = tableVar.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    var delimMatch = data.substring(0, 10000).match(/\.split\((['"])(.)(\1)\)/);
    var unsafeBraces = delimMatch && delimMatch[2] === '}';
    // v8: [\w$] matches $ in function names
    var funcDefs = data.matchAll(/(?:^|[^a-zA-Z0-9_$.])(?:var\s+)?([\w$]+)=function\(([\w$]+(?:,[\w$]+){2,})\)\{/g);
    var candidates = [];
    for (var fd of funcDefs) {
        var funcName = fd[1];
        var defPos = data.indexOf(funcName + '=function(', fd.index);
        if (defPos === -1) continue;
        // v8: Skip property assignments
        if (defPos > 0 && data[defPos - 1] === '.') continue;
        var bodyStart = data.indexOf('{', defPos);
        var funcBody = null;
        if (!unsafeBraces && bodyStart !== -1) {
            var depth = 0, pos = bodyStart;
            while (pos < data.length) {
                if (data[pos] === '{') depth++;
                else if (data[pos] === '}') { depth--; if (depth === 0) { funcBody = data.substring(bodyStart, pos + 1); break; } }
                pos++;
            }
        }
        var searchText = funcBody || data.substring(defPos, Math.min(defPos + 3000, data.length));
        // Must have XOR table accesses
        var xorRx = new RegExp(escaped + '\\[\\w+\\^(\\d+)\\]', 'g');
        var bases = new Set(), xm;
        while ((xm = xorRx.exec(searchText)) !== null) bases.add(parseInt(xm[1]) ^ splitIdx);
        // Cipher candidates need many bases (the cipher function accesses many table entries)
        // and the function must be large enough to contain the dispatch logic
        if (bases.size >= 10 && searchText.length > 500) {
            candidates.push({ funcName: funcName, bases: Array.from(bases) });
        }
    }
    candidates.sort(function(a, b) { return b.bases.length - a.bases.length; });
    return candidates;
}

/**
 * Build cipher probe code.
 */
function buildCipherProbe(candidates, testEntries) {
    var fnArr = candidates.map(function(c) { return c.funcName; }).join(',');
    var nameArr = candidates.map(function(c) { return '"' + c.funcName + '"'; }).join(',');
    var paramArr = testEntries.map(function(e) { return '[' + e.fi + ',' + e.r + ',' + e.p + ']'; }).join(',');
    return [
        'var _cfns=[' + fnArr + '],_cnames=[' + nameArr + '];',
        'var _cparams=[' + paramArr + '];',
        'var _cSig="AOq0QJ8wRAIgTXjVbFq4RE0_C3YYzJ-j-rVqGi25Oj_bm9c3x2CiqKICIFfBKjR5Q3iBvFHIqZLqhY1jQ9o5a_FV8WNi9Z2v3BdMAhIARbCqF0FHn4";',
        'var _cSig2="ZZq0QJ8wRAIgTXjVbFq4RE0_C3YYzJ-j-rVqGi25Oj_bm9c3x2CiqKICIFfBKjR5Q3iBvFHIqZLqhY1jQ9o5a_FV8WNi9Z2v3BdMAhIARbCqF0FHZZ";',
        'function _isCipherResult(input,output){',
        '  if(typeof output!=="string")return false;',
        '  if(output===input)return false;',
        '  if(output.length<20)return false;',
        '  if(output.length>input.length)return false;',
        '  if(output.length<input.length-10)return false;',
        '  return true;',
        '}',
        'for(var _ci=0;_ci<_cparams.length&&!_result.sig;_ci++){',
        '  var _cfi=_cparams[_ci][0],_cr=_cparams[_ci][1],_cp=_cparams[_ci][2];',
        '  try{',
        '    var _cres=_cfns[_cfi](_cr,_cp,_cSig);',
        '    if(_isCipherResult(_cSig,_cres)){',
        '      var _cres2=_cfns[_cfi](_cr,_cp,_cSig);',
        '      var _cres3=_cfns[_cfi](_cr,_cp,_cSig2);',
        '      if(_cres===_cres2&&_cres3!==_cres&&_isCipherResult(_cSig2,_cres3)){',
        '        (function(fi,r,p){_result.sig=function(s){return _cfns[fi](r,p,s);};})',
        '        (_cfi,_cr,_cp);',
        '        _result._sigName=_cnames[_cfi]+"("+_cr+","+_cp+",s)";',
        '        break;',
        '      }',
        '    }',
        '  }catch(e){}',
        '}'
    ].join('\n');
}

/**
 * Build _df-based cipher probe (fallback when direct names are overwritten).
 */
function buildDfCipherProbe(candidates, testEntries) {
    var fnArr = candidates.map(function(_, i) { return '_cdf' + i; }).join(',');
    var nameArr = candidates.map(function(c) { return '"' + c.funcName + '"'; }).join(',');
    var paramArr = testEntries.map(function(e) { return '[' + e.fi + ',' + e.r + ',' + e.p + ']'; }).join(',');
    return [
        'var _cfns2=[' + fnArr + '],_cnames2=[' + nameArr + '];',
        'var _cparams2=[' + paramArr + '];',
        'var _cSig3="AOq0QJ8wRAIgTXjVbFq4RE0_C3YYzJ-j-rVqGi25Oj_bm9c3x2CiqKICIFfBKjR5Q3iBvFHIqZLqhY1jQ9o5a_FV8WNi9Z2v3BdMAhIARbCqF0FHn4";',
        'var _cSig4="ZZq0QJ8wRAIgTXjVbFq4RE0_C3YYzJ-j-rVqGi25Oj_bm9c3x2CiqKICIFfBKjR5Q3iBvFHIqZLqhY1jQ9o5a_FV8WNi9Z2v3BdMAhIARbCqF0FHZZ";',
        'function _isCipherResult2(input,output){',
        '  if(typeof output!=="string")return false;',
        '  if(output===input)return false;',
        '  if(output.length<20)return false;',
        '  if(output.length>input.length)return false;',
        '  if(output.length<input.length-10)return false;',
        '  return true;',
        '}',
        'for(var _ci2=0;_ci2<_cparams2.length&&!_result.sig;_ci2++){',
        '  var _cfi2=_cparams2[_ci2][0],_cr2=_cparams2[_ci2][1],_cp2=_cparams2[_ci2][2];',
        '  if(typeof _cfns2[_cfi2]!=="function")continue;',
        '  try{',
        '    var _cres4=_cfns2[_cfi2](_cr2,_cp2,_cSig3);',
        '    if(_isCipherResult2(_cSig3,_cres4)){',
        '      var _cres5=_cfns2[_cfi2](_cr2,_cp2,_cSig3);',
        '      var _cres6=_cfns2[_cfi2](_cr2,_cp2,_cSig4);',
        '      if(_cres4===_cres5&&_cres6!==_cres4&&_isCipherResult2(_cSig4,_cres6)){',
        '        (function(fi,r,p){_result.sig=function(s){return _cfns2[fi](r,p,s);};})',
        '        (_cfi2,_cr2,_cp2);',
        '        _result._sigName=_cnames2[_cfi2]+"("+_cr2+","+_cp2+",s)";',
        '        break;',
        '      }',
        '    }',
        '  }catch(e){}',
        '}'
    ].join('\n');
}

/**
 * Cipher entry point — extract signature cipher function from base.js.
 * Called separately from preprocessPlayer (which handles n-param).
 *
 * @param {string} data - Full player.js source (main/base.js variant)
 * @param {object|null} cipherCache - {funcName, r, p} from previous solve
 * @returns {string} - Code ready for Function("_result", code)(resultObj)
 */
function preprocessCipher(data, cipherCache) {
    var probeBody;
    var candidates = null;

    if (cipherCache && cipherCache.funcName) {
        probeBody = [
            'var _cSig="AOq0QJ8wRAIgTXjVbFq4RE0_C3YYzJ-j-rVqGi25Oj_bm9c3x2CiqKICIFfBKjR5Q3iBvFHIqZLqhY1jQ9o5a_FV8WNi9Z2v3BdMAhIARbCqF0FHn4";',
            'var _cSig2="ZZq0QJ8wRAIgTXjVbFq4RE0_C3YYzJ-j-rVqGi25Oj_bm9c3x2CiqKICIFfBKjR5Q3iBvFHIqZLqhY1jQ9o5a_FV8WNi9Z2v3BdMAhIARbCqF0FHZZ";',
            'try{',
            '  var _cres=' + cipherCache.funcName + '(' + cipherCache.r + ',' + cipherCache.p + ',_cSig);',
            '  if(typeof _cres==="string"&&_cres!==_cSig&&_cres.length>=20&&_cres.length<=_cSig.length){',
            '    var _cres2=' + cipherCache.funcName + '(' + cipherCache.r + ',' + cipherCache.p + ',_cSig);',
            '    var _cres3=' + cipherCache.funcName + '(' + cipherCache.r + ',' + cipherCache.p + ',_cSig2);',
            '    if(_cres===_cres2&&_cres3!==_cres){',
            '      _result.sig=function(s){return ' + cipherCache.funcName + '(' + cipherCache.r + ',' + cipherCache.p + ',s);};',
            '      _result._sigName="' + cipherCache.funcName + '(' + cipherCache.r + ',' + cipherCache.p + ',s)";',
            '    }',
            '  }',
            '}catch(e){}'
        ].join('\n');
    } else {
        var table = findStringTable(data);
        if (!table) {
            var strictIdx = data.indexOf("'use strict';");
            if (strictIdx > 0 && strictIdx < 10000) {
                table = findStringTable(data.substring(strictIdx));
            }
        }
        if (table) {
            candidates = findCipherCandidates(data, table.tableVar, table.splitIdx);
            if (candidates.length > 0) {
                var cipherCValues = [8, 9, 40, 41];
                var testEntries = [];
                var seen = {};
                for (var fi = 0; fi < candidates.length; fi++) {
                    for (var bi = 0; bi < candidates[fi].bases.length; bi++) {
                        var base = candidates[fi].bases[bi];
                        for (var ci = 0; ci < cipherCValues.length; ci++) {
                            var r = cipherCValues[ci];
                            var p = base ^ r;
                            var key = fi + ':' + r + ',' + p;
                            if (!seen[key]) { seen[key] = true; testEntries.push({ fi: fi, r: r, p: p }); }
                        }
                    }
                }
                probeBody = buildCipherProbe(candidates, testEntries);
                var dfCipherProbe = buildDfCipherProbe(candidates, testEntries);
                probeBody = probeBody + '\nif(!_result.sig){\n' + dfCipherProbe + '\n}';
            }
        }
    }

    if (!probeBody) probeBody = '/* no cipher candidates found */';

    // --- Detect player variant ---
    var baseJs = isBaseJsVariant(data);

    // --- Inject _df captures and wrap player ---
    var modified = data;
    if (!baseJs && candidates && candidates.length > 0) {
        var tableDelimiter = null;
        var delimMatch = data.substring(0, 10000).match(/\.split\((['"])(.)(\1)\)/);
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
                    commaInjections.push({ pos: pos + 1, code: ',_cdf' + i + '=' + c.funcName });
                }
            }
            commaInjections.sort(function(a, b) { return b.pos - a.pos; });
            for (var j = 0; j < commaInjections.length; j++) {
                var inj = commaInjections[j];
                modified = modified.substring(0, inj.pos) + inj.code + modified.substring(inj.pos);
            }
        }

        // Strategy 2: Chain-boundary injection
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
                if (nextSemiNl - defIdx > 10000) break;
                var afterSemi = modified.substring(nextSemiNl + 2, nextSemiNl + 32);
                // v8: [\w$] to match $ in identifiers
                if (/^(?:function |var |[\w$]+=function\()/.test(afterSemi)) {
                    chainEnd = nextSemiNl + 1;
                    break;
                }
                searchFrom = nextSemiNl + 2;
            }
            if (chainEnd !== -1) {
                chainInjections.push({ pos: chainEnd, code: '\ntry{_cdf' + i + '=' + c.funcName + ';}catch(e){}' });
            }
        }
        var mergedByPos = {};
        for (var j = 0; j < chainInjections.length; j++) {
            var pp = chainInjections[j].pos;
            if (!mergedByPos[pp]) mergedByPos[pp] = '';
            mergedByPos[pp] += chainInjections[j].code;
        }
        var sorted = Object.keys(mergedByPos).map(Number).sort(function(a, b) { return b - a; });
        for (var j = 0; j < sorted.length; j++) {
            var ppos = sorted[j];
            modified = modified.substring(0, ppos) + mergedByPos[ppos] + modified.substring(ppos);
        }
    }

    // Wrap player
    var iifeCloseIdx = modified.lastIndexOf('}).call(this)');
    if (iifeCloseIdx === -1) iifeCloseIdx = modified.lastIndexOf('})(_yt_player)');
    if (iifeCloseIdx === -1) iifeCloseIdx = modified.lastIndexOf('})(');

    if (iifeCloseIdx !== -1) {
        var strictIdx = modified.indexOf("'use strict';");
        var afterStrict = strictIdx !== -1 ? strictIdx + "'use strict';".length : modified.indexOf('{') + 1;

        if (baseJs) {
            // v8: base.js — no try-catch wrapping for cipher either
            return SETUP_CODE + '\n' +
                modified.substring(0, iifeCloseIdx) + '\n' +
                probeBody + '\n' +
                modified.substring(iifeCloseIdx);
        }

        var dfDecl = '';
        if (candidates && candidates.length > 0) {
            var dfNames = [];
            for (var i = 0; i < candidates.length; i++) dfNames.push('_cdf' + i);
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
