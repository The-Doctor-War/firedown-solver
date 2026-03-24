// =============================================================================
// YouTube Signature Cipher Decryptor — Remote Module v1
// Hosted at: https://github.com/solarizeddev/firedown-solver
// The background.js shell fetches, caches, and executes this module.
//
// YouTube's signatureCipher format:
//   s=SCRAMBLED_SIG&sp=sig&url=BASE_URL
//
// The 's' value is decrypted using a function chain extracted from player JS.
// The chain is composed of simple array operations on the signature characters:
//   - reverse: reverse the array
//   - splice: remove first N elements
//   - swap: swap first element with element at index N
//
// Once decrypted, the signature is appended to the URL as &sig=DECRYPTED
// (or &sp_value=DECRYPTED if sp param is not "sig").
// =============================================================================
var CIPHER_VERSION = 1;

/**
 * Parse a signatureCipher query string into its components.
 * Format: s=SCRAMBLED&sp=sig&url=https://...
 *
 * @param {string} cipherString - The signatureCipher field value
 * @returns {{ s: string, sp: string, url: string } | null}
 */
function parseSignatureCipher(cipherString) {
    if (!cipherString) return null;
    try {
        var params = {};
        var parts = cipherString.split("&");
        for (var i = 0; i < parts.length; i++) {
            var eq = parts[i].indexOf("=");
            if (eq > 0) {
                var key = decodeURIComponent(parts[i].substring(0, eq));
                var val = decodeURIComponent(parts[i].substring(eq + 1));
                params[key] = val;
            }
        }
        if (!params.s || !params.url) return null;
        return {
            s: params.s,
            sp: params.sp || "sig",
            url: params.url
        };
    } catch (e) {
        return null;
    }
}

/**
 * Extract the initial signature manipulation function from player JS.
 *
 * YouTube's player contains a pattern like:
 *   var Xy={
 *     wG:function(a){a.reverse()},
 *     fr:function(a,b){a.splice(0,b)},
 *     Xz:function(a,b){var c=a[0];a[0]=a[b%a.length];a[b%a.length]=c}
 *   };
 *
 * And a dispatcher function like:
 *   function Tza(a){
 *     a=a.split("");
 *     Xy.Xz(a,20);
 *     Xy.wG(a,67);
 *     Xy.fr(a,3);
 *     Xy.Xz(a,36);
 *     return a.join("")
 *   }
 *
 * We need to:
 * 1. Find the dispatcher function (identified by: split("") ... join(""))
 * 2. Extract the helper object name and its method definitions
 * 3. Map each method to an operation type (reverse, splice, swap)
 * 4. Build the ordered operation chain
 *
 * @param {string} playerSource - Full player.js source
 * @returns {{ operations: Array<{op: string, arg: number}> } | null}
 */
function extractCipherOperations(playerSource) {
    // =========================================================================
    // Step 1: Find the signature decryption dispatcher function
    // Pattern: function XX(a){a=a.split("");OBJ.method(a,N);...;return a.join("")}
    // =========================================================================

    // Match function that splits a string, calls methods on it, and joins
    // The function may be declared as:
    //   function Tza(a){...}         — named function declaration
    //   var Tza=function(a){...}     — var assignment
    var dispatcherRx = /(?:function\s+([a-zA-Z_$][\w$]*)\s*\(a\)\{a=a\.split\(""\);([^}]+);return a\.join\(""\)\}|([a-zA-Z_$][\w$]*)=function\s*\(a\)\{a=a\.split\(""\);([^}]+);return a\.join\(""\)\})/g;
    var dm;
    var dispatcherBody = null;
    var dispatcherName = null;

    while ((dm = dispatcherRx.exec(playerSource)) !== null) {
        dispatcherName = dm[1] || dm[3];
        dispatcherBody = dm[2] || dm[4];
        // Validate: the body should contain at least 2 method calls (real sig
        // functions have 3-6 operations). Skip trivial matches.
        if (dispatcherBody && (dispatcherBody.match(/\./g) || []).length >= 2) {
            break;
        }
        dispatcherBody = null;
    }

    if (!dispatcherBody) return null;

    // =========================================================================
    // Step 2: Extract the helper object name from the dispatcher body
    // The body looks like: "Xy.Xz(a,20);Xy.wG(a,67);Xy.fr(a,3);Xy.Xz(a,36)"
    // All calls reference the same object, so grab the first one.
    // =========================================================================

    var callMatch = dispatcherBody.match(/([a-zA-Z_$][\w$]*)\.\w+\(a/);
    if (!callMatch) return null;
    var helperObjName = callMatch[1];

    // =========================================================================
    // Step 3: Find the helper object definition and extract methods
    // Pattern: var Xy={method1:function(a,b){...},method2:function(a){...},...};
    //
    // We need to handle the escaped object name in regex and find the block.
    // =========================================================================

    var escapedObj = helperObjName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    // Match: var ObjName={...}; — but the object may span multiple lines
    // Use a non-greedy search from the var declaration to find the matching }
    var objDefRx = new RegExp("(?:var\\s+)?" + escapedObj + "\\s*=\\s*\\{");
    var objMatch = objDefRx.exec(playerSource);
    if (!objMatch) return null;

    // Find the matching closing brace for the object literal
    var objStart = objMatch.index + objMatch[0].length - 1; // position of {
    var depth = 0;
    var pos = objStart;
    while (pos < playerSource.length) {
        if (playerSource[pos] === "{") depth++;
        else if (playerSource[pos] === "}") {
            depth--;
            if (depth === 0) break;
        }
        pos++;
    }
    var objBody = playerSource.substring(objStart + 1, pos);

    // =========================================================================
    // Step 4: Parse each method definition to determine its operation type
    //
    // Three operation types exist:
    //   reverse: function(a){a.reverse()}
    //   splice:  function(a,b){a.splice(0,b)}
    //   swap:    function(a,b){var c=a[0];a[0]=a[b%a.length];a[b%a.length]=c}
    //
    // We identify by checking for .reverse(), .splice(, or a[0] swap pattern.
    // =========================================================================

    var methodMap = {}; // methodName -> "reverse" | "splice" | "swap"

    // Match method definitions: methodName:function(a){...} or methodName:function(a,b){...}
    var methodRx = /([a-zA-Z_$][\w$]*)\s*:\s*function\s*\([^)]*\)\s*\{([^}]*(?:\{[^}]*\}[^}]*)*)\}/g;
    var mm;
    while ((mm = methodRx.exec(objBody)) !== null) {
        var methodName = mm[1];
        var methodBody = mm[2];

        if (methodBody.indexOf(".reverse()") !== -1) {
            methodMap[methodName] = "reverse";
        } else if (methodBody.indexOf(".splice(") !== -1) {
            methodMap[methodName] = "splice";
        } else if (methodBody.indexOf("a[0]") !== -1 || methodBody.indexOf("%a.length") !== -1) {
            methodMap[methodName] = "swap";
        }
    }

    if (Object.keys(methodMap).length === 0) return null;

    // =========================================================================
    // Step 5: Parse the dispatcher body to build the ordered operation chain
    // Each call looks like: Xy.Xz(a,20) or Xy.wG(a,67) or Xy.wG(a)
    // =========================================================================

    var operations = [];
    var callRx = new RegExp(escapedObj + "\\.([a-zA-Z_$][\\w$]*)\\(a(?:,(\\d+))?\\)", "g");
    var cm;
    while ((cm = callRx.exec(dispatcherBody)) !== null) {
        var method = cm[1];
        var arg = cm[2] ? parseInt(cm[2], 10) : 0;
        var op = methodMap[method];
        if (!op) {
            // Unknown method — can't safely decrypt
            return null;
        }
        operations.push({ op: op, arg: arg });
    }

    if (operations.length === 0) return null;

    return { operations: operations, dispatcherName: dispatcherName || "unknown" };
}

/**
 * Apply the cipher operation chain to decrypt a scrambled signature.
 *
 * @param {string} scrambled - The 's' value from signatureCipher
 * @param {Array<{op: string, arg: number}>} operations - From extractCipherOperations
 * @returns {string} - Decrypted signature
 */
function decryptSignature(scrambled, operations) {
    var a = scrambled.split("");
    for (var i = 0; i < operations.length; i++) {
        var step = operations[i];
        switch (step.op) {
            case "reverse":
                a.reverse();
                break;
            case "splice":
                a.splice(0, step.arg);
                break;
            case "swap":
                var idx = step.arg % a.length;
                var c = a[0];
                a[0] = a[idx];
                a[idx] = c;
                break;
        }
    }
    return a.join("");
}

/**
 * Build a playable URL from a signatureCipher format entry.
 *
 * @param {string} cipherString - The signatureCipher field value
 * @param {Array<{op: string, arg: number}>} operations - From extractCipherOperations
 * @returns {string|null} - Full playable URL with decrypted signature appended
 */
function buildCipherUrl(cipherString, operations) {
    var parsed = parseSignatureCipher(cipherString);
    if (!parsed) return null;

    var decrypted = decryptSignature(parsed.s, operations);
    if (!decrypted) return null;

    // Append the decrypted signature to the URL
    // YouTube uses &sp=sig (or another param name specified by 'sp')
    var separator = parsed.url.indexOf("?") !== -1 ? "&" : "?";
    return parsed.url + separator + encodeURIComponent(parsed.sp) + "=" + encodeURIComponent(decrypted);
}

/**
 * Main entry point — extract cipher operations from player source.
 * Called by background.js with the same player source used for the n-param solver.
 *
 * @param {string} playerSource - Full player.js source
 * @returns {{ operations: Array<{op: string, arg: number}>, dispatcherName: string } | null}
 */
function preprocessCipher(playerSource) {
    return extractCipherOperations(playerSource);
}
