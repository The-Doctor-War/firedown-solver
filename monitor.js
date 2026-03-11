#!/usr/bin/env node
// =============================================================================
// YouTube Solver Monitor Bot
// Runs periodically (cron/GitHub Actions), tests current solver against
// the latest YouTube TV player. If the solver fails, uses Claude API to
// debug and generate a fix, then pushes to GitHub.
// =============================================================================
//
// Setup:
//   npm install node-fetch @anthropic-ai/sdk
//
// Environment variables:
//   ANTHROPIC_API_KEY  — Claude API key
//   GITHUB_TOKEN       — GitHub PAT with repo write access
//   GITHUB_REPO        — e.g. "solarizeddev/firedown-solver"
//   DISCORD_WEBHOOK    — (optional) Discord webhook URL for notifications
//
// Usage:
//   node monitor.js              # run once
//   node monitor.js --dry-run    # test without pushing
//
// Cron (every 3 hours):
//   0 */3 * * * cd /path/to/bot && node monitor.js >> monitor.log 2>&1
//
// GitHub Actions: see .github/workflows/monitor.yml in the repo
// =============================================================================

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY;
const GITHUB_TOKEN = process.env.GITHUB_TOKEN;
const GITHUB_REPO = process.env.GITHUB_REPO || 'solarizeddev/firedown-solver';
const DISCORD_WEBHOOK = process.env.DISCORD_WEBHOOK || '';
const DRY_RUN = process.argv.includes('--dry-run');
const MAX_FIX_ATTEMPTS = 5;

const PLAYER_VARIANTS = ['tv', 'tv_es6'];
const PLAYER_BASE_URL = 'https://www.youtube.com/s/player';
const TV_PLAYER_PATH = 'tv-player-ias.vflset/tv-player-ias.js';
const TV_ES6_PLAYER_PATH = 'tv-player-ias_es6.vflset/tv-player-ias_es6.js';

// =============================================================================
// HELPERS
// =============================================================================

function log(msg) {
    const ts = new Date().toISOString().replace('T', ' ').substring(0, 19);
    console.log(`[${ts}] ${msg}`);
}

async function fetchText(url) {
    const resp = await fetch(url);
    if (!resp.ok) throw new Error(`HTTP ${resp.status} for ${url}`);
    return resp.text();
}

async function notify(message) {
    log(message);
    if (!DISCORD_WEBHOOK) return;
    try {
        await fetch(DISCORD_WEBHOOK, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ content: `🔧 **Solver Monitor**: ${message}` })
        });
    } catch (e) {
        log(`Discord notification failed: ${e.message}`);
    }
}

// =============================================================================
// STEP 1: Discover current YouTube player version
// =============================================================================

async function discoverPlayerVersion() {
    log('Discovering current player version...');
    const html = await fetchText('https://www.youtube.com');
    const match = html.match(/"jsUrl":"[^"]*\/player\/([a-zA-Z0-9]+)\//);
    if (!match) throw new Error('Could not find player version in YouTube HTML');
    return match[1];
}

async function fetchPlayer(version) {
    const url = `${PLAYER_BASE_URL}/${version}/${TV_PLAYER_PATH}`;
    log(`Fetching TV player: ${url}`);
    const source = await fetchText(url);
    if (source.length < 10000) throw new Error('Player source too small');
    return source;
}

// =============================================================================
// STEP 2: Test current solver against the player
// =============================================================================

function testSolver(solverCode, playerSource) {
    // Build the test script
    const testScript = `
        ${solverCode}
        var data = ${JSON.stringify(playerSource)};
        var code = preprocessPlayer(data, null);
        var _result = { n: null, sig: null };
        try {
            Function("_result", code)(_result);
        } catch(e) {
            _result._error = e.message;
        }
        _result;
    `;

    try {
        const result = new Function(testScript)();
        return {
            success: !!result.n,
            funcName: result._nName || null,
            error: result._error || null,
        };
    } catch (e) {
        return { success: false, funcName: null, error: e.message };
    }
}

function testSolverWithTransform(solverCode, playerSource) {
    const result = testSolver(solverCode, playerSource);
    if (!result.success) return result;

    // Verify the n-function actually transforms strings
    try {
        const testScript = `
            ${solverCode}
            var data = ${JSON.stringify(playerSource)};
            var code = preprocessPlayer(data, null);
            var _result = { n: null };
            Function("_result", code)(_result);
            var out1 = _result.n("ABCDEFGHabcdefg1");
            var out2 = _result.n("ZYXWVUTS98765432");
            ({ out1, out2, same: out1 === out2 });
        `;
        const transformResult = new Function(testScript)();
        if (!transformResult.out1 || transformResult.same) {
            return { success: false, funcName: result.funcName, error: 'Transform produces identical or null output' };
        }
        return { ...result, transform: transformResult };
    } catch (e) {
        return { success: false, funcName: result.funcName, error: `Transform test failed: ${e.message}` };
    }
}

// =============================================================================
// STEP 3: Use Claude API to fix the solver
// =============================================================================

async function askClaude(messages) {
    const resp = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'x-api-key': ANTHROPIC_API_KEY,
            'anthropic-version': '2023-06-01',
        },
        body: JSON.stringify({
            model: 'claude-sonnet-4-20250514',
            max_tokens: 16000,
            messages,
        })
    });
    if (!resp.ok) {
        const err = await resp.text();
        throw new Error(`Claude API error: ${resp.status} ${err}`);
    }
    const data = await resp.json();
    return data.content.map(b => b.text || '').join('');
}

function buildFixPrompt(solverCode, playerSource, testResult, attempt) {
    // Truncate player source to first 30KB (where candidates live)
    const playerExcerpt = playerSource.substring(0, 30000);

    return [
        {
            role: 'user',
            content: `You are maintaining a YouTube n-parameter solver for the Firedown browser.

The solver extracts and solves YouTube's n-parameter obfuscation by:
1. Finding a string table in the first 2KB (var X="...".split("D") or array literal)
2. Finding candidate dispatch functions with TABLE[VAR^NUM] XOR accesses in first 30KB
3. Injecting _df capture vars via comma injection inside var chains
4. Wrapping the IIFE body in try-catch
5. Probing each candidate with test params behaviorally

The current solver (v${solverCode.match(/SOLVER_VERSION\s*=\s*(\d+)/)?.[1] || '?'}) is FAILING on a new player version.

Test result:
- success: ${testResult.success}
- error: ${testResult.error || 'none'}
- funcName: ${testResult.funcName || 'none'}

Current solver.js:
\`\`\`javascript
${solverCode}
\`\`\`

First 30KB of the failing player.js:
\`\`\`javascript
${playerExcerpt}
\`\`\`

This is fix attempt ${attempt}/${MAX_FIX_ATTEMPTS}.

Analyze why the solver fails on this player and provide a COMPLETE fixed solver.js.
Return ONLY the JavaScript code, no explanations. The code must:
- Keep SOLVER_VERSION as a var at the top (bump the number)
- Keep the preprocessPlayer(data, solvedCache) function signature
- Work with all previous player formats (split with ; } { delimiters, array literals)
- Handle this new player format`
        }
    ];
}

async function attemptFix(solverCode, playerSource, testResult) {
    const conversation = [];

    for (let attempt = 1; attempt <= MAX_FIX_ATTEMPTS; attempt++) {
        log(`Fix attempt ${attempt}/${MAX_FIX_ATTEMPTS}...`);

        if (attempt === 1) {
            conversation.push(...buildFixPrompt(solverCode, playerSource, testResult, attempt));
        } else {
            conversation.push({
                role: 'user',
                content: `That fix didn't work. New test result:
- success: ${testResult.success}
- error: ${testResult.error || 'none'}

Please analyze the error and provide a corrected COMPLETE solver.js.
Return ONLY the JavaScript code.`
            });
        }

        const response = await askClaude(conversation);
        conversation.push({ role: 'assistant', content: response });

        // Extract code from response
        let newSolverCode = response;
        const codeMatch = response.match(/```(?:javascript|js)?\n([\s\S]+?)```/);
        if (codeMatch) newSolverCode = codeMatch[1];

        // Validate it has required exports
        if (!newSolverCode.includes('SOLVER_VERSION') || !newSolverCode.includes('preprocessPlayer')) {
            log('Invalid response — missing required functions');
            testResult = { success: false, error: 'Response missing SOLVER_VERSION or preprocessPlayer' };
            continue;
        }

        // Test the new solver
        testResult = testSolverWithTransform(newSolverCode, playerSource);
        log(`Attempt ${attempt} result: ${testResult.success ? 'SUCCESS' : 'FAIL'} — ${testResult.error || testResult.funcName}`);

        if (testResult.success) {
            return { code: newSolverCode, attempts: attempt };
        }
    }

    return null; // All attempts failed
}

// =============================================================================
// STEP 4: Push fix to GitHub
// =============================================================================

async function pushToGitHub(newSolverCode, version, oldVersion) {
    if (DRY_RUN) {
        log('DRY RUN — would push solver update to GitHub');
        fs.writeFileSync('/tmp/solver_fix.js', newSolverCode);
        log('Fix written to /tmp/solver_fix.js');
        return;
    }

    const apiBase = `https://api.github.com/repos/${GITHUB_REPO}`;
    const headers = {
        'Authorization': `Bearer ${GITHUB_TOKEN}`,
        'Content-Type': 'application/json',
        'Accept': 'application/vnd.github.v3+json',
    };

    // Get current file SHA
    const fileResp = await fetch(`${apiBase}/contents/solver.js`, { headers });
    const fileData = await fileResp.json();
    const sha = fileData.sha;

    // Update file
    const updateResp = await fetch(`${apiBase}/contents/solver.js`, {
        method: 'PUT',
        headers,
        body: JSON.stringify({
            message: `fix: update solver for player ${version} (auto-fix)`,
            content: Buffer.from(newSolverCode).toString('base64'),
            sha,
        })
    });

    if (!updateResp.ok) {
        const err = await updateResp.text();
        throw new Error(`GitHub push failed: ${err}`);
    }

    log('Pushed solver update to GitHub');
}

// =============================================================================
// STEP 5: State tracking — remember last tested version
// =============================================================================

const STATE_FILE = path.join(__dirname, '.monitor-state.json');

function loadState() {
    try {
        return JSON.parse(fs.readFileSync(STATE_FILE, 'utf8'));
    } catch {
        return { lastVersion: null, lastCheck: null, failures: [] };
    }
}

function saveState(state) {
    fs.writeFileSync(STATE_FILE, JSON.stringify(state, null, 2));
}

// =============================================================================
// MAIN
// =============================================================================

async function main() {
    log('=== Solver Monitor Start ===');

    if (!ANTHROPIC_API_KEY) {
        log('ERROR: ANTHROPIC_API_KEY not set');
        process.exit(1);
    }

    const state = loadState();

    // 1. Discover current player version
    let version;
    try {
        version = await discoverPlayerVersion();
        log(`Current player version: ${version}`);
    } catch (e) {
        log(`Failed to discover player version: ${e.message}`);
        process.exit(1);
    }

    // 2. Fetch player source
    let playerSource;
    try {
        playerSource = await fetchPlayer(version);
        log(`Player fetched: ${Math.round(playerSource.length / 1024)}KB`);
    } catch (e) {
        log(`Failed to fetch player: ${e.message}`);
        process.exit(1);
    }

    // 3. Fetch current solver from GitHub
    let solverCode;
    try {
        const rawUrl = `https://raw.githubusercontent.com/${GITHUB_REPO}/main/solver.js`;
        solverCode = await fetchText(rawUrl);
        const solverVersion = solverCode.match(/SOLVER_VERSION\s*=\s*(\d+)/)?.[1];
        log(`Current solver: v${solverVersion}`);
    } catch (e) {
        log(`Failed to fetch solver: ${e.message}`);
        process.exit(1);
    }

    // 4. Test solver against player
    const testResult = testSolverWithTransform(solverCode, playerSource);
    log(`Test result: ${testResult.success ? 'PASS' : 'FAIL'} — ${testResult.error || testResult.funcName}`);

    if (testResult.success) {
        log(`Solver works for player ${version}`);
        state.lastVersion = version;
        state.lastCheck = new Date().toISOString();
        saveState(state);

        if (state.lastVersion !== version) {
            await notify(`✅ Solver works with new player \`${version}\` — ${testResult.funcName}`);
        }
        return;
    }

    // 5. Solver failed — attempt auto-fix
    await notify(`❌ Solver FAILED on player \`${version}\`: ${testResult.error}`);

    log('Attempting auto-fix via Claude API...');
    const fix = await attemptFix(solverCode, playerSource, testResult);

    if (!fix) {
        await notify(`🚨 Auto-fix FAILED after ${MAX_FIX_ATTEMPTS} attempts for player \`${version}\`. Manual intervention needed.`);
        state.failures.push({ version, date: new Date().toISOString(), error: testResult.error });
        saveState(state);
        process.exit(1);
    }

    // 6. Push fix
    log(`Fix found in ${fix.attempts} attempt(s). Pushing...`);
    try {
        await pushToGitHub(fix.code, version, state.lastVersion);
        await notify(`✅ Auto-fixed solver for player \`${version}\` (${fix.attempts} attempt(s)). Pushed to GitHub.`);
        state.lastVersion = version;
        state.lastCheck = new Date().toISOString();
        saveState(state);
    } catch (e) {
        await notify(`🚨 Fix found but GitHub push failed: ${e.message}`);
        // Save the fix locally
        fs.writeFileSync('/tmp/solver_fix.js', fix.code);
        log('Fix saved to /tmp/solver_fix.js');
        process.exit(1);
    }

    log('=== Monitor Complete ===');
}

main().catch(e => {
    log(`Fatal error: ${e.message}`);
    process.exit(1);
});
