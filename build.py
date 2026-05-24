#!/usr/bin/env python3
"""
Dispatch HQ — Build Script
Usage: python3 build.py [--push] [--message "commit message"]

Compiles taxi-dispatcher.jsx → app-compiled.js → dispatch-hq.html
Optionally commits and pushes to GitHub (triggers auto-deploy).
"""

import subprocess, sys, os, re

ESBUILD = os.path.expanduser(
    "~/.npm-global/lib/node_modules/tsx/node_modules/esbuild/bin/esbuild"
)
JSX_SRC  = "taxi-dispatcher.jsx"
JSX_PREP = "app-for-compile.jsx"
JS_OUT   = "app-compiled.js"
HTML     = "dispatch-hq.html"

START_MARKER = "function runDispatchApp() {\n    // React loaded — run the app\n"
END_MARKER   = "\n  // Hide splash after React renders"

def step(msg): print(f"\n▶ {msg}")
def ok(msg):   print(f"  ✅ {msg}")
def fail(msg): print(f"  ❌ {msg}"); sys.exit(1)


# ── Step 1: Prep JSX ──
step("Preparing JSX for compile...")
with open(JSX_SRC) as f:
    jsx = f.read()

jsx = jsx.replace(
    'import { useState, useEffect, useCallback, useRef, useMemo } from "react";',
    'const { useState, useEffect, useCallback, useRef, useMemo } = React;'
)
jsx = jsx.replace(
    'export default function TaxiDispatcherApp()',
    'function TaxiDispatcherApp()'
)
jsx += '\nReactDOM.createRoot(document.getElementById("root")).render(React.createElement(TaxiDispatcherApp));\n'

with open(JSX_PREP, 'w') as f:
    f.write(jsx)
ok(f"Prepared {JSX_PREP}")


# ── Step 2: Compile ──
step("Compiling with esbuild...")
r = subprocess.run(
    [ESBUILD, JSX_PREP, "--jsx=transform", f"--outfile={JS_OUT}", "--target=es2018"],
    capture_output=True
)
err = r.stderr.decode('utf-8', errors='replace')
errors   = err.count('[ERROR]')
warnings = err.count('[WARNING]')

if r.returncode != 0 or errors > 0:
    print(err[:600])
    fail(f"esbuild failed: {errors} errors")
ok(f"Compiled — {errors} errors, {warnings} warnings")


# ── Step 3: Inject into HTML ──
step("Injecting compiled JS into dispatch-hq.html...")
with open(HTML) as f:
    h = f.read()
with open(JS_OUT) as f:
    js = f.read()

if START_MARKER not in h:
    fail(f"START marker not found in {HTML}")
if END_MARKER not in h:
    fail(f"END marker not found in {HTML}")

start_idx = h.index(START_MARKER) + len(START_MARKER)
end_idx   = h.index(END_MARKER)
new_html  = h[:start_idx] + js.replace('</script', '<\\/script') + h[end_idx:]

with open(HTML, 'w') as f:
    f.write(new_html)
ok(f"HTML updated — {len(new_html):,} bytes")


# ── Step 4: QA checks ──
step("Running quick QA...")
checks = {
    "No clearLocalSession":    'clearLocalSession' not in js,
    "No deviceBookings":       'deviceBookings' not in js,
    "authStatus gate":         'authStatus' in js,
    "bookedDrivers":           'bookedDrivers' in js,
    "TOWN_PRICES (hackensack)":'hackensack' in js,
    "priceCheckMode":          'priceCheckMode' in js,
    "autoFareLabel":           'autoFareLabel' in js,
    "React 18.2.0":            '18.2.0' in new_html,
}
all_ok = True
for name, passed in checks.items():
    print(f"  {'✅' if passed else '❌'} {name}")
    if not passed: all_ok = False

if not all_ok:
    fail("QA checks failed — fix issues before pushing")
ok("All QA checks passed")


# ── Step 5: Optional git push ──
push    = '--push' in sys.argv
message = "build: update dispatch-hq.html"
for i, arg in enumerate(sys.argv):
    if arg == '--message' and i+1 < len(sys.argv):
        message = sys.argv[i+1]

if push:
    step("Committing and pushing to GitHub...")
    subprocess.run(['git', 'add', HTML, JSX_SRC], check=True)
    result = subprocess.run(['git', 'commit', '-m', message], capture_output=True)
    if result.returncode != 0:
        out = result.stdout.decode()
        if 'nothing to commit' in out:
            ok("Nothing new to commit — already up to date")
        else:
            fail("git commit failed: " + out)
    else:
        ok(f"Committed: {message}")

    subprocess.run(['git', 'push'], check=True)
    ok("Pushed to GitHub — Actions will auto-deploy in ~60s")
    print(f"\n  🚀 Live at: https://capable-custard-36d377.netlify.app")
else:
    print(f"\n  💡 Run with --push to deploy: python3 build.py --push")

print("\n✅ Build complete\n")
