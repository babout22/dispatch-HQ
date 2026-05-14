#!/usr/bin/env python3
"""Build script: JSX transform -> esbuild -> inject into dispatch-hq.html"""
import subprocess
import sys

# Step 1: Transform JSX (strip React import, strip export default)
jsx = open("taxi-dispatcher.jsx", encoding="utf-8").read()
jsx = jsx.replace(
    'import { useState, useEffect, useCallback, useRef, useMemo } from "react";',
    'const { useState, useEffect, useCallback, useRef, useMemo } = React;'
)
jsx = jsx.replace("export default function TaxiDispatcherApp()", "function TaxiDispatcherApp()")
jsx += '\nReactDOM.createRoot(document.getElementById("root"'
jsx += ')).render(React.createElement(TaxiDispatcherApp));\n'
open("app-for-compile.jsx", "w", encoding="utf-8").write(jsx)
print("JSX transformation done.")

# Step 2: Compile with esbuild (via local node_modules after npm ci)
result = subprocess.run(
    ["npx", "esbuild", "app-for-compile.jsx",
     "--jsx=transform", "--outfile=app-compiled.js", "--target=es2018"],
    capture_output=True, text=True
)
if result.returncode != 0:
    print("esbuild FAILED:\n" + result.stderr)
    sys.exit(1)
print("esbuild compilation done.")

# Step 3: Inject compiled JS into dispatch-hq.html between the two markers
compiled = open("app-compiled.js", encoding="utf-8").read()
html = open("dispatch-hq.html", encoding="utf-8").read()

START = "    // React loaded — run the app\n"
END = "\n    setTimeout(function() { var s = document.getElementById(\"splash\")"

start_idx = html.find(START)
end_idx = html.find(END)

if start_idx == -1 or end_idx == -1:
    print("ERROR: injection markers not found in dispatch-hq.html")
    sys.exit(1)

insert_at = start_idx + len(START)
new_html = html[:insert_at] + compiled + html[end_idx:]
open("dispatch-hq.html", "w", encoding="utf-8").write(new_html)
print("Injection done. Build complete -> dispatch-hq.html")
