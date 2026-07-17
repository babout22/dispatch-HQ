---
name: dispatch-hq-dev
description: >
  Development workflow for Dispatch HQ — a bilingual (English/Korean) taxi dispatch
  booking PWA for NYC. Use whenever the user asks to build, edit, fix, add a feature,
  compile, deploy, or test Dispatch HQ. Triggers on: "update the app", "fix this bug",
  "change the driver logic", "update the GAS backend", "run QA", or any mention of
  taxi-dispatcher.jsx, dispatch-hq.html, or google-apps-script.js.
  After EVERY change: run the QA gate (Section 3). Never skip QA.
  Project FACTS (drivers, pricebook, data shapes, storage keys, GAS contract) live in
  CLAUDE.md — read it before editing code; do not duplicate facts into this skill.
---

# Dispatch HQ — Development Workflow

This file is the HOW. CLAUDE.md (repo root) is the WHAT — all project facts live
there and only there. If this file and CLAUDE.md disagree, CLAUDE.md wins on facts,
this file wins on process.

## 1. WORKFLOW

1. Read CLAUDE.md first — line numbers, data shapes, invariants.
2. Edit `taxi-dispatcher.jsx` only. NEVER hand-edit `dispatch-hq.html`.
3. Rebuild (Section 2). Zero errors AND zero warnings required.
4. Run the QA gate (Section 3). All assertions must pass.
5. Run runtime smoke (Section 4) — text checks alone miss runtime crashes
   (a Python `None` leak once shipped with a clean compile).
6. Deploy: `python3 build.py --push --message "..."` then redeploy
   dispatch-hq.html to Netlify (SW changes live in the HTML shell).

## 2. BUILD PIPELINE

```bash
python3 -c "
jsx = open('taxi-dispatcher.jsx').read()
jsx = jsx.replace('import { useState, useEffect, useCallback, useRef, useMemo } from \"react\";', 'const { useState, useEffect, useCallback, useRef, useMemo } = React;')
jsx = jsx.replace('export default function TaxiDispatcherApp()', 'function TaxiDispatcherApp()')
jsx += '\nReactDOM.createRoot(document.getElementById(\"root\")).render(React.createElement(TaxiDispatcherApp));\n'
open('app-for-compile.jsx', 'w').write(jsx)
"
esbuild app-for-compile.jsx --jsx=transform --outfile=app-compiled.js --target=es2018
```

Flags are immutable: `--target=es2018` (strips `?.`/`??`), `--jsx=transform`
(classic runtime), NO `--bundle` (React is a CDN global).

HTML injection markers:
- START: `function runDispatchApp() {\n    // React loaded — run the app\n`
- END:   `\n  // Hide splash after React renders`

Escape `</script` as `<\/script` when injecting.

## 3. QA GATE (run after EVERY change)

```python
import re, subprocess

with open('taxi-dispatcher.jsx') as f: c = f.read()
with open('dispatch-hq.html') as f: h = f.read()
with open('google-apps-script.js') as f: g = f.read()

# ── Compile: zero errors AND zero warnings ──
r = subprocess.run(['esbuild','app-for-compile.jsx','--jsx=transform',
    '--outfile=app-compiled.js','--target=es2018'], capture_output=True)
assert r.returncode == 0
assert r.stderr.decode().count('[ERROR]') == 0
assert r.stderr.decode().count('[WARNING]') == 0

# ── Secrets: SHAPE-based scan, not a hardcoded literal ──
# Catches ANY 25+ char token assigned to a credential-ish key, current or future.
assert not re.search(r'(authToken|token|apiKey|password)\s*[:=]\s*["\'][A-Za-z0-9+/_-]{25,}["\']', c)
assert 'authToken: ""' in c            # empty default; user sets in SYNC settings
assert not re.search(r'AIzaSy[A-Za-z0-9_-]{10,}', c + h)   # real Maps keys (placeholder "AIzaSy..." passes)

# ── TDZ order ──
def ln(t): return next(i for i,l in enumerate(c.split('\n')) if t in l)
assert ln('const [passphrase') < ln('const [syncStatus') < ln('const syncNow =') < ln('const [autoSyncEnabled')

# ── Security ──
assert 'eval(' not in c and 'dangerouslySetInnerHTML' not in c
assert not re.search(r'\balert\s*\(', c)
assert 'const esc = s =>' in c                       # print-slip XSS guard
assert 'hasOwnProperty' in g
assert '...' not in g.replace('// ...','')           # GAS V8: no spread
assert g.index('adminGetUsers') < g.index('if (!checkAuth')

# ── SHIP-HUNT INVARIANTS: these six fixes must never regress ──
assert not re.search(r':\s*None\b', c)               # 1. Python None leak (runtime crash)
assert 'AIRPORTS.includes(dAnchor)' in c             # 2. airport beats MHT as fare anchor
assert 'GENERIC' in c                                # 3. neighborhood beats generic borough key
assert re.search(r'if \(e === 0\) e = 24', c)        # 4. midnight shift-end = All-Day
assert 'mins(a.timeSlot) - mins(b.timeSlot)' in c    # 5. chronological sort (not localeCompare)
assert 'dispatch-hq-v2' in h and '"navigate"' in h or 'navigate' in h  # 6. SW network-first for document
assert '"8" + spoken.padStart(2, "0")' in c          # voice "driver 19" -> "819"
assert 'queuePendingDelete(deleteConfirmId)' in c    # 8. deletes tombstone to cloud (no zombies)
assert 'tombstones.has(b.id)' in c                   #    sync merge shielded from queued deletes
assert 'if (!w)' in c and 'Print blocked' in c       # 9. print popup null-guarded (iOS PWA)
assert 'normalizeSpokenNumbers(spoken)' in c         # 10. field mic normalizes numbers
assert 'today.getFullYear()' in c                    # 11. local todayStr (not UTC toISOString)
assert 'inSegment' in c                              # 12. town-segment beats street-name substring
assert 'modifiedAt: sanitize(b.modifiedAt' in c      # 13. reload preserves notes/status/modifiedAt
assert re.search(r'a\.length \+ b\.length\) >= 7', c) # 14. voice phone digit-merge
assert 'filters.shift === "allday"' in c             # 15. All-Day filter handled (24h partition)
assert 'PAGE_LIMIT' in g and 'Too many pages' in c   # 16. list pagination (server cap + client loop)
assert 'sanitize(fareData' in c                      # 17. fareBreakdown sanitized at write
assert 'actionPending' in c                          # 18. admin double-submit guard + timeouts
assert 'if (!townStr || !townStr.trim()) return null;' in c  # 19. empty address -> no phantom fare
assert 'maxLength = 200' in c and 'raw.length > 200' in c    # 19b. live input caps (Field + AddressField)
assert not re.search(r'^\s*(async|await|const|let|var|function)\s*$', c, re.M)  # 20. no dangling keywords (orphaned tokens are VALID syntax but crash at runtime)
assert "skipDivergenceCheck !== true" in c              # inv21 divergence guard strict-true (onClick passes event objects)
assert "removePendingDelete(undoBooking.id)" in c       # inv22 undo cancels tombstone + stamps modifiedAt
assert "isMobileDevice" in c                            # inv23 Face ID mobile-only (Windows Hello false-positive)
assert c.count("setPaymentManuallyEdited(true)") >= 2   # inv24 edit locks negotiated payment
assert "cancelIsRebook: editingBooking.cancelIsRebook" in c  # inv25 edit preserves cancel status
assert "bulkToDriver, modifiedAt" in c                  # inv26 ALL mutations stamp modifiedAt (cancel/restore/bulk)
# 20b. MANDATORY jsdom boot test: compile, then execute the FULL bundle with real
# React UMD in jsdom (runScripts outside-only) and assert #root renders >500 chars
# with zero uncaught errors. Compile-clean does NOT mean boot-clean: a bare
# identifier statement (e.g. orphaned 'async') compiles fine and crashes at startup.
# The shell's catch previously blamed the React CDN for such crashes — it now logs
# the real error and shows "App failed to start" instead.

# ── Features present ──
for token in ['cancelModal','bulkMode','CustomerHistoryView','TemplatesView',
              'custSuggestions','bookedDrivers','isAirportTrip','dupConfirmed',
              'NYC_CONGESTION_FEE','findNearbyTown','directMatch',
              'Payment ($ + tip)','TIP NOT INCLUDED','+tip',
              'ko-KR','KOR_DIGIT','normalizeSpokenNumbers','730','AES-GCM']:
    assert token in c, token

# ── HTML shell ──
assert '18.2.0' in h and '18.3.1' not in h
assert h.count('integrity="sha384-') >= 2
assert 'waitForReact' in h and 'serviceWorker' in h
```

## 4. RUNTIME SMOKE (node)

Text assertions can't catch runtime-only crashes. Extract and EXECUTE:

```python
# Extract TOWN_PRICES..lookupFlatRate block, run in node:
#   Object.keys(TOWN_PRICES).length          -> matches CLAUDE.md town count
#   lookupFlatRate("Midtown Manhattan","JFK") -> {fare: 87}
#   lookupFlatRate("Downtown Manhattan","JFK")-> {fare: 99}   (not 87)
#   lookupFlatRate("Port Washington","JFK")   -> {fare: 60}
#   lookupFlatRate("Unknown Town XYZ","JFK")  -> null (no throw)
# Extract isTimeInShift + formatTime24, verify:
#   ("2:00 AM","17:00","04:00") -> true   (overnight D50)
#   ("11:30 PM","04:00","00:00") -> true  (midnight-end D19)
#   ("9:00 AM" sorts before "10:00 AM" via the mins() comparator)
```

## 5. PROCESS RULES (the WHY behind the gate)

- jsx source import is stripped by the build script — never `import React`.
- `clearSession`, never `clearLocalSession` (removed).
- Driver IDs are 3-char strings ("808"); spoken "driver 19" maps to "819".
- `filteredBookings` excludes cancelled: `bookings.filter(b => !b.status)`.
- `handleBulkSelectAll` computes actives inline — referencing the
  `filteredBookings` useMemo there is a TDZ crash.
- All print-slip user fields go through `esc()`.
- GAS deploys need a NEW VERSION (Deploy → Manage → Edit → New version).
- After changing the HTML shell (SW, CDN, splash), bump the SW cache name.

## 6. HUMAN CHECKLISTS (do not duplicate here)

- `pre-deploy-checklist.md` — 8-minute manual pass before every Netlify deploy
- `qa-checklist.md` — full manual regression for major releases
The skill's QA gate is the automated superset; those files are for the human.
