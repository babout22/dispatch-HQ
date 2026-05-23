# CLAUDE.md — Dispatch HQ

Bilingual (English/Korean) taxi dispatch booking PWA for NYC.
Read this file before touching any code in this project.

---

## REPO MAP

```
dispatch-hq/
├── taxi-dispatcher.jsx          ← SOURCE (5,283 lines) — EDIT THIS
├── dispatch-hq.html             ← PRODUCTION BUILD — NEVER hand-edit, always regenerate
├── google-apps-script.js        ← GAS backend — paste into Apps Script (gitignored)
├── _headers                     ← Netlify security headers (COOP/COEP/CSP)
├── netlify.toml                 ← publish = ".", catch-all redirect
├── .github/workflows/deploy.yml ← GitHub Actions auto-deploy
├── CLAUDE.md                    ← This file
```

### Key Source Locations

```
L 278  const TOWN_PRICES = { ... }     // 130+ town pricebook (replaces FLAT_RATES)
L 495  function lookupFlatRate()
L 621  function executeFare()          // surcharges: EWR +$14/$54, pax x1.5/x2, RT x2
L 838  const DRIVERS = [ ... ]         // 22 real drivers, 3-digit IDs
L1255  function DispatcherApp()
L1257  const [priceCheckMode]          // price check mode state
L1301  const [customDrivers]           // driver management (NOT in IIFE)
L1542  const [passphrase]              // TDZ anchor
L1545  const [syncStatus]
L1613  const syncNow = useCallback()
L1721  const [autoSyncEnabled]         // MUST come after passphrase/syncStatus/syncNow
L1744  const [autoFareLabel]           // fare auto-fill label
L4223  function LoginPage()
L4397  function AdminDashboard()
L5018  function BookingSection()
L5054  function BookingCard()
L5283  export default function TaxiDispatcherApp()
```

---

## DEPLOYMENT — AUTO (GitHub Actions)

Push `dispatch-hq.html` to master → auto-deploys to Netlify in ~60s.
No manual deploy needed.

**Fallback only:**
```bash
cd C:\dispatch-hq
netlify deploy --prod --dir .
```

Live URL: https://capable-custard-36d377.netlify.app/
Netlify Site ID: 6303731e-02f6-4a6d-97a2-77b1ac626ee1

---

## BUILD COMMAND

```bash
python3 -c "
jsx = open('taxi-dispatcher.jsx').read()
jsx = jsx.replace('import { useState, useEffect, useCallback, useRef, useMemo } from \"react\";', 'const { useState, useEffect, useCallback, useRef, useMemo } = React;')
jsx = jsx.replace('export default function TaxiDispatcherApp()', 'function TaxiDispatcherApp()')
jsx += '\nReactDOM.createRoot(document.getElementById(\"root\"'
jsx += ')).render(React.createElement(TaxiDispatcherApp));\n'
open('app-for-compile.jsx', 'w').write(jsx)
"
esbuild app-for-compile.jsx --jsx=transform --outfile=app-compiled.js --target=es2018
```

HTML Injection Markers:
- START: `function runDispatchApp() {\n    // React loaded — run the app\n`
- END: `\n  // Hide splash after React renders`

---

## ARCHITECTURE RULES

### Auth — password hashing (CRITICAL)
```javascript
// Client: SHA-256(password + "dispatch-hq-client-salt")  ← EXACT
// NOT: SHA-256(salt + password + "dispatch-hq-2024")      ← WRONG (removed)
```
- clearLocalSession REMOVED — use clearSession
- deviceBookings / DevicePassphraseGate REMOVED — Option C permanent

### Temporal Dead Zone — NEVER reorder
```
priceCheckMode (L1257) → customDrivers (L1301) → passphrase (L1542)
→ syncStatus (L1545) → syncNow (L1613) → autoSync (L1721)
```

### GAS Rules
- All POST: Content-Type: text/plain
- No spread operators in GAS
- adminGetUsers BEFORE checkAuth gate in doGet
- adminGetUsers must include &token= alongside &sessionToken=

### Driver Management — state in DispatcherApp (NOT IIFE)
```javascript
const [customDrivers, setCustomDrivers] = useState(...)  // L1301
const [showAddDriver, setShowAddDriver] = useState(false) // L1304
```

---

## DESIGN SYSTEM — Seoul Noir

```css
--bg-0: #06070d  --bg-1: #0b0d18  --bg-2: #111428
--amber: #f5a623  --slate: #a8b4cc  --white: #f2f0fa
--mono: 'Overpass Mono'   --sans: 'Noto Sans KR'   --display: 'Bebas Neue'
```

---

## DRIVERS (22 real, 3-digit IDs)

```
NYC: 808 KANG K Y, 810 SUK, 811 PARK L B, 817 KIM K O, 819 KANG H D,
     820 KANG KJ, 830 KIM JAMES, 833 KWON S H, 835 YUN G J, 837 KIM Y S,
     845 NO N I, 850 KANG D R, 855 KIM B S, 857 SEO H G, 860 HAN S H,
     877 YI BOB, 887 YUN J K, 888 PARK J G, 895 LEE S I
NJ (24hrs): 100 YOO S H, 500 SONG K Y, 802 OH N S
```

Driver IDs: always 3-char strings — "808" not 8 — padStart(3,"0")

---

## GAS API CONTRACT

```
GET  ?action=adminGetUsers&token=AUTH_TOKEN&sessionToken=TOKEN  ← both required
POST { action:"resetPassword", targetUsername, newPasswordHash, sessionToken }
```

Backend: https://script.google.com/macros/s/AKfycbzRFmi7dn8yy_u6m0YCz7YCHt-_-PNm6VHOVdOMixf_vMBq0SF3lWg1sEQhwWI2J8I-/exec
Token: kX9mP2vQ8nL5wR3jF7tY4cH6dA1sE0bN

---

## COMMON MISTAKES

| Wrong | Correct |
|-------|---------|
| SHA-256(salt+password+"2024") | SHA-256(password+"dispatch-hq-client-salt") |
| clearLocalSession() | clearSession() |
| deviceBookings state | Removed permanently |
| React.useState in driver IIFE | State in DispatcherApp L1301 |
| adminGetUsers without &token= | Must include &token=AUTH_TOKEN |
| padStart(2,"0") for driver IDs | padStart(3,"0") |
| FLAT_RATES | TOWN_PRICES |
| saveMapsKey in Admin | saveAdminMapsKey |
| Manual Netlify deploy | git push to master |

---

## KNOWN LIMITATIONS

1. Admin settings IIFE — 7 React.useState calls. Works. Don't fix without request.
2. localStorage plaintext — Option C permanent.
3. AI flight lookup disabled on website (CORS). FlightAware fallback shown.
4. Admin hash requires GAS console generateAdminHash().
5. google-apps-script.js gitignored — paste manually into Apps Script when changed.
