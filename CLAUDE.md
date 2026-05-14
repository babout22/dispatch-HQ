# CLAUDE.md — Dispatch HQ

Bilingual (English/Korean) taxi dispatch booking PWA for NYC.
Read this file before touching any code in this project.

---

## REPO MAP

```
dispatch-hq/
├── taxi-dispatcher.jsx       ← SOURCE (4890 lines) — EDIT THIS
├── dispatch-hq.html          ← PRODUCTION BUILD — NEVER hand-edit, always regenerate
├── google-apps-script.js     ← GAS backend — paste into Apps Script
├── _headers                  ← Netlify security headers (COOP/COEP/CSP)
├── CLAUDE.md                 ← This file
├── .cursorrules              ← Cursor IDE rules
└── CURSOR_CONTEXT.md         ← Cursor narrative context
```

### Source File — Top-Level Declarations

```
L   7  const AUTH_ACCOUNTS_KEY  = "dispatch-hq-accounts";
L   8  const AUTH_SESSION_KEY   = "dispatch-hq-session";
L   9  const ADMIN_EMAIL        = "admin";          // login username fo
L  12  async function hashPassword(password, salt) {
L  19  function generateId() {
L  34  function sanitize(str, maxLen = 200) {
L  38  function sanitizePhone(str) {
L  42  function sanitizeNumeric(str) {
L  49  function sanitizeInteger(str, min, max) {
L  57  function sanitizeDriverId(str) {
L  61  function sanitizeErrorMsg(err) {
L  71  function isStandaloneMode() {
L  75  function generateSecureId() {
L  82  const CryptoService = {
L 148  const SyncService = {
L 238  const SYNC_CONFIG_KEY = "dispatch-hq-sync-config";
L 239  function loadSyncConfig() {
L 253  function saveSyncConfig(config) {
L 257  const MAPS_KEY_STORAGE = "dispatch-hq-maps-key";
L 258  function loadMapsKey() { try { return localStorage.getItem(MAPS_K
L 259  function saveMapsKey(k) { try { if (k) localStorage.setItem(MAPS_
L 264  function ensureMapsLoaded(apiKey, cb) {
L 277  const FLAT_RATES = [
L 332  function normalizeLocation(text) {
L 360  function getSubZone(text) {
L 375  function lookupFlatRate(pickup, dropoff) {
L 422  const TOOL_DEFINITIONS = [
L 453  async function executeToolCall(toolName, toolInput) {
L 463  function executeFare(input) {
L 490  async function executeFlight(input) {
L 543  async function runAIAssist(flightNumber, airline, city, date, pic
L 656  const DRIVERS = [
L 678  const DAYS = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursd
L 679  const AM_SLOTS = ["4:00 AM","4:30 AM","5:00 AM","5:30 AM","6:00 A
L 680  const PM_SLOTS = ["12:00 PM","12:30 PM","1:00 PM","1:30 PM","2:00
L 682  function getDriverShift(driver, date) {
L 702  function getShiftLabel(driver) {
L 710  function formatTime24(t) {
L 718  function formatShiftDisplay(start, end) {
L 730  function isTimeInShift(slot12h, shiftStart, shiftEnd) {
L 742  const INIT_FORM = { customerName: "", pickupAddress: "", dropoffA
L 745  const STORAGE_KEY     = "taxi-bookings-data";      // plaintext (
L 746  const ENC_STORAGE_KEY = "taxi-bookings-enc";       // encrypted (
L 747  const ENC_SALT_KEY    = "taxi-bookings-salt";      // PBKDF2 salt
L 750  async function loadBookingsEncrypted(passphrase) {
L 783  async function saveBookingsEncrypted(bookings, passphrase) {
L 792  const REQUIRED_BOOKING_FIELDS = ["id","customerName","date","time
L 794  function isValidBooking(b) {
L 802  function loadBookings() {
L 832  function saveBookings(bookings) {
L 850  const BACKUP_PREFIX = "dispatch-hq-backup-";
L 851  const BACKUP_LOG_KEY = "dispatch-hq-backup-log";
L 852  const MAX_SNAPSHOTS = 5; // Keep last 5 auto-snapshots
L 854  const BackupService = {
L1067  function DispatcherApp({ session, onLogout }) {
L3872  function LoginPage({ endpointUrl: initialEndpointUrl, onLogin, on
L4041  function AdminDashboard({ currentUser, endpointUrl, onSignOut }) 
L4313  function normalizeSpokenNumbers(text) {
L4460  function DevicePassphraseGate({ onUnlocked, isFirstTime }) {
L4540  function Field({ label, value, onChange, type = "text", full, hig
L4549  function AddressField({ label, value, onChange, highlight, mapsRe
L4787  function Badge({ label, ok, neutral }) {
L4795  function BookingSection({ title, bookings, onEdit, onDelete }) {
L4828  function BookingCard({ booking: b, onEdit, onDelete, isCluster })
L4887  export default function TaxiDispatcherApp() {
```

---

## BUILD COMMAND

Run after **every** change to `taxi-dispatcher.jsx`:

```bash
python3 -c "
jsx = open('taxi-dispatcher.jsx').read()
jsx = jsx.replace(
    'import { useState, useEffect, useCallback, useRef, useMemo } from \"react\";',
    'const { useState, useEffect, useCallback, useRef, useMemo } = React;'
)
jsx = jsx.replace('export default function TaxiDispatcherApp()', 'function TaxiDispatcherApp()')
jsx += '\nReactDOM.createRoot(document.getElementById(\"root\"'
jsx += ')).render(React.createElement(TaxiDispatcherApp));\n'
open('app-for-compile.jsx', 'w').write(jsx)
"

esbuild app-for-compile.jsx \
  --jsx=transform \
  --outfile=app-compiled.js \
  --target=es2018
```

Then inject `app-compiled.js` into `dispatch-hq.html` between:
- **START:** `} else {\n    // React loaded — run the app\n`
- **END:** `\n    setTimeout(function() { var s = document.getElementById("splash")`

**esbuild flags — immutable:**
- `--target=es2018` removes `?.` and `??` (Chrome 66+ / Firefox 57+ / Safari 12+)
- `--jsx=transform` uses classic `React.createElement` (NOT automatic runtime)
- NO `--bundle` — React is a CDN global

---

## ARCHITECTURE RULES

### React is a CDN global — NEVER import it
```javascript
// ✅ TOP OF FILE — kept as source import, stripped by build script
import { useState, useEffect, useCallback, useRef, useMemo } from "react";

// ❌ NEVER ADD
import React from "react";
```

### Component Tree
```
TaxiDispatcherApp          ← entry point — auth gate only
└── DispatcherApp          ← all state + all business logic
    ├── LoginPage           ← shown when authStatus === "unauthenticated"
    ├── AdminDashboard      ← shown when currentUser.role === "admin"
    └── [booking app JSX]
        ├── AddressField    ← Maps autocomplete + Whisper mic (has local state)
        ├── Field           ← thin input wrapper (stateless)
        ├── Badge           ← status pill (stateless)
        ├── BookingSection  ← groups cards by date
        └── BookingCard     ← ✏️ 🖨 🗑 actions per booking
```

### Critical State Declaration Order — NEVER reorder these
```javascript
// passphrase must come before syncStatus
const [passphrase, setPassphrase] = useState("");            // L~1608

// syncStatus must come before syncNow
const [syncStatus, setSyncStatus] = useState("idle");        // L~1611

// syncNow must come before autoSync useEffect
const syncNow = useCallback(async () => { ... });            // L~1679

// autoSync block MUST be last — uses all three above
const [autoSyncEnabled, setAutoSyncEnabled] = useState();    // L~1786
useEffect(() => { ... }, [...passphrase, syncStatus...]);
```

### Form State — always spread
```javascript
// ✅ Correct
setForm(prev => ({ ...prev, driverNumber: "08" }));

// ❌ Mutation — breaks React
form.driverNumber = "08";
```

### isAirportTrip — the one source of truth
```javascript
// ✅ Always use the useMemo
const isAirportTrip = useMemo(() => { ... }, [form.pickupAddress, form.dropoffAddress]);

// ❌ Never call normalizeLocation() inline in render — expensive
if (normalizeLocation(form.pickupAddress) === "JFK") { ... }
```

---

## NAMING CONVENTIONS

| Pattern | Example | Rule |
|---------|---------|------|
| Sanitizers | `sanitizePhone()` | Always prefix `sanitize` |
| Loaders | `loadBookings()` | `load` prefix, sync |
| Savers | `saveBookings()` | `save` prefix, sync |
| Handlers | `handleSubmit()` | `handle` prefix |
| Boolean state | `isListening`, `isAirportTrip` | `is` prefix |
| Visibility state | `showCal`, `showConfirm` | `show` prefix |
| Admin IIFE helpers | `saveAdminMapsKey()` | `admin` prefix — avoids global collision |
| Driver IDs | `"08"`, `"19"` | **Always strings**, always 2-char padded |
| Date values | `"2025-06-03"` | **Always `"YYYY-MM-DD"`** |
| Time (timeSlot) | `"3:00 PM"` | 12h with space before AM/PM |
| Time (customTime) | `"15:00"` | 24h for `<input type="time">` |

### Key Constants
```javascript
INIT_FORM           // form reset object — 14 fields
STORAGE_KEY         // "taxi-bookings-data"
SYNC_CONFIG_KEY     // "dispatch-hq-sync-config"
MAPS_KEY_STORAGE    // "dispatch-hq-maps-key"
BACKUP_PREFIX       // "dispatch-hq-backup-"
REQUIRED_BOOKING_FIELDS  // string[] — used in isValidBooking()
```

---

## DATA SHAPES

### Booking (18 fields — all required in storage)
```typescript
{
  id: string           // 24-char hex from generateSecureId()
  customerName: string // sanitize() max 200
  phone: string        // sanitizePhone() — [0-9+\-.()space] only
  pickupAddress: string
  dropoffAddress: string
  airline: string      // "" when !isAirportTrip
  flightNumber: string // "" when !isAirportTrip, always UPPERCASE
  passengers: string   // "1" default
  luggage: string      // "0" default
  tripType: "one-way" | "round-trip"
  paymentAmount: string
  driverNumber: string // ALWAYS string "08" not number 8
  date: string         // "YYYY-MM-DD"
  timeSlot: string     // "3:00 PM"
  createdAt: string    // ISO 8601
  modifiedAt: string   // ISO 8601 — newer wins on sync conflict
  flightStatus: string
  flightArrival: string
  fareRoute: string
  fareBreakdown: string
}
```

### Driver
```typescript
{
  id: string              // "08" — string, 2-char padded
  airportPickup: boolean
  airportDropoff: boolean
  shiftStart: string      // "05:00" 24h
  shiftEnd: string        // "16:00" 24h
  daysOff: string[]       // ["Thursday"]
  monthlyOff: number[]    // [9, 19, 29]
  specialShifts: Array<{ day: string, start: string, end: string }>
  notes: string
  custom?: boolean        // true = added via UI
}
```

---

## STATE VARIABLES (57 in DispatcherApp)

```javascript
// ── Navigation ──
view                    // "booking"|"dashboard"|"drivers"|"sync"|"backup"

// ── Auth ──
authStatus              // "loading"|"unauthenticated"|"authenticated"
currentUser             // SessionObject | null

// ── Bookings ──
bookings                // Booking[]
form                    // BookingForm (mirrors INIT_FORM shape + customTime)
editingBooking          // Booking | null
showConfirm             // Booking | null
deleteConfirmId         // string | null
missingFields           // string[] (field keys)
formError               // string
isSubmitting            // bool (1s debounce guard)
paymentManuallyEdited   // bool (prevents auto-fill overwrite)

// ── UI pickers ──
showCal                 // bool
showTimePicker          // bool
calViewMonth            // { year: int, month: int }
dashPage                // int (50 = show 50 bookings)

// ── Voice ──
isListening             // bool
speechLang              // "en-US"|"ko-KR"
transcript              // string
micPermission           // "unknown"|"granted"|"denied"|"sandbox"

// ── Maps ──
mapsReady               // bool — Google Maps Places loaded

// ── Sync ──
passphrase              // string (cleared after key derivation)
syncStatus              // "idle"|"syncing"|"success"|"error"
autoSyncEnabled         // bool
autoSyncInterval        // int (minutes: 5/10/15/30/60)

// ── useMemos ──
isAirportTrip           // bool — pickup or dropoff is JFK/LGA/EWR
filteredBookings        // Booking[] — search + filter applied
groupedBookings         // Record<string, Booking[]> — by date
driverAvailability      // Record<driverId, ShiftInfo>
bookedDrivers           // Set<driverId> — already booked at current slot
driverTimeMatch         // Record<driverId, { available: bool }>
```

---

## STORAGE KEYS — COMPLETE MAP

```javascript
// localStorage
"dispatch-hq-session"           // SessionObject (GAS auth, 24h TTL)
"dispatch-hq-sync-config"       // { endpointUrl, authToken, passphraseHash, lastSync }
"dispatch-hq-maps-key"          // Google Maps API key
"dispatch-hq-gdpr-notice"       // "dismissed"
"dispatch-hq-autosync"          // "true"|"false"
"dispatch-hq-autosync-interval" // "30"
"dispatch-hq-custom-drivers"    // Driver[]
"dispatch-hq-backup-{ts}"       // Booking[] snapshots (rolling 5)
"dispatch-hq-backup-log"        // BackupLogEntry[] (max 100)
"taxi-bookings-data"            // Booking[] (plaintext, 2-year retention)
"dispatch-hq-accounts"          // UserAccount[] (legacy local auth — keep for fallback)
```

---

## GAS API CONTRACT

Transport: `Content-Type: text/plain;charset=utf-8` on ALL POST requests (no CORS preflight)

```
GET  ?action=ping&token=AUTH_TOKEN
GET  ?action=list&token=AUTH_TOKEN[&since=ISO]
GET  ?action=validateSession&sessionToken=TOKEN
GET  ?action=adminGetUsers&sessionToken=TOKEN       # admin only

POST { action:"login", username, passwordHash }
POST { action:"register", username, passwordHash, displayName, email }
POST { action:"logout", sessionToken }
POST { action:"approveUser"|"rejectUser"|"disableUser"|"enableUser"|"deleteUser",
       targetUsername, sessionToken }
POST { action:"batchSync", records:[], clientId, token }  # max 500
POST { action:"delete", id, clientId, token }
POST { action:"purge", confirmPurge:true, token }         # 1hr cooldown
```

GAS Sheets: `EncryptedBookings | Users | Sessions | SyncMeta | SyncLog`

**GAS-specific rules:**
- No spread operators (`...obj`) — GAS V8 doesn't support them
- All `LockService.waitLock()` in try/catch with `releaseLock()` in finally
- Rate limit key MUST be `"rate_global"` (not client-supplied)

---

## TEST EXPECTATIONS

### Automated — run after every change
```python
assert compile_exit_code == 0
assert compile_errors == 0

# Temporal dead zone order
assert line("passphrase") < line("autoSyncEnabled")
assert line("syncStatus") < line("autoSyncEnabled")
assert line("syncNow") < line("autoSyncInterval in useEffect deps")

# Auth
assert 'authStatus === "unauthenticated"' in jsx
assert 'currentUser.role === "admin"' in jsx
assert jsx.count("function AdminDashboard(") == 1

# Security
assert "eval(" not in jsx
assert "dangerouslySetInnerHTML" not in jsx
assert not re.search(r"\balert\s*\(", jsx)
assert "hasOwnProperty" in jsx
assert "..." not in gas.replace("// ...", "")  # no GAS spread operators

# Business logic
assert "bookedDrivers" in jsx     # driver double-booking prevention
assert "isAirportTrip" in jsx     # airport field conditional
assert "dupConfirmed" in jsx      # duplicate booking warning
assert "pastDateConfirmed" in jsx # past-date warning
assert "730" in jsx               # 2-year retention
assert "AES-GCM" in jsx           # encryption
assert "PRECACHE" in html         # React CDN cached in SW
```

### Manual smoke tests (before every Netlify deploy)
1. `admin` / `Admin1234` → Admin Dashboard (not booking form)
2. `/exec?action=ping` → `{"success":true,...}`
3. Create a booking → confirm → appears in Dashboard
4. Assign same driver at same time as existing booking → grid shows `"Booked 3:00 PM"`
5. Set pickup = "JFK" → Airline/Flight become required (red asterisk, enabled)
6. Set pickup = "Manhattan" → Airline/Flight greyed out and disabled
7. Tap 🎤 on address field → records → second tap stops → field fills
8. Past dates unclickable in calendar, today highlighted orange
9. 🖨 opens print slip in new window
10. Push to Sheets → Google Sheet gets encrypted row

---

## COMMON MISTAKES

| ❌ Wrong | ✅ Correct | Why |
|----------|-----------|-----|
| `new Date("YYYY-MM-DD")` | `new Date("YYYY-MM-DD" + "T12:00:00")` | UTC midnight = wrong local weekday |
| `{...sess}` in GAS | `{token:sess.token, role:sess.role}` | GAS V8 no spread |
| `alert("error")` | Inline error state | Blocked in iframes |
| `saveMapsKey` in Admin IIFE | `saveAdminMapsKey` | Name collision with global |
| `language:"korean"` in Whisper | `language: null` | Breaks bilingual speakers |
| Driver id = `8` | `"08"` padStart | Always string, always 2-char |
| `form.phone.replace(/\D/g,"")` | `form.phone.replace(/[^0-9]/g,"")` | esbuild target compat |
| Two `AdminDashboard()` defs | One only | JS uses last, first is dead |
| autoSync block before passphrase | passphrase first (L1608 < L1786) | Temporal dead zone crash |
| `\uXXXX` Korean in compiled JS | Leave it — don't "fix" | esbuild unicode encoding |

---

## DEPLOYMENT

### Netlify
1. Download `dispatch-hq.html`
2. Drag to [app.netlify.com](https://app.netlify.com) → Deploys → drop area
3. Deploy `_headers` alongside it (Whisper needs COOP/COEP)
4. Hard refresh: Ctrl+Shift+R

Live URL: `https://capable-custard-36d377.netlify.app/`

### GAS — after any backend change
1. Apps Script → select all → delete → paste `google-apps-script.js`
2. If password changing: run `generateAdminHash()` → copy hash → paste into `ADMIN_PASSWORD_HASH`
3. Save → Deploy → Manage → Edit → **New version** → Deploy
4. Settings: Execute as Me / Who: Anyone
5. Verify: `[URL]?action=ping` → `{"success":true}`

Backend URL: `https://script.google.com/macros/s/AKfycbzRFmi7dn8yy_u6m0YCz7YCHt-_-PNm6VHOVdOMixf_vMBq0SF3lWg1sEQhwWI2J8I-/exec`
Admin: `admin` / `Admin1234` | Token: `kX9mP2vQ8nL5wR3jF7tY4cH6dA1sE0bN`

---

## KNOWN LIMITATIONS

1. **localStorage plaintext** — local bookings unencrypted. Cloud sync is AES-256. Awaiting user decision on local encryption.
2. **Hooks in IIFEs** — Stats/Driver/Fleet panels use `React.useState()` inside IIFEs. Works. Violates Rules of Hooks. Do not refactor without explicit request.
3. **AI flight lookup offline** — disabled on website (CORS blocks browser→Anthropic). Works in Claude.ai artifact. FlightAware link shown as fallback.
4. **Admin hash generation** — requires GAS console (`generateAdminHash()`). Cannot automate client-side.
