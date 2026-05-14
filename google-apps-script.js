// ═══════════════════════════════════════════════════════════════════
// DISPATCH HQ — Google Apps Script Backend (Code.gs)
// ═══════════════════════════════════════════════════════════════════
// Deploy this in a Google Sheets Apps Script editor.
// All booking data stored is AES-256-GCM encrypted.
// User auth data stored with bcrypt-style PBKDF2 hashing.
//
// SETUP:
// 1. Create a new Google Sheet
// 2. Extensions → Apps Script
// 3. Paste this entire file into Code.gs
// 4. Set ADMIN_PASSWORD_HASH below (run hashPassword("yourpassword") first)
// 5. Deploy → New Deployment → Web App
//    - Execute as: Me
//    - Who has access: Anyone
// 6. Copy the deployment URL into the Dispatch HQ app settings
// ═══════════════════════════════════════════════════════════════════

const SHEET_NAME     = "EncryptedBookings";
const META_SHEET     = "SyncMeta";
const USERS_SHEET    = "Users";
const SESSIONS_SHEET = "Sessions";
const SYNC_LOG_SHEET = "SyncLog";
const MAX_ROWS       = 10000;
const API_VERSION    = "2.0";
const SESSION_TTL_HOURS = 24; // sessions expire after 24 hours

// ── Sync token (for booking sync only, separate from user auth) ──
const AUTH_TOKEN = "CHANGE_ME_TO_A_RANDOM_SECRET_TOKEN_32_CHARS_MIN";

// ── Admin account ──
// Username is always "admin". Set the password by running this in the Script Editor console:
//   Logger.log(hashPassword("YourDesiredPassword"))
// Then paste the result here.
const ADMIN_PASSWORD_HASH = "CHANGE_ME_RUN_hashPassword_TO_GENERATE";
const ADMIN_DISPLAY_NAME  = "Administrator";

// ────────────────────────────────────────────────────────
// SHEET HELPERS
// ────────────────────────────────────────────────────────

function getBookingSheet() {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  let sheet = ss.getSheetByName(SHEET_NAME);
  if (!sheet) {
    sheet = ss.insertSheet(SHEET_NAME);
    sheet.appendRow(["id","encryptedData","iv","salt","timestamp","deleted"]);
    sheet.getRange("A1:F1").setFontWeight("bold");
    sheet.setColumnWidth(2, 400);
    const p = sheet.protect().setDescription("Encrypted booking data — do not edit manually");
    p.setWarningOnly(true);
  }
  return sheet;
}

function getMetaSheet() {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  let sheet = ss.getSheetByName(META_SHEET);
  if (!sheet) {
    sheet = ss.insertSheet(META_SHEET);
    sheet.appendRow(["key","value","updatedAt"]);
    sheet.getRange("A1:C1").setFontWeight("bold");
  }
  return sheet;
}

function getUsersSheet() {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  let sheet = ss.getSheetByName(USERS_SHEET);
  if (!sheet) {
    sheet = ss.insertSheet(USERS_SHEET);
    sheet.appendRow(["id","username","passwordHash","displayName","role","status","createdAt","approvedAt","approvedBy","email"]);
    sheet.getRange("A1:J1").setFontWeight("bold");
    sheet.setColumnWidth(3, 200);
    // Insert the built-in admin row (status=active, role=admin)
    sheet.appendRow([
      "admin",
      "admin",
      ADMIN_PASSWORD_HASH,
      ADMIN_DISPLAY_NAME,
      "admin",
      "active",
      new Date().toISOString(),
      new Date().toISOString(),
      "system",
      ""
    ]);
  }
  return sheet;
}

function getSessionsSheet() {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  let sheet = ss.getSheetByName(SESSIONS_SHEET);
  if (!sheet) {
    sheet = ss.insertSheet(SESSIONS_SHEET);
    sheet.appendRow(["token","userId","username","role","createdAt","expiresAt","ip"]);
    sheet.getRange("A1:G1").setFontWeight("bold");
  }
  return sheet;
}

function getSyncLogSheet() {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  let sheet = ss.getSheetByName(SYNC_LOG_SHEET);
  if (!sheet) {
    sheet = ss.insertSheet(SYNC_LOG_SHEET);
    sheet.appendRow(["timestamp","action","clientId","recordCount","details"]);
    sheet.getRange("A1:E1").setFontWeight("bold");
    sheet.setColumnWidth(1, 200);
    sheet.setColumnWidth(5, 400);
  }
  return sheet;
}

function getMetaValue(key) {
  const sheet = getMetaSheet();
  const data = sheet.getDataRange().getValues();
  for (let i = 1; i < data.length; i++) {
    if (data[i][0] === key) return data[i][1];
  }
  return null;
}

function setMetaValue(key, value) {
  const sheet = getMetaSheet();
  const data = sheet.getDataRange().getValues();
  for (let i = 1; i < data.length; i++) {
    if (data[i][0] === key) {
      sheet.getRange(i + 1, 2, 1, 2).setValues([[value, new Date().toISOString()]]);
      return;
    }
  }
  sheet.appendRow([key, value, new Date().toISOString()]);
}

// ────────────────────────────────────────────────────────
// CRYPTO HELPERS
// ────────────────────────────────────────────────────────

// PBKDF2-style password hashing using GAS Utilities
function hashPassword(password) {
  // Use SHA-256 of password+salt (GAS doesn't have PBKDF2 natively)
  // We use multiple rounds of SHA-256 for key stretching
  var hash = password + "dispatch-hq-salt-2024";
  for (var i = 0; i < 10000; i++) {
    hash = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, hash + i)
      .map(function(b) { return (b < 0 ? b + 256 : b).toString(16).padStart(2,"0"); })
      .join("");
  }
  return "pbkdf2$" + hash;
}

function verifyPassword(password, storedHash) {
  if (!storedHash || !password) return false;
  const computed = hashPassword(password);
  // Constant-time comparison
  if (computed.length !== storedHash.length) return false;
  var mismatch = 0;
  for (var i = 0; i < computed.length; i++) {
    mismatch |= computed.charCodeAt(i) ^ storedHash.charCodeAt(i);
  }
  return mismatch === 0;
}

function generateToken() {
  var bytes = Utilities.computeDigest(
    Utilities.DigestAlgorithm.SHA_256,
    new Date().getTime() + Math.random().toString() + Math.random().toString()
  );
  return bytes.map(function(b) { return (b < 0 ? b + 256 : b).toString(16).padStart(2,"0"); }).join("");
}

// ────────────────────────────────────────────────────────
// SESSION MANAGEMENT
// ────────────────────────────────────────────────────────

function createSession(userId, username, role) {
  const token = generateToken();
  const now = new Date();
  const expires = new Date(now.getTime() + SESSION_TTL_HOURS * 3600 * 1000);
  const sheet = getSessionsSheet();
  // Purge old sessions for this user
  purgeOldSessions();
  sheet.appendRow([token, userId, username, role, now.toISOString(), expires.toISOString(), ""]);
  return { token: token, expiresAt: expires.toISOString() };
}

function validateSession(token) {
  if (!token) return null;
  const sheet = getSessionsSheet();
  const lastRow = sheet.getLastRow();
  if (lastRow <= 1) return null;
  const data = sheet.getRange(2, 1, lastRow - 1, 6).getValues();
  const now = new Date();
  for (var i = 0; i < data.length; i++) {
    if (data[i][0] === token) {
      const expires = new Date(data[i][5]);
      if (now > expires) return null; // expired
      return {
        userId:   data[i][1],
        username: data[i][2],
        role:     data[i][3],
        expiresAt: data[i][5]
      };
    }
  }
  return null;
}

function destroySession(token) {
  if (!token) return;
  const sheet = getSessionsSheet();
  const lastRow = sheet.getLastRow();
  if (lastRow <= 1) return;
  const data = sheet.getRange(2, 1, lastRow - 1, 1).getValues();
  for (var i = 0; i < data.length; i++) {
    if (data[i][0] === token) {
      sheet.deleteRow(i + 2);
      return;
    }
  }
}

function purgeOldSessions() {
  try {
    const sheet = getSessionsSheet();
    const lastRow = sheet.getLastRow();
    if (lastRow <= 1) return;
    const data = sheet.getRange(2, 1, lastRow - 1, 6).getValues();
    const now = new Date();
    const toDelete = [];
    for (var i = data.length - 1; i >= 0; i--) {
      const expires = new Date(data[i][5]);
      if (now > expires) toDelete.push(i + 2);
    }
    toDelete.forEach(function(row) { sheet.deleteRow(row); });
  } catch(e) {}
}

// ────────────────────────────────────────────────────────
// USER MANAGEMENT
// ────────────────────────────────────────────────────────

function getUserByUsername(username) {
  const sheet = getUsersSheet();
  const lastRow = sheet.getLastRow();
  if (lastRow <= 1) return null;
  const data = sheet.getRange(2, 1, lastRow - 1, 10).getValues();
  for (var i = 0; i < data.length; i++) {
    if (data[i][1] === username) {
      return {
        id:          data[i][0],
        username:    data[i][1],
        passwordHash: data[i][2],
        displayName: data[i][3],
        role:        data[i][4],
        status:      data[i][5],
        createdAt:   data[i][6],
        approvedAt:  data[i][7],
        approvedBy:  data[i][8],
        email:       data[i][9],
        _row:        i + 2
      };
    }
  }
  return null;
}

function getAllUsers() {
  const sheet = getUsersSheet();
  const lastRow = sheet.getLastRow();
  if (lastRow <= 1) return [];
  const data = sheet.getRange(2, 1, lastRow - 1, 10).getValues();
  return data.map(function(row, i) {
    return {
      id:          row[0],
      username:    row[1],
      displayName: row[3],
      role:        row[4],
      status:      row[5],
      createdAt:   row[6],
      approvedAt:  row[7],
      approvedBy:  row[8],
      email:       row[9],
      _row:        i + 2
    };
  }).filter(function(u) { return u.role !== "admin"; }); // don't expose admin in list
}

// ────────────────────────────────────────────────────────
// LOG
// ────────────────────────────────────────────────────────

function addSyncLog(action, clientId, recordCount, details) {
  try {
    const sheet = getSyncLogSheet();
    if (sheet.getLastRow() > 5000) sheet.deleteRows(2, 1000);
    sheet.appendRow([
      new Date().toISOString(),
      String(action).slice(0, 20),
      String(clientId || "unknown").slice(0, 50),
      Number(recordCount) || 0,
      String(details || "").slice(0, 500)
    ]);
  } catch(e) {}
}

// ────────────────────────────────────────────────────────
// RATE LIMITING
// ────────────────────────────────────────────────────────

function checkRateLimit(key) {
  const cache = CacheService.getScriptCache();
  const rKey = "rate_global";
  const count = parseInt(cache.get(rKey) || "0");
  if (count > 200) return false;
  cache.put(rKey, String(count + 1), 60);
  return true;
}

// ────────────────────────────────────────────────────────
// RESPONSE HELPERS
// ────────────────────────────────────────────────────────

function createJsonResponse(data) {
  const out = ContentService.createTextOutput(JSON.stringify(Object.assign({ apiVersion: API_VERSION, ts: new Date().toISOString() }, data)));
  out.setMimeType(ContentService.MimeType.JSON);
  return out;
}

function createErrorResponse(message, code) {
  return createJsonResponse({ success: false, error: message, code: code || 400 });
}

function checkAuth(token) {
  if (AUTH_TOKEN === "CHANGE_ME_TO_A_RANDOM_SECRET_TOKEN_32_CHARS_MIN") return true;
  return token === AUTH_TOKEN;
}

// ────────────────────────────────────────────────────────
// GET HANDLER
// ────────────────────────────────────────────────────────

function doGet(e) {
  try {
    if (!checkRateLimit("get")) return createErrorResponse("Rate limit exceeded", 429);
    const p      = (e && e.parameter) || {};
    const action = p.action || "list";

    // ── Auth routes (no booking token needed) ──
    if (action === "validateSession") {
      const sess = validateSession(p.sessionToken);
      if (!sess) return createJsonResponse({ success: false, valid: false });
      return createJsonResponse({ success: true, valid: true, user: { username: sess.username, role: sess.role, displayName: sess.displayName } });
    }

    // ── Booking routes (require sync token) ──
    if (!checkAuth(p.token || "")) return createErrorResponse("Unauthorized", 401);

    if (action === "ping") {
      addSyncLog("ping", p.clientId, 0, "Health check");
      return createJsonResponse({
        success: true,
        message: "Dispatch HQ backend v" + API_VERSION,
        sheetName: SpreadsheetApp.getActiveSpreadsheet().getName(),
        recordCount: Math.max(0, getBookingSheet().getLastRow() - 1)
      });
    }

    if (action === "list") {
      const sheet = getBookingSheet();
      const lastRow = sheet.getLastRow();
      if (lastRow <= 1) return createJsonResponse({ success: true, records: [], count: 0 });
      const data = sheet.getRange(2, 1, lastRow - 1, 6).getValues();
      const since = p.since || "";
      const records = [];
      for (var i = 0; i < data.length; i++) {
        const row = data[i];
        const rec = { id: row[0], encryptedData: row[1], iv: row[2], salt: row[3], timestamp: row[4],
          deleted: row[5] === true || String(row[5]).toLowerCase() === "true" };
        if (since) { const rt = new Date(rec.timestamp).getTime(); const st = new Date(since).getTime(); if (rt <= st) continue; }
        records.push(rec);
      }
      addSyncLog("list", p.clientId, records.length, "Fetched " + records.length);
      return createJsonResponse({ success: true, records: records, count: records.length });
    }

    // ── Admin routes (require valid admin session) ──
    if (action === "adminGetUsers") {
      const sess = validateSession(p.sessionToken);
      if (!sess || sess.role !== "admin") return createErrorResponse("Admin access required", 403);
      const users = getAllUsers();
      const sessions = getSessionsSheet().getLastRow() > 1
        ? getSessionsSheet().getRange(2, 1, getSessionsSheet().getLastRow()-1, 6).getValues()
          .filter(function(r) { return new Date(r[5]) > new Date(); }).length
        : 0;
      return createJsonResponse({
        success: true,
        users: users,
        activeSessions: sessions,
        totalBookings: Math.max(0, getBookingSheet().getLastRow() - 1)
      });
    }

    return createErrorResponse("Unknown action", 400);
  } catch(err) {
    addSyncLog("error", "", 0, "doGet: " + err.message);
    return createErrorResponse("Internal server error", 500);
  }
}

// ────────────────────────────────────────────────────────
// POST HANDLER
// ────────────────────────────────────────────────────────

function doPost(e) {
  try {
    if (!e || !e.postData) return createErrorResponse("No request body", 400);
    if (!checkRateLimit("post")) return createErrorResponse("Rate limit exceeded", 429);

    var body;
    try { body = JSON.parse(e.postData.contents); }
    catch(parseErr) { return createErrorResponse("Invalid JSON body", 400); }

    if (!body || typeof body !== "object") return createErrorResponse("Invalid request body", 400);

    const action = String(body.action || "").slice(0, 30);
    const lock = LockService.getScriptLock();

    // ── Auth routes (no booking token needed) ──

    if (action === "register") {
      const username    = String(body.username || "").toLowerCase().trim().replace(/[^a-z0-9_]/g,"").slice(0,30);
      const password    = String(body.passwordHash || "").slice(0, 500); // client sends pre-hashed
      const displayName = String(body.displayName || "").trim().slice(0, 60);
      const email       = String(body.email || "").trim().slice(0, 100);

      if (!username || username.length < 3) return createErrorResponse("Username must be at least 3 characters (letters, numbers, underscores only)", 400);
      if (username === "admin") return createErrorResponse("Username 'admin' is reserved", 400);
      if (!password) return createErrorResponse("Password is required", 400);
      if (!displayName) return createErrorResponse("Display name is required", 400);

      // Check duplicate
      if (getUserByUsername(username)) return createErrorResponse("Username already taken", 409);

      const userId = "u_" + Date.now() + "_" + Math.floor(Math.random() * 9999);
      // Store the pre-hashed password hashed again server-side for defense-in-depth
      const serverHash = hashPassword(password);

      try { lock.waitLock(8000); } catch(lockErr) { return createErrorResponse("Server busy, try again", 503); }
      try {
        getUsersSheet().appendRow([userId, username, serverHash, displayName, "dispatcher", "pending", new Date().toISOString(), "", "", email]);
        addSyncLog("register", username, 0, "New dispatcher registration — pending admin approval");
        return createJsonResponse({ success: true, status: "pending", message: "Account created. Awaiting admin approval before you can sign in." });
      } finally { lock.releaseLock(); }
    }

    if (action === "login") {
      const username = String(body.username || "").toLowerCase().trim();
      const password = String(body.passwordHash || "").slice(0, 500); // client sends pre-hashed

      if (!username || !password) return createErrorResponse("Username and password are required", 400);

      // Special admin path — check against ADMIN_PASSWORD_HASH directly
      if (username === "admin") {
        if (ADMIN_PASSWORD_HASH === "CHANGE_ME_RUN_hashPassword_TO_GENERATE") {
          // Admin password not set yet — allow first-time login to set it
          const sess = createSession("admin", "admin", "admin");
          addSyncLog("login", "admin", 0, "Admin first-time login (password not configured)");
          return createJsonResponse({ success: true, token: sess.token, expiresAt: sess.expiresAt, role: "admin", displayName: ADMIN_DISPLAY_NAME, firstLogin: true });
        }
        if (!verifyPassword(password, ADMIN_PASSWORD_HASH)) {
          addSyncLog("login-fail", "admin", 0, "Invalid admin password attempt");
          return createErrorResponse("Invalid username or password", 401);
        }
        const sess = createSession("admin", "admin", "admin");
        addSyncLog("login", "admin", 0, "Admin signed in");
        return createJsonResponse({ success: true, token: sess.token, expiresAt: sess.expiresAt, role: "admin", displayName: ADMIN_DISPLAY_NAME });
      }

      const user = getUserByUsername(username);
      if (!user) return createErrorResponse("Invalid username or password", 401);
      if (user.status === "pending") return createErrorResponse("Your account is pending admin approval. You will be able to sign in once approved.", 403);
      if (user.status === "disabled") return createErrorResponse("Your account has been disabled. Contact your administrator.", 403);
      if (user.status !== "active") return createErrorResponse("Account not active", 403);
      if (!verifyPassword(password, user.passwordHash)) {
        addSyncLog("login-fail", username, 0, "Invalid password attempt");
        return createErrorResponse("Invalid username or password", 401);
      }

      const sess = createSession(user.id, user.username, user.role);
      addSyncLog("login", username, 0, "Dispatcher signed in");
      return createJsonResponse({ success: true, token: sess.token, expiresAt: sess.expiresAt, role: user.role, displayName: user.displayName });
    }

    if (action === "logout") {
      destroySession(body.sessionToken);
      return createJsonResponse({ success: true });
    }

    // ── Admin user management ──

    if (action === "approveUser" || action === "rejectUser" || action === "disableUser" || action === "enableUser" || action === "deleteUser") {
      const sess = validateSession(body.sessionToken);
      if (!sess || sess.role !== "admin") return createErrorResponse("Admin access required", 403);

      const targetUsername = String(body.targetUsername || "").toLowerCase().trim();
      if (!targetUsername || targetUsername === "admin") return createErrorResponse("Invalid target user", 400);

      const user = getUserByUsername(targetUsername);
      if (!user) return createErrorResponse("User not found", 404);

      const sheet = getUsersSheet();
      const newStatus = action === "approveUser" ? "active"
        : action === "rejectUser" ? "rejected"
        : action === "disableUser" ? "disabled"
        : action === "enableUser" ? "active"
        : null; // deleteUser

      try { lock.waitLock(8000); } catch(lockErr) { return createErrorResponse("Server busy", 503); }
      try {
        if (action === "deleteUser") {
          sheet.deleteRow(user._row);
          addSyncLog(action, sess.username, 0, "Deleted user: " + targetUsername);
          return createJsonResponse({ success: true, message: "User deleted" });
        }
        sheet.getRange(user._row, 6).setValue(newStatus);
        if (action === "approveUser") {
          sheet.getRange(user._row, 8).setValue(new Date().toISOString());
          sheet.getRange(user._row, 9).setValue(sess.username);
        }
        addSyncLog(action, sess.username, 0, targetUsername + " → " + newStatus);
        return createJsonResponse({ success: true, message: "User " + action.replace("User","").toLowerCase() + "d" });
      } finally { lock.releaseLock(); }
    }

    if (action === "setAdminPassword") {
      const sess = validateSession(body.sessionToken);
      if (!sess || sess.role !== "admin") return createErrorResponse("Admin access required", 403);
      // Return the hash to paste into the script
      const newPassword = String(body.newPassword || "").slice(0, 500);
      if (!newPassword) return createErrorResponse("Password required", 400);
      const newHash = hashPassword(newPassword);
      addSyncLog("setAdminPassword", "admin", 0, "Admin password hash generated");
      return createJsonResponse({ success: true, hash: newHash, instruction: "Paste this hash into ADMIN_PASSWORD_HASH in your Apps Script and redeploy." });
    }

    // ── Booking sync routes (require sync token) ──
    if (!checkAuth(body.token || "")) return createErrorResponse("Unauthorized", 401);

    if (action === "batchSync") {
      // ... (existing booking sync logic unchanged)
      return handleBatchSync(body, lock);
    }
    if (action === "delete") return handleDelete(body, lock);
    if (action === "purge") {
      if (body.confirmPurge !== true) return createErrorResponse("Purge requires confirmPurge: true", 400);
      var purgeCache = CacheService.getScriptCache();
      if (purgeCache.get("purge_cooldown")) return createErrorResponse("Purge can only be performed once per hour", 429);
      purgeCache.put("purge_cooldown", "1", 3600);
      return handlePurge(lock);
    }

    return createErrorResponse("Unknown action: " + action, 400);
  } catch(err) {
    addSyncLog("error", "", 0, "doPost: " + err.message);
    return createErrorResponse("Internal server error", 500);
  }
}

// ────────────────────────────────────────────────────────
// BOOKING SYNC HANDLERS (unchanged from v1)
// ────────────────────────────────────────────────────────

function handleBatchSync(body, lock) {
  const records = body.records;
  if (!Array.isArray(records)) return createErrorResponse("records must be an array", 400);
  if (records.length > 500) return createErrorResponse("Batch limit is 500 records", 400);

  for (var i = 0; i < records.length; i++) {
    var r = records[i];
    if (!r || typeof r !== "object") return createErrorResponse("Invalid record at index " + i, 400);
    if (typeof r.id !== "string" || r.id.length > 50) return createErrorResponse("Invalid record id", 400);
    if (typeof r.encryptedData !== "string" || r.encryptedData.length > 50000) return createErrorResponse("Record too large", 400);
  }

  try { lock.waitLock(10000); } catch(lockErr) { return createErrorResponse("Server busy, try again", 503); }
  try {
    const sheet = getBookingSheet();
    const lastRow = sheet.getLastRow();
    const existing = {};
    if (lastRow > 1) {
      const data = sheet.getRange(2, 1, lastRow - 1, 6).getValues();
      for (var j = 0; j < data.length; j++) existing[data[j][0]] = { row: j + 2, data: data[j] };
    }

    if (lastRow - 1 + records.length > MAX_ROWS) return createErrorResponse("Sheet at capacity (" + MAX_ROWS + " records)", 507);

    var created = 0, updated = 0;
    for (var k = 0; k < records.length; k++) {
      var rec = records[k];
      const isDeleted = rec.deleted === true || rec.deleted === "true";
      const rowData = [
        String(rec.id).slice(0, 50),
        String(rec.encryptedData || "").slice(0, 50000),
        String(rec.iv || "").slice(0, 200),
        String(rec.salt || "").slice(0, 100),
        new Date().toISOString(),
        isDeleted ? "true" : "false"
      ];
      if (existing[rec.id]) {
        sheet.getRange(existing[rec.id].row, 1, 1, 6).setValues([rowData]);
        updated++;
      } else {
        sheet.appendRow(rowData);
        created++;
      }
    }

    addSyncLog("batchSync", body.clientId, records.length, "Created:" + created + " Updated:" + updated);
    return createJsonResponse({ success: true, created: created, updated: updated, totalRecords: sheet.getLastRow() - 1 });
  } finally { lock.releaseLock(); }
}

function handleDelete(body, lock) {
  const id = String(body.id || "").slice(0, 50);
  if (!id) return createErrorResponse("Record id required", 400);

  try { lock.waitLock(5000); } catch(lockErr) { return createErrorResponse("Server busy", 503); }
  try {
    const sheet = getBookingSheet();
    const lastRow = sheet.getLastRow();
    if (lastRow <= 1) return createErrorResponse("Record not found", 404);
    const data = sheet.getRange(2, 1, lastRow - 1, 1).getValues();
    for (var i = 0; i < data.length; i++) {
      if (data[i][0] === id) {
        sheet.getRange(i + 2, 6).setValue("true");
        addSyncLog("delete", body.clientId, 1, "Soft-deleted: " + id);
        return createJsonResponse({ success: true, deleted: id });
      }
    }
    return createErrorResponse("Record not found", 404);
  } finally { lock.releaseLock(); }
}

// ── Admin Setup Helper ──
// Run this to generate ADMIN_PASSWORD_HASH correctly.
// It simulates the full client+server hashing pipeline.
function generateAdminHash() {
  var rawPassword = "REPLACE_WITH_YOUR_PASSWORD";
  // Step 1: simulate what the browser does (SHA-256 + client salt)
  var clientSalt = "dispatch-hq-client-salt";
  var clientHashBytes = Utilities.computeDigest(
    Utilities.DigestAlgorithm.SHA_256,
    rawPassword + clientSalt
  );
  var clientHash = clientHashBytes
    .map(function(b) { return (b < 0 ? b + 256 : b).toString(16).padStart(2, "0"); })
    .join("");
  // Step 2: apply server-side hashPassword to the client hash
  var finalHash = hashPassword(clientHash);
  Logger.log("ADMIN_PASSWORD_HASH = \"" + finalHash + "\"");
  Logger.log("Your raw login password is: " + rawPassword);
}

function handlePurge(lock) {
  try { lock.waitLock(10000); } catch(lockErr) { return createErrorResponse("Server busy", 503); }
  try {
    const sheet = getBookingSheet();
    const lastRow = sheet.getLastRow();
    if (lastRow <= 1) return createJsonResponse({ success: true, purged: 0 });
    const data = sheet.getRange(2, 1, lastRow - 1, 6).getValues();
    var purged = 0;
    for (var i = data.length - 1; i >= 0; i--) {
      const isDeleted = data[i][5] === true || String(data[i][5]).toLowerCase() === "true";
      if (isDeleted) { sheet.deleteRow(i + 2); purged++; }
    }
    addSyncLog("purge", "system", purged, "Hard-deleted " + purged + " soft-deleted records");
    return createJsonResponse({ success: true, purged: purged });
  } finally { lock.releaseLock(); }
}
