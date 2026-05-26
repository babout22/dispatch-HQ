import { useState, useEffect, useCallback, useRef, useMemo } from "react";

// ════════════════════════════════════════════════════════════════
// AUTH SYSTEM — accounts, sessions, admin
// ════════════════════════════════════════════════════════════════

const AUTH_ACCOUNTS_KEY  = "dispatch-hq-accounts";
const AUTH_SESSION_KEY   = "dispatch-hq-session";
const ADMIN_EMAIL        = "admin";          // login username for admin

// Hash password with SHA-256
// Hash password — client uses inline clientHash() in LoginPage; this is unused legacy
// async function hashPassword removed — see LoginPage clientHash() for correct formula

function generateId() {
  const arr = new Uint8Array(12);
  crypto.getRandomValues(arr);
  return Array.from(arr).map(b => b.toString(16).padStart(2,"0")).join("");
}



// ── Admin account — created on first run ──

// ════════════════════════════════════════════════════════════════
// SANITIZERS & UTILITIES
// ════════════════════════════════════════════════════════════════


function sanitize(str, maxLen = 200) {
  if (typeof str !== "string") return "";
  return str.replace(/[<>&"'/\\]/g, "").trim().slice(0, maxLen);
}
function sanitizePhone(str) {
  if (typeof str !== "string") return "";
  return str.replace(/[^0-9+\-(). ]/g, "").slice(0, 30);
}
function sanitizeNumeric(str) {
  if (typeof str !== "string") return "";
  const cleaned = str.replace(/[^0-9.]/g, "").slice(0, 15);
  const parts = cleaned.split(".");
  if (parts.length <= 2) return cleaned;
  return parts[0] + "." + parts.slice(1).join("");
}
function sanitizeInteger(str, min, max) {
  if (typeof str !== "string") return String(min || 0);
  const n = parseInt(str.replace(/[^0-9]/g, ""), 10);
  if (isNaN(n)) return String(min || 0);
  if (min != null && n < min) return String(min);
  if (max != null && n > max) return String(max);
  return String(n);
}
function sanitizeDriverId(str) {
  if (typeof str !== "string") return "";
  return str.replace(/[^0-9]/g, "").slice(0, 3);
}
function sanitizeErrorMsg(err) {
  const msg = (err && err.message) ? err.message : String(err || "Unknown error");
  // Strip anything that looks like a URL, path, or API key
  return msg.replace(/https?:\/\/[^\s]+/g, "[url]")
            .replace(/\/[^\s]*\//g, "[path]")
            .replace(/[A-Za-z0-9]{32,}/g, "[redacted]")
            .slice(0, 200);
}
// Detect if running standalone (website) vs inside Claude.ai artifact (iframe)
// Anthropic API calls only work in the artifact — browser CORS blocks them on standalone sites
function isStandaloneMode() {
  try { return window.self === window.top; } catch { return false; }
}

function generateSecureId() {
  const arr = new Uint8Array(12);
  crypto.getRandomValues(arr);
  return Array.from(arr, b => b.toString(36).padStart(2, "0")).join("").slice(0, 16);
}

// ── Encryption Service (AES-256-GCM via Web Crypto API) ──
const CryptoService = {
  async deriveKey(passphrase, salt) {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
      "raw", enc.encode(passphrase), "PBKDF2", false, ["deriveKey"]
    );
    return crypto.subtle.deriveKey(
      { name: "PBKDF2", salt, iterations: 310000, hash: "SHA-256" },
      keyMaterial,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
  },

  async encrypt(data, passphrase) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await this.deriveKey(passphrase, salt);
    const enc = new TextEncoder();
    const ciphertext = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv }, key, enc.encode(JSON.stringify(data))
    );
    return {
      encryptedData: this._bufToBase64(ciphertext),
      iv: this._bufToBase64(iv),
      salt: this._bufToBase64(salt)
    };
  },

  async decrypt(encryptedData, iv, salt, passphrase) {
    const saltBuf = this._base64ToBuf(salt);
    const ivBuf = this._base64ToBuf(iv);
    const dataBuf = this._base64ToBuf(encryptedData);
    const key = await this.deriveKey(passphrase, saltBuf);
    const decrypted = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: ivBuf }, key, dataBuf
    );
    return JSON.parse(new TextDecoder().decode(decrypted));
  },

  async hashPassphrase(passphrase) {
    const enc = new TextEncoder();
    const hash = await crypto.subtle.digest("SHA-256", enc.encode("dispatch-hq-v1:" + passphrase));
    return this._bufToBase64(hash);
  },

  _bufToBase64(buf) {
    const bytes = new Uint8Array(buf);
    let binary = "";
    for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary);
  },

  _base64ToBuf(b64) {
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes.buffer;
  }
};

// ── Remote Sync Service ──
// Google Apps Script Web Apps respond with 302 redirects. fetch() follows 302 but 
// changes POST→GET per HTTP spec, losing the body. Fix: use "text/plain" Content-Type 
// to avoid CORS preflight, which lets GAS handle the POST directly.
const SyncService = {
  // Safe JSON extraction: finds first balanced {...} in text
  _extractJson(text) {
    const start = text.indexOf("{");
    if (start < 0) return null;
    let depth = 0;
    for (let i = start; i < text.length; i++) {
      const ch = text[i];
      if (ch === "{") depth++;
      else if (ch === "}") { depth--; if (depth === 0) return text.slice(start, i + 1); }
    }
    return null;
  },

  _parseResponse(text) {
    try { return JSON.parse(text); }
    catch {
      const json = this._extractJson(text);
      if (json) return JSON.parse(json);
      return null;
    }
  },

  // Fetch with timeout (default 30 seconds)
  async _fetchWithTimeout(url, options, timeoutMs) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), timeoutMs || 30000);
    try {
      const resp = await fetch(url, { ...options, signal: controller.signal });
      clearTimeout(timeout);
      return resp;
    } catch (err) {
      clearTimeout(timeout);
      if (err.name === "AbortError") throw new Error("Request timed out after " + ((timeoutMs || 30000) / 1000) + "s — check your internet connection");
      throw err;
    }
  },

  async _gasPost(url, body) {
    const resp = await this._fetchWithTimeout(url, {
      method: "POST",
      headers: { "Content-Type": "text/plain;charset=utf-8" },
      body: JSON.stringify(body),
      redirect: "follow"
    }, 30000);
    if (!resp.ok && resp.status !== 0) {
      // GAS returns 200 even for errors (wrapped in JSON), but network/proxy errors give real HTTP codes
      throw new Error("Server returned HTTP " + resp.status);
    }
    const text = await resp.text();
    if (!text || text.length < 2) throw new Error("Empty response from server");
    const result = this._parseResponse(text);
    if (!result) throw new Error("Server returned invalid response (not JSON)");
    return result;
  },

  async ping(url, token) {
    const resp = await this._fetchWithTimeout(
      url + "?action=ping&clientId=dispatch-hq&token=" + encodeURIComponent(token || ""),
      { method: "GET", redirect: "follow" },
      15000  // 15s timeout for ping
    );
    const text = await resp.text();
    if (!text || text.length < 2) throw new Error("Empty response — check that the URL is a valid Apps Script deployment");
    const result = this._parseResponse(text);
    if (!result) throw new Error("Server returned invalid response — verify the Apps Script is deployed as a Web App");
    return result;
  },

  async fetchAll(url, since, token) {
    let fetchUrl = url + "?action=list&clientId=dispatch-hq&token=" + encodeURIComponent(token || "");
    if (since) fetchUrl += "&since=" + encodeURIComponent(since);
    const resp = await this._fetchWithTimeout(fetchUrl, { method: "GET", redirect: "follow" }, 60000);  // 60s for large pulls
    const text = await resp.text();
    if (!text || text.length < 2) throw new Error("Empty response from server");
    const result = this._parseResponse(text);
    if (!result) throw new Error("Server returned invalid data");
    return result;
  },

  async batchSync(url, records, token) {
    return this._gasPost(url, { action: "batchSync", records, clientId: "dispatch-hq", token });
  },

  async deleteRecord(url, id, token) {
    return this._gasPost(url, { action: "delete", id, clientId: "dispatch-hq", token });
  }
};

// ── Sync Config Storage (non-sensitive — stored in localStorage) ──
const SYNC_CONFIG_KEY = "dispatch-hq-sync-config";
function loadSyncConfig() {
  try {
    const raw = localStorage.getItem(SYNC_CONFIG_KEY);
    if (!raw) return { endpointUrl: "https://script.google.com/macros/s/AKfycbzRFmi7dn8yy_u6m0YCz7YCHt-_-PNm6VHOVdOMixf_vMBq0SF3lWg1sEQhwWI2J8I-/exec", passphraseHash: "", lastSync: "", authToken: "" };
    const parsed = JSON.parse(raw);
    if (typeof parsed !== "object" || parsed === null) return { endpointUrl: "https://script.google.com/macros/s/AKfycbzRFmi7dn8yy_u6m0YCz7YCHt-_-PNm6VHOVdOMixf_vMBq0SF3lWg1sEQhwWI2J8I-/exec", passphraseHash: "", lastSync: "" };
    return {
      endpointUrl: typeof parsed.endpointUrl === "string" && parsed.endpointUrl ? parsed.endpointUrl : "https://script.google.com/macros/s/AKfycbzRFmi7dn8yy_u6m0YCz7YCHt-_-PNm6VHOVdOMixf_vMBq0SF3lWg1sEQhwWI2J8I-/exec",
      passphraseHash: typeof parsed.passphraseHash === "string" ? parsed.passphraseHash : "",
      lastSync: typeof parsed.lastSync === "string" ? parsed.lastSync : "",
      authToken: typeof parsed.authToken === "string" && parsed.authToken ? parsed.authToken : "kX9mP2vQ8nL5wR3jF7tY4cH6dA1sE0bN"
    };
  } catch { return { endpointUrl: "https://script.google.com/macros/s/AKfycbzRFmi7dn8yy_u6m0YCz7YCHt-_-PNm6VHOVdOMixf_vMBq0SF3lWg1sEQhwWI2J8I-/exec", passphraseHash: "", lastSync: "", authToken: "kX9mP2vQ8nL5wR3jF7tY4cH6dA1sE0bN" }; }
}
function saveSyncConfig(config) {
  try { localStorage.setItem(SYNC_CONFIG_KEY, JSON.stringify(config)); } catch {}
}

const MAPS_KEY_STORAGE = "dispatch-hq-maps-key";
function loadMapsKey() { try { return localStorage.getItem(MAPS_KEY_STORAGE) || ""; } catch { return ""; } }
function saveMapsKey(k) { try { if (k) localStorage.setItem(MAPS_KEY_STORAGE, k); else localStorage.removeItem(MAPS_KEY_STORAGE); } catch {} }

// Dynamically load Google Maps Places library once
let mapsLoadState = "idle"; // idle | loading | ready | error
let mapsReadyCbs = [];
function ensureMapsLoaded(apiKey, cb) {
  if (mapsLoadState === "ready") { cb(true); return; }
  if (mapsLoadState === "error") { cb(false); return; }
  mapsReadyCbs.push(cb);
  if (mapsLoadState === "loading") return;
  mapsLoadState = "loading";
  const s = document.createElement("script");
  s.src = `https://maps.googleapis.com/maps/api/js?key=${apiKey}&libraries=places&loading=async&v=weekly`;
  s.async = true;
  s.onload = () => { mapsLoadState = "ready"; mapsReadyCbs.forEach(f => f(true)); mapsReadyCbs = []; };
  s.onerror = () => { mapsLoadState = "error"; mapsReadyCbs.forEach(f => f(false)); mapsReadyCbs = []; };
  document.head.appendChild(s);
}
// ── Complete Price Book (from Gemini-generated pricebook) ──
const TOWN_PRICES = {
  // NJ
  "allendale": { NJ: 75, MHT: 85, LGA: 85, EWR: 85, JFK: 115 },
  "alpine": { NJ: 40, MHT: 70, LGA: 70, EWR: 70, JFK: 100 },
  "bayonne": { NJ: 50, MHT: 50, LGA: 75, EWR: 65, JFK: 105 },
  "beleville": { NJ: 50, MHT: 50, LGA: 75, EWR: 65, JFK: 105 },
  "bergenfield": { NJ: 20, MHT: 45, LGA: 65, EWR: 55, JFK: 95 },
  "blauvelt": { NJ: 50, MHT: 55, LGA: 80, EWR: 70, JFK: 100 },
  "bloomfield": { NJ: 50, MHT: 55, LGA: 80, EWR: 70, JFK: 100 },
  "bogota": { NJ: 20, MHT: 40, LGA: 65, EWR: 55, JFK: 85 },
  "caldwell": { NJ: 50, MHT: 60, LGA: 85, EWR: 75, JFK: 105 },
  "carlstadt": { NJ: 35, MHT: 45, LGA: 70, EWR: 60, JFK: 90 },
  "cliffside park": { NJ: 15, MHT: 40, LGA: 50, EWR: 40, JFK: 70 },
  "clifton": { NJ: 40, MHT: 50, LGA: 75, EWR: 65, JFK: 95 },
  "closter": { NJ: 30, MHT: 70, LGA: 70, EWR: 60, JFK: 100 },
  "cresskill": { NJ: 30, MHT: 70, LGA: 70, EWR: 60, JFK: 100 },
  "demarest": { NJ: 30, MHT: 70, LGA: 70, EWR: 60, JFK: 100 },
  "dover": { NJ: 75, MHT: 80, LGA: 105, EWR: 95, JFK: 105 },
  "dumont": { NJ: 40, MHT: 70, LGA: 70, EWR: 70, JFK: 100 },
  "east brunswick": { NJ: 75, MHT: 80, LGA: 105, EWR: 95, JFK: 125 },
  "east orange": { NJ: 50, MHT: 55, LGA: 80, EWR: 70, JFK: 100 },
  "e.rutherford": { NJ: 30, MHT: 40, LGA: 65, EWR: 55, JFK: 85 },
  "east rutherford": { NJ: 30, MHT: 40, LGA: 65, EWR: 55, JFK: 85 },
  "edgewater": { NJ: 15, MHT: 60, LGA: 60, EWR: 50, JFK: 90 },
  "edison": { NJ: 70, MHT: 70, LGA: 95, EWR: 85, JFK: 105 },
  "elizabeth": { NJ: 50, MHT: 55, LGA: 80, EWR: 70, JFK: 100 },
  "elmwood park": { NJ: 40, MHT: 50, LGA: 75, EWR: 65, JFK: 95 },
  "emerson": { NJ: 40, MHT: 50, LGA: 75, EWR: 65, JFK: 95 },
  "englewood": { NJ: 15, MHT: 60, LGA: 60, EWR: 50, JFK: 90 },
  "englewood cliff": { NJ: 15, MHT: 40, LGA: 60, EWR: 50, JFK: 90 },
  "englewood cliffs": { NJ: 15, MHT: 40, LGA: 60, EWR: 50, JFK: 90 },
  "fairfield": { NJ: 55, MHT: 60, LGA: 85, EWR: 75, JFK: 105 },
  "fair lawn": { NJ: 30, MHT: 50, LGA: 75, EWR: 65, JFK: 95 },
  "fairlawn": { NJ: 30, MHT: 50, LGA: 75, EWR: 65, JFK: 95 },
  "fair view": { NJ: 15, MHT: 40, LGA: 60, EWR: 50, JFK: 80 },
  "fairview": { NJ: 15, MHT: 40, LGA: 60, EWR: 50, JFK: 80 },
  "fort lee": { NJ: 10, MHT: 50, LGA: 50, EWR: 40, JFK: 70, Flushing: 60 },
  "franklin lakes": { NJ: 55, MHT: 80, LGA: 80, EWR: 70, JFK: 110 },
  "freehold": { NJ: 100, MHT: 105, LGA: 130, EWR: 120, JFK: 150 },
  "garfield": { NJ: 35, MHT: 45, LGA: 65, EWR: 55, JFK: 95 },
  "glen rock": { NJ: 40, MHT: 80, LGA: 80, EWR: 80, JFK: 110 },
  "guttenberg": { NJ: 40, MHT: 50, LGA: 75, EWR: 65, JFK: 95 },
  "hackensack": { NJ: 25, MHT: 65, LGA: 65, EWR: 55, JFK: 95 },
  "harrington park": { NJ: 40, MHT: 45, LGA: 80, EWR: 80, JFK: 110 },
  "hasbrook hts.": { NJ: 30, MHT: 50, LGA: 75, EWR: 65, JFK: 95 },
  "hasbrouck heights": { NJ: 30, MHT: 50, LGA: 75, EWR: 65, JFK: 95 },
  "haworth": { NJ: 40, MHT: 45, LGA: 75, EWR: 65, JFK: 95 },
  "hillsdale": { NJ: 40, MHT: 50, LGA: 75, EWR: 65, JFK: 95 },
  "hillside": { NJ: 45, MHT: 50, LGA: 75, EWR: 50, JFK: 80 },
  "hoboken": { NJ: 45, MHT: 55, LGA: 70, EWR: 60, JFK: 90 },
  "ho-ho-kus": { NJ: 50, MHT: 40, LGA: 80, EWR: 80, JFK: 120 },
  "hohokus": { NJ: 50, MHT: 40, LGA: 80, EWR: 80, JFK: 120 },
  "holmdel": { NJ: 90, MHT: 90, LGA: 115, EWR: 105, JFK: 135 },
  "jersey city": { NJ: 40, MHT: 40, LGA: 65, EWR: 55, JFK: 85 },
  "kinnelon": { MHT: 75, LGA: 100, EWR: 90, JFK: 120 },
  "ledgewood": { NJ: 85, MHT: 90, LGA: 115, EWR: 105, JFK: 135 },
  "leonia": { NJ: 10, MHT: 50, LGA: 50, EWR: 50, JFK: 80 },
  "lincoln park": { NJ: 60, MHT: 65, LGA: 90, EWR: 80, JFK: 110 },
  "little ferry": { NJ: 15, MHT: 40, LGA: 60, EWR: 50, JFK: 80 },
  "livingston": { NJ: 60, MHT: 60, LGA: 100, EWR: 75, JFK: 150 },
  "lodi": { NJ: 35, MHT: 45, LGA: 70, EWR: 60, JFK: 90 },
  "lyndhurst": { NJ: 40, MHT: 40, LGA: 65, EWR: 55, JFK: 95 },
  "madison": { NJ: 65, MHT: 70, LGA: 95, EWR: 85, JFK: 115 },
  "mahwah": { NJ: 60, MHT: 65, LGA: 90, EWR: 80, JFK: 120 },
  "maywood": { NJ: 35, MHT: 45, LGA: 70, EWR: 60, JFK: 100 },
  "millburn": { NJ: 60, MHT: 55, LGA: 80, EWR: 70, JFK: 100 },
  "montclair": { NJ: 50, MHT: 55, LGA: 80, EWR: 70, JFK: 120 },
  "montvale": { NJ: 55, MHT: 60, LGA: 75, EWR: 65, JFK: 95 },
  "montville": { NJ: 65, MHT: 70, LGA: 95, EWR: 85, JFK: 115 },
  "moonachie": { NJ: 20, MHT: 40, LGA: 65, EWR: 55, JFK: 85 },
  "morristown": { NJ: 70, MHT: 75, LGA: 100, EWR: 90, JFK: 120 },
  "nanuet": { NJ: 60, MHT: 65, LGA: 90, EWR: 80, JFK: 110 },
  "newark": { NJ: 50, MHT: 50, LGA: 75, EWR: 65, JFK: 95 },
  "new brunswick": { NJ: 80, MHT: 80, LGA: 105, EWR: 95, JFK: 125 },
  "new milford": { NJ: 35, MHT: 45, LGA: 65, EWR: 55, JFK: 85 },
  "new port": { NJ: 45, MHT: 40, LGA: 65, EWR: 55, JFK: 85 },
  "north arlington": { NJ: 45, MHT: 50, LGA: 75, EWR: 65, JFK: 95 },
  "north bergen": { NJ: 20, MHT: 40, LGA: 65, EWR: 55, JFK: 85 },
  "north brunswick": { NJ: 75, MHT: 80, LGA: 105, EWR: 95, JFK: 125 },
  "north caldwell": { NJ: 55, MHT: 60, LGA: 85, EWR: 75, JFK: 105 },
  "n.plainfield": { NJ: 90, MHT: 75, LGA: 100, EWR: 95, JFK: 120 },
  "northvale": { NJ: 45, MHT: 55, LGA: 80, EWR: 70, JFK: 100 },
  "norwood": { NJ: 40, MHT: 50, LGA: 75, EWR: 65, JFK: 95 },
  "nutley": { NJ: 50, MHT: 45, LGA: 80, EWR: 70, JFK: 100 },
  "nyack": { NJ: 60, MHT: 65, LGA: 90, EWR: 80, JFK: 110 },
  "oakland": { NJ: 55, MHT: 60, LGA: 85, EWR: 75, JFK: 105 },
  "old tappan": { NJ: 45, MHT: 55, LGA: 80, EWR: 70, JFK: 100 },
  "oradell": { NJ: 40, MHT: 50, LGA: 75, EWR: 65, JFK: 95 },
  "orange": { NJ: 60, MHT: 55, LGA: 80, EWR: 70, JFK: 70 },
  "palisades park": { NJ: 10, MHT: 35, LGA: 50, EWR: 40, JFK: 70 },
  "paramus": { NJ: 35, MHT: 45, LGA: 65, EWR: 55, JFK: 85 },
  "park ridge": { NJ: 50, MHT: 55, LGA: 80, EWR: 70, JFK: 100 },
  "parsippany": { NJ: 60, MHT: 70, LGA: 85, EWR: 75, JFK: 105 },
  "passaic": { NJ: 45, MHT: 50, LGA: 75, EWR: 65, JFK: 95 },
  "paterson": { NJ: 45, MHT: 50, LGA: 75, EWR: 65, JFK: 95 },
  "pine brook": { NJ: 70, MHT: 75, LGA: 100, EWR: 90, JFK: 120 },
  "plainfield": { NJ: 70, MHT: 75, LGA: 100, EWR: 90, JFK: 120 },
  "princeton": { NJ: 105, MHT: 105, LGA: 145, EWR: 135, JFK: 165 },
  "rahway": { NJ: 55, MHT: 65, LGA: 90, EWR: 80, JFK: 110 },
  "ramsey": { NJ: 60, MHT: 60, LGA: 85, EWR: 75, JFK: 105 },
  "ridgefield": { NJ: 10, MHT: 35, LGA: 50, EWR: 40, JFK: 70 },
  "ridgefield park": { NJ: 15, MHT: 40, LGA: 50, EWR: 40, JFK: 70 },
  "ridgewood": { NJ: 35, MHT: 50, LGA: 75, EWR: 65, JFK: 95 },
  "riveredge": { NJ: 40, MHT: 45, LGA: 70, EWR: 60, JFK: 90 },
  "river edge": { NJ: 40, MHT: 45, LGA: 70, EWR: 60, JFK: 90 },
  "rochelle park": { NJ: 35, MHT: 45, LGA: 70, EWR: 60, JFK: 90 },
  "rockaway": { NJ: 65, MHT: 70, LGA: 100, EWR: 90, JFK: 120 },
  "rockleigh": { NJ: 45, MHT: 50, LGA: 75, EWR: 65, JFK: 95 },
  "rutherford": { NJ: 35, MHT: 40, LGA: 65, EWR: 55, JFK: 85 },
  "saddle brook": { NJ: 35, MHT: 45, LGA: 70, EWR: 60, JFK: 90 },
  "saddle river": { NJ: 50, MHT: 55, LGA: 80, EWR: 70, JFK: 100 },
  "secaucus": { NJ: 35, MHT: 40, LGA: 65, EWR: 55, JFK: 85 },
  "six flag": { NJ: 120 },
  "spring valley": { NJ: 85, MHT: 85, LGA: 110, EWR: 100, JFK: 130 },
  "summit": { NJ: 65, MHT: 65, LGA: 90, EWR: 80, JFK: 110 },
  "teaneck": { NJ: 20, MHT: 40, LGA: 60, EWR: 50, JFK: 80 },
  "tenafly": { NJ: 30, MHT: 45, LGA: 65, EWR: 55, JFK: 85 },
  "teterboro": { NJ: 20, MHT: 40, LGA: 65, EWR: 55, JFK: 85 },
  "totowa": { NJ: 50, MHT: 55, LGA: 80, EWR: 70, JFK: 100 },
  "towaco": { NJ: 65, MHT: 60, LGA: 95, EWR: 85, JFK: 115 },
  "trenton": { NJ: 120, MHT: 120, LGA: 145, EWR: 135, JFK: 165 },
  "union": { NJ: 50, MHT: 55, LGA: 80, EWR: 70, JFK: 100 },
  "union city": { NJ: 35, MHT: 40, LGA: 65, EWR: 55, JFK: 85 },
  "upper saddle river": { NJ: 55, MHT: 60, LGA: 85, EWR: 75, JFK: 105 },
  "waldwick": { NJ: 50, MHT: 55, LGA: 80, EWR: 70, JFK: 100 },
  "wallington": { NJ: 35, MHT: 45, LGA: 70, EWR: 60, JFK: 90 },
  "washington twp": { NJ: 45, MHT: 50, LGA: 75, EWR: 65, JFK: 95 },
  "watchung": { NJ: 75, MHT: 75, LGA: 100, EWR: 90, JFK: 120 },
  "wayne": { NJ: 55, MHT: 60, LGA: 85, EWR: 75, JFK: 115 },
  "weehawken": { NJ: 35, MHT: 40, LGA: 65, EWR: 55, JFK: 95 },
  "westfield": { NJ: 65, MHT: 65, LGA: 90, EWR: 80, JFK: 120 },
  "west new york": { NJ: 30, MHT: 40, LGA: 65, EWR: 55, JFK: 95 },
  "west orange": { NJ: 55, MHT: 60, LGA: 85, EWR: 75, JFK: 115 },
  "woodbridge": { NJ: 65, MHT: 70, LGA: 95, EWR: 85, JFK: 125 },
  "woodcliff lake": { NJ: 50, MHT: 55, LGA: 80, EWR: 70, JFK: 110 },
  "woodridge": { NJ: 30, MHT: 40, LGA: 65, EWR: 55, JFK: 95 },
  "wyckoff": { NJ: 50, MHT: 55, LGA: 80, EWR: 70, JFK: 110 },
  "westwood": { NJ: 45, MHT: 55, LGA: 80, EWR: 70, JFK: 110 },
  // Manhattan
  "manhattan": { JFK: 97, LGA: 77, EWR: 115 }, // base + tolls + congestion
  "midtown": { JFK: 97, LGA: 77, EWR: 115 },
  "downtown": { JFK: 97, LGA: 77, EWR: 115 },
  "upper east side": { JFK: 97, LGA: 77, EWR: 115 },
  "upper west side": { JFK: 97, LGA: 77, EWR: 115 },
  "harlem": { JFK: 97, LGA: 77, EWR: 115 },
  // Nassau County
  "new hyde park": { Flushing: 35, MHT: 65, LGA: 45, JFK: 45, EWR: 95 },
  "albertson": { Flushing: 40, MHT: 70, LGA: 50, JFK: 50, EWR: 100 },
  "atlantic beach": { Flushing: 70, MHT: 100, LGA: 80, JFK: 80, EWR: 130 },
  "baldwin": { Flushing: 60, MHT: 90, LGA: 70, JFK: 70, EWR: 120 },
  "bellmore": { Flushing: 70, MHT: 100, LGA: 80, JFK: 80, EWR: 130 },
  "bethpage": { Flushing: 60, MHT: 90, LGA: 70, JFK: 70, EWR: 120 },
  "cedarhurst": { Flushing: 50, MHT: 80, LGA: 60, JFK: 50, EWR: 110 },
  "east meadow": { Flushing: 50, MHT: 80, LGA: 60, JFK: 60, EWR: 110 },
  "elmont": { Flushing: 40, MHT: 70, LGA: 50, JFK: 50, EWR: 100 },
  "farmingdale": { Flushing: 65, MHT: 95, LGA: 75, JFK: 70, EWR: 125 },
  "floral park": { Flushing: 30, MHT: 60, LGA: 40, JFK: 40, EWR: 90 },
  "franklin square": { Flushing: 50, MHT: 80, LGA: 60, JFK: 50, EWR: 110 },
  "freeport": { Flushing: 60, MHT: 90, LGA: 70, JFK: 70, EWR: 120 },
  "garden city": { Flushing: 40, MHT: 70, LGA: 50, JFK: 50, EWR: 100 },
  "glen cove": { Flushing: 60, MHT: 90, LGA: 70, JFK: 70, EWR: 120 },
  "great neck": { Flushing: 30, MHT: 60, LGA: 40, JFK: 50, EWR: 90 },
  "hempstead": { Flushing: 45, MHT: 75, LGA: 55, JFK: 55, EWR: 105 },
  "long beach": { Flushing: 90, MHT: 120, LGA: 100, JFK: 100, EWR: 150 },
  "lynbrook": { Flushing: 45, MHT: 75, LGA: 65, JFK: 55, EWR: 105 },
  "manhasset": { Flushing: 35, MHT: 65, LGA: 45, JFK: 55, EWR: 95 },
  "massapequa": { Flushing: 80, MHT: 110, LGA: 90, JFK: 90, EWR: 140 },
  "mineola": { Flushing: 40, MHT: 70, LGA: 50, JFK: 50, EWR: 100 },
  "oceanside": { Flushing: 70, MHT: 100, LGA: 80, JFK: 80, EWR: 130 },
  "rockville centre": { Flushing: 50, MHT: 80, LGA: 60, JFK: 60, EWR: 110 },
  "roslyn": { JFK: 60, LGA: 45, EWR: 75, MHT: 75, Flushing: 40 },
  "roslyn heights": { JFK: 65, LGA: 50, EWR: 80, MHT: 80, Flushing: 45 },
  "syosset": { Flushing: 60, MHT: 90, LGA: 70, JFK: 70, EWR: 120 },
  "valley stream": { Flushing: 50, MHT: 80, LGA: 60, JFK: 50, EWR: 110 },
  "westbury": { Flushing: 50, MHT: 80, LGA: 60, JFK: 60, EWR: 110 },
  // Suffolk County
  "bayshore": { Flushing: 80, MHT: 110, LGA: 90, JFK: 90, EWR: 140 },
  "bay shore": { Flushing: 80, MHT: 110, LGA: 90, JFK: 90, EWR: 140 },
  // Flushing / Queens local
  "flushing": { JFK: 20, LGA: 15, EWR: 80, MHT: 50 },
  "queens": { JFK: 30, LGA: 25, EWR: 85, MHT: 55 },
  "forest hills": { JFK: 25, LGA: 20, EWR: 85, MHT: 55 },
  "jackson heights": { JFK: 25, LGA: 20, EWR: 80, MHT: 50 },
  "elmhurst": { JFK: 25, LGA: 20, EWR: 80, MHT: 50 },
  "corona": { JFK: 25, LGA: 20, EWR: 80, MHT: 50 },
  "astoria": { JFK: 30, LGA: 20, EWR: 85, MHT: 55 },
  "woodside": { JFK: 25, LGA: 20, EWR: 80, MHT: 50 },
  "bayside": { JFK: 35, LGA: 30, EWR: 90, MHT: 60 },
  // Brooklyn
  "brooklyn": { JFK: 40, LGA: 45, EWR: 95, MHT: 65 },
  // Bronx
  "bronx": { JFK: 60, LGA: 50, EWR: 100, MHT: 60 },
  // Staten Island
  "staten island": { JFK: 60, LGA: 65, EWR: 85, MHT: 80 },
};

// Airport/anchor detection
function getAnchorCode(str) {
  const s = str.toUpperCase().trim();
  if (s.includes("JFK") || s.includes("KENNEDY")) return "JFK";
  if (s.includes("LGA") || s.includes("LAGUARDIA") || s.includes("LA GUARDIA")) return "LGA";
  if (s.includes("NEWARK") || s.includes("EWR")) return "EWR";
  if (s.includes("FLUSHING")) return "Flushing";
  if (s.includes("MHT") || s.includes("MANHATTAN") || s.includes("MIDTOWN") ||
      s.includes("DOWNTOWN") || s.includes("NEW YORK CITY") || s.includes("NYC") ||
      s.includes("TIMES SQUARE") || s.includes("PENN STATION") || s.includes("GRAND CENTRAL")) {
    if (!s.includes("MANHATTAN BEACH")) return "MHT";
  }
  return null;
}

// Normalize town name for lookup
function normalizeTown(str) {
  return str.toLowerCase().trim().replace(/\s+/g, " ").replace(/[.,#]/g, "");
}

// Main fare calculator
function lookupFlatRate(pickup, dropoff) {
  const pAnchor = getAnchorCode(pickup);
  const dAnchor = getAnchorCode(dropoff);
  const anchor = pAnchor || dAnchor;

  // ── Airport route: one side is an airport ──
  if (anchor) {
    const townStr = normalizeTown(pAnchor ? dropoff : pickup);
    const match = Object.keys(TOWN_PRICES)
      .sort((a, b) => b.length - a.length)
      .find(town => townStr.includes(town));
    if (!match) return null;
    const prices = TOWN_PRICES[match];
    const base = prices[anchor];
    if (!base) return null;
    let fare = base;
    let breakdown = match + " → " + anchor;
    if (anchor === "EWR") {
      const isNJ = "NJ" in prices;
      fare += isNJ ? 14 : 54;
      breakdown += isNJ ? " +$14 toll" : " +$54 tolls";
    }
    return { fare, route: pickup + " → " + dropoff, breakdown };
  }

  // ── Non-airport route: town → town ──
  // Detect destination type from dropoff
  const doLower = normalizeTown(dropoff);
  const puLower = normalizeTown(pickup);

  // Determine destination column
  let destCol = null;
  if (doLower.includes("manhattan") || doLower.includes("midtown") || doLower.includes("downtown") || doLower.includes("new york city") || doLower.includes("nyc") || doLower.includes("times square") || doLower.includes("penn station") || doLower.includes("grand central") || doLower.includes("upper east") || doLower.includes("upper west") || doLower.includes("tribeca") || doLower.includes("soho") || doLower.includes("chelsea")) destCol = "MHT";
  else if (doLower.includes("flushing")) destCol = "Flushing";
  else if (doLower.includes("queens") || doLower.includes("bayside") || doLower.includes("fresh meadows") || doLower.includes("jamaica") || doLower.includes("forest hills") || doLower.includes("astoria") || doLower.includes("corona") || doLower.includes("elmhurst") || doLower.includes("woodside") || doLower.includes("jackson heights") || doLower.includes("rego park")) destCol = "LGA";
  else if (doLower.includes("brooklyn") || doLower.includes("bronx") || doLower.includes("staten island")) destCol = "JFK";

  if (destCol) {
    // Pickup is a town
    const match = Object.keys(TOWN_PRICES)
      .sort((a, b) => b.length - a.length)
      .find(town => puLower.includes(town));
    if (match && TOWN_PRICES[match][destCol]) {
      const fare = TOWN_PRICES[match][destCol];
      return { fare, route: pickup + " → " + dropoff, breakdown: match + " → " + destCol };
    }
  }

  // Try reverse — dropoff is the town, pickup is a destination type
  const puDest = (() => {
    if (puLower.includes("manhattan") || puLower.includes("midtown") || puLower.includes("nyc")) return "MHT";
    if (puLower.includes("flushing")) return "Flushing";
    if (puLower.includes("queens") || puLower.includes("bayside")) return "LGA";
    return null;
  })();
  if (puDest) {
    const match = Object.keys(TOWN_PRICES)
      .sort((a, b) => b.length - a.length)
      .find(town => doLower.includes(town));
    if (match && TOWN_PRICES[match][puDest]) {
      const fare = TOWN_PRICES[match][puDest];
      return { fare, route: pickup + " → " + dropoff, breakdown: match + " → " + puDest };
    }
  }

  // NJ town → NJ town (use NJ column)
  const puMatch = Object.keys(TOWN_PRICES).sort((a,b)=>b.length-a.length).find(t => puLower.includes(t) && "NJ" in TOWN_PRICES[t]);
  const doMatch = Object.keys(TOWN_PRICES).sort((a,b)=>b.length-a.length).find(t => doLower.includes(t) && "NJ" in TOWN_PRICES[t]);
  if (puMatch && doMatch && puMatch !== doMatch) {
    const fare = Math.round((TOWN_PRICES[puMatch].NJ + TOWN_PRICES[doMatch].NJ) / 2 + 15);
    return { fare, route: pickup + " → " + dropoff, breakdown: puMatch + " ↔ " + doMatch };
  }

  return null;
}


// Normalize location text for matching
function normalizeLocation(text) {
  if (!text) return "";
  const t = text.toLowerCase().trim();
  // Airport codes
  if (/\bjfk\b|john f\.?\s*kennedy|kennedy airport/.test(t)) return "JFK";
  if (/\blga\b|laguardia|la\s*guardia/.test(t)) return "LGA";
  if (/\bewr\b|newark\s*(liberty)?\s*airport|newark\s*ewr/.test(t)) return "EWR";
  // NYC Boroughs
  if (/\bmanhattan\b|\bmidtown\b|\bdowntown\b|\buptown\b|\bupper\s*(east|west)\b|\blower\s*(east|manhattan)\b|\btimes\s*sq/.test(t)) return "Manhattan";
  if (/\bbrooklyn\b|\bbushwick\b|\bwilliamsburg\b|\bpark\s*slope\b|\bbay\s*ridge\b|\bsunset\s*park\b|\bflatbush\b/.test(t)) return "Brooklyn";
  if (/\bqueens\b|\bjamaica\b|\bastoria\b|\blong\s*island\s*city\b|\blic\b|\belmhurst\b|\bjackson\s*heights\b|\bbayside\b/.test(t)) return "Queens";
  if (/\bbronx\b|\briverdale\b/.test(t)) return "Bronx";
  if (/\bstaten\s*island\b/.test(t)) return "Staten Island";
  if (/\bflushing\b/.test(t)) return "Flushing";
  // NJ
  if (/\bfort\s*lee\b/.test(t)) return "Fort Lee";
  if (/\bpalisades?\s*park\b|\bpalisade\b/.test(t)) return "Palisades Park";
  if (/\bnew\s*jersey\b|\bnj\b|\bjersey\s*city\b|\bhoboken\b|\bnewark\b(?!.*airport)/.test(t)) return "New Jersey";
  // CT
  if (/\bconnecticut\b|\bct\b|\bstamford\b|\bgreenwich\b|\bnorwalk\b|\bdanbury\b/.test(t)) return "Connecticut";
  if (/\bhartford\b|\bnew\s*haven\b|\bbridgeport\b/.test(t)) return "Connecticut";
  // LI / Westchester
  if (/\blong\s*island\b|\bnassau\b|\bgarden\s*city\b|\bhempstead\b|\bmineola\b/.test(t)) return "Long Island";
  if (/\bsuffolk\b|\bhuntington\b|\bbabylon\b|\bislip\b/.test(t)) return "Long Island";
  if (/\bwestchester\b|\bwhite\s*plains\b|\byonkers\b|\bnew\s*rochelle\b|\btarrytown\b/.test(t)) return "Westchester";
  return t;
}

function getSubZone(text) {
  if (!text) return null;
  const t = text.toLowerCase();
  if (/midtown|times\s*sq|herald|penn\s*sta|34th|42nd|50th/.test(t)) return "Midtown";
  if (/downtown|financial|wall\s*st|tribeca|soho|lower\s*manhattan|battery/.test(t)) return "Downtown";
  if (/uptown|harlem|upper\s*(east|west)|morningside|washington\s*heights|inwood/.test(t)) return "Uptown";
  if (/north\s*(?:nj|jersey)|bergen|hackensack|teaneck|englewood|fort\s*lee|palisade/.test(t)) return "North NJ";
  if (/central\s*(?:nj|jersey)|edison|new\s*brunswick|woodbridge|princeton/.test(t)) return "Central NJ";
  if (/stamford|greenwich|norwalk|darien|westport/.test(t)) return "Stamford";
  if (/hartford|new\s*haven|bridgeport|waterbury|danbury/.test(t)) return "Hartford";
  if (/nassau|garden\s*city|hempstead|mineola|great\s*neck/.test(t)) return "Nassau";
  if (/suffolk|huntington|babylon|islip|smithtown/.test(t)) return "Suffolk";
  return null;
}




// ── AI Assist Service — Anthropic API with Parallel Tool Calling ──
const TOOL_DEFINITIONS = [
  {
    name: "lookup_flight_status",
    description: "Look up current flight status, arrival/departure times, delays, gate, and terminal info. Use for any flight-related query. Can search by flight number (e.g. KE81, UA123, OZ222) or by airline + city.",
    input_schema: {
      type: "object",
      properties: {
        flight_number: { type: "string", description: "IATA flight number, e.g. 'KE81', 'UA123', 'DL456'" },
        airline: { type: "string", description: "Airline name if flight number not provided, e.g. 'Korean Air', 'United'" },
        city: { type: "string", description: "Origin or destination city to filter flights, e.g. 'Seoul', 'Los Angeles'" },
        date: { type: "string", description: "Flight date in YYYY-MM-DD format" }
      },
      required: []
    }
  },
  {
    name: "calculate_fare",
    description: "Calculate the flat-rate taxi fare between a pickup location and dropoff location in the NYC/NJ/CT metro area. Handles airports (JFK, LGA, EWR), Manhattan zones, boroughs, NJ, CT, Long Island, Westchester, Flushing, Fort Lee, Palisades Park. Returns fare breakdown with tolls.",
    input_schema: {
      type: "object",
      properties: {
        pickup_location: { type: "string", description: "Pickup address or area name" },
        dropoff_location: { type: "string", description: "Dropoff address or area name" },
        trip_type: { type: "string", enum: ["one-way", "round-trip"], description: "Trip type for fare calculation" },
        num_passengers: { type: "integer", description: "Number of passengers (surcharge may apply for 5+)" }
      },
      required: ["pickup_location", "dropoff_location"]
    }
  }
];

async function executeToolCall(toolName, toolInput) {
  if (toolName === "lookup_flight_status") {
    return executeFlight(toolInput);
  }
  if (toolName === "calculate_fare") {
    return executeFare(toolInput);
  }
  return { error: "Unknown tool" };
}

function executeFare(input) {
  const result = lookupFlatRate(input.pickup_location, input.dropoff_location);
  if (!result) {
    return { found: false, message: `No preset rate for this route. Enter a custom amount.` };
  }

  let total = result.fare;
  const surcharges = [];
  if (result.breakdown) surcharges.push(result.breakdown);

  // Airport pickup fee
  const pAnchor = getAnchorCode(input.pickup_location || "");
  const isAirportPickup = pAnchor === "JFK" || pAnchor === "LGA" || pAnchor === "EWR";
  const dAnchor = getAnchorCode(input.dropoff_location || "");
  const isAirportTrip = isAirportPickup || dAnchor === "JFK" || dAnchor === "LGA" || dAnchor === "EWR";

  if (isAirportPickup) {
    total += 5;
    surcharges.push("+$5 airport pickup");
  }

  // Passenger/luggage surcharges
  const pax = parseInt(input.num_passengers) || 1;
  const bags = parseInt(input.num_luggage) || 0;

  if (isAirportTrip) {
    if (pax === 4 || pax === 5) { total *= 1.5; surcharges.push("x1.5 (4-5 pax)"); }
    else if (pax >= 6) { total *= 2.0; surcharges.push("x2 (6+ pax)"); }
  } else {
    if (pax > 3) { const extra = (pax - 3) * 10; total += extra; surcharges.push(`+$${extra} extra pax`); }
    if (bags > 3) { const extra = (bags - 3) * 5; total += extra; surcharges.push(`+$${extra} extra bags`); }
  }

  // Round trip
  if (input.trip_type === "round-trip") {
    total *= 2;
    surcharges.push("x2 round-trip");
  }

  total = Math.round(total);

  return {
    found: true,
    route: result.route,
    base_fare: result.fare,
    surcharges,
    total,
    currency: "USD"
  };
}

async function executeFlight(input) {
  const fn = (input.flight_number || "").toUpperCase().replace(/\s+/g, "");
  if (!fn) return { error: "No flight number provided", status: "error" };

  try {
    const resp = await fetch(`/.netlify/functions/flight?flight=${encodeURIComponent(fn)}`, {
      signal: AbortSignal.timeout(10000)
    });
    const data = await resp.json();

    if (!resp.ok || data.error) {
      return { error: data.error || "Flight lookup failed", status: "error" };
    }
    if (!data.found) {
      return { error: "Flight not found", status: "unknown", flight_number: fn };
    }

    // Normalize to existing app format
    return {
      flight_number:      data.flight,
      airline:            data.airline,
      status:             data.statusRaw === "landed"    ? "landed"
                        : data.statusRaw === "active"    ? "in-air"
                        : data.statusRaw === "scheduled" ? "scheduled"
                        : data.statusRaw === "cancelled" ? "cancelled"
                        : data.statusRaw === "diverted"  ? "diverted"
                        : "unknown",
      delay_minutes:      data.delay || 0,
      scheduled_arrival:  data.scheduledArrival || "",
      actual_arrival:     data.actualArrival || "",
      destination_code:   data.arrival || "",
      origin_code:        data.departure || "",
      message:            data.message || "",
      found:              true,
    };
  } catch (err) {
    return { error: "Flight lookup failed: " + err.message, status: "error" };
  }
}

async function runAIAssist(flightNumber, airline, city, date, pickup, dropoff, tripType, passengers) {
  const hasFlightQuery = !!(flightNumber || airline);
  const hasFareQuery = !!(pickup && dropoff);
  if (!hasFlightQuery && !hasFareQuery) return { flight: null, fare: null };

  const results = { flight: null, fare: null };

  // Run flight + fare in parallel
  const tasks = [];

  if (hasFlightQuery) {
    tasks.push(
      executeFlight({ flight_number: flightNumber, airline, city, date })
        .then(r => { results.flight = r; })
        .catch(e => { results.flight = { error: e.message, status: "error" }; })
    );
  }

  if (hasFareQuery) {
    tasks.push(
      Promise.resolve(executeFare({ pickup_location: pickup, dropoff_location: dropoff, passengers: parseInt(passengers) || 1, trip_type: tripType || "one-way" }))
        .then(r => { results.fare = r; })
        .catch(e => { results.fare = { error: e.message }; })
    );
  }

  await Promise.all(tasks);
  return results;
}


// ── Driver Database ──
const DRIVERS = [
  // ── NYC Drivers ──
  { id: "808", name: "KANG K Y",  carType: "Silver Nissan SUV",         phone: "646-363-3340", airportPickup: true,  airportDropoff: false, shiftStart: "05:00", shiftEnd: "16:00", daysOff: ["Thursday"], specialShifts: [{ day: "Thursday", start: "05:00", end: "09:00" }], notes: "Thu 5am–9am only. No airport dropoff." },
  { id: "810", name: "SUK",       carType: "Black Kia SUV",             phone: "929-855-6507", airportPickup: true,  airportDropoff: true,  shiftStart: "10:00", shiftEnd: "22:00", daysOff: [], monthlyOff: [9, 19, 29], notes: "Off every 9th, 19th, 29th" },
  { id: "811", name: "PARK L B",  carType: "Black Toyota Avalon",       phone: "347-992-9014", airportPickup: true,  airportDropoff: true,  shiftStart: "07:00", shiftEnd: "19:00", daysOff: [], notes: "" },
  { id: "817", name: "KIM K O",   carType: "Silver Honda CRV",          phone: "347-610-1304", airportPickup: true,  airportDropoff: true,  shiftStart: "06:00", shiftEnd: "22:00", daysOff: ["Wednesday", "Saturday"], notes: "" },
  { id: "819", name: "KANG H D",  carType: "Silver Toyota Sienna",      phone: "929-800-0140", airportPickup: true,  airportDropoff: true,  shiftStart: "04:00", shiftEnd: "00:00", daysOff: [], notes: "" },
  { id: "820", name: "KANG KJ",   carType: "Black Hyundai Genesis",     phone: "718-909-5556", airportPickup: true,  airportDropoff: true,  shiftStart: "05:00", shiftEnd: "00:00", daysOff: [], notes: "" },
  { id: "830", name: "KIM JAMES", carType: "Bronze Toyota Sienna",      phone: "347-749-1680", airportPickup: true,  airportDropoff: true,  shiftStart: "05:00", shiftEnd: "00:00", daysOff: ["Monday", "Friday"], notes: "" },
  { id: "833", name: "KWON S H",  carType: "Silver Toyota Sienna",      phone: "917-621-7724", airportPickup: true,  airportDropoff: true,  shiftStart: "05:00", shiftEnd: "17:00", daysOff: [], notes: "" },
  { id: "835", name: "YUN G J",   carType: "Black Chevy SUV",           phone: "718-813-7557", airportPickup: true,  airportDropoff: false, shiftStart: "10:00", shiftEnd: "00:00", daysOff: ["Tuesday"], notes: "No airport dropoff." },
  { id: "837", name: "KIM Y S",   carType: "Black Toyota Highlander",   phone: "718-757-0861", airportPickup: true,  airportDropoff: true,  shiftStart: "10:00", shiftEnd: "19:00", daysOff: ["Monday", "Tuesday"], notes: "" },
  { id: "845", name: "NO N I",    carType: "Black Lexus SUV",           phone: "917-821-1114", airportPickup: false, airportDropoff: false, shiftStart: "07:00", shiftEnd: "19:00", daysOff: ["Thursday"], notes: "No airport service." },
  { id: "850", name: "KANG D R",  carType: "Silver Toyota Sienna",      phone: "646-302-4615", airportPickup: true,  airportDropoff: true,  shiftStart: "17:00", shiftEnd: "04:00", daysOff: ["Sunday"], notes: "Night shift (5pm–4am)" },
  { id: "855", name: "KIM B S",   carType: "Silver Toyota Sienna",      phone: "917-943-7337", airportPickup: true,  airportDropoff: true,  shiftStart: "05:00", shiftEnd: "15:00", daysOff: [], notes: "" },
  { id: "857", name: "SEO H G",   carType: "Black Honda Odyssey",       phone: "646-331-8785", airportPickup: true,  airportDropoff: true,  shiftStart: "08:00", shiftEnd: "18:00", daysOff: ["Wednesday", "Saturday"], notes: "" },
  { id: "860", name: "HAN S H",   carType: "Gray Toyota RAV4",          phone: "646-567-8644", airportPickup: false, airportDropoff: false, shiftStart: "07:00", shiftEnd: "22:00", daysOff: ["Wednesday"], notes: "No airport service." },
  { id: "877", name: "YI BOB",    carType: "White Honda Pilot",         phone: "646-886-6371", airportPickup: true,  airportDropoff: true,  shiftStart: "04:00", shiftEnd: "00:00", daysOff: [], notes: "" },
  { id: "887", name: "YUN J K",   carType: "White Infiniti SUV",        phone: "917-655-1737", airportPickup: true,  airportDropoff: false, shiftStart: "04:00", shiftEnd: "18:00", daysOff: ["Sunday"], specialShifts: [{ day: "Wednesday", start: "04:00", end: "12:00" }, { day: "Saturday", start: "04:00", end: "12:00" }], notes: "Wed/Sat: 4am–12pm. No airport dropoff." },
  { id: "888", name: "PARK J G",  carType: "White Toyota Sedan",        phone: "718-813-0448", airportPickup: true,  airportDropoff: false, shiftStart: "07:00", shiftEnd: "00:00", daysOff: ["Sunday"], notes: "No airport dropoff." },
  { id: "895", name: "LEE S I",   carType: "Black Honda RDX",           phone: "917-359-7779", airportPickup: true,  airportDropoff: true,  shiftStart: "10:00", shiftEnd: "20:00", daysOff: [], notes: "" },
  // ── NJ Drivers ──
  { id: "100", name: "YOO S H",   carType: "Gray Dodge Minivan",        phone: "201-286-4668", airportPickup: true,  airportDropoff: true,  shiftStart: "00:00", shiftEnd: "00:00", daysOff: [], notes: "🚗 NJ-based driver · 24hrs" },
  { id: "500", name: "SONG K Y",  carType: "Black Lexus SUV",           phone: "201-978-3898", airportPickup: true,  airportDropoff: true,  shiftStart: "00:00", shiftEnd: "00:00", daysOff: [], notes: "🚗 NJ-based driver · 24hrs" },
  { id: "802", name: "OH N S",    carType: "Black Infiniti SUV",        phone: "201-618-3007", airportPickup: true,  airportDropoff: true,  shiftStart: "00:00", shiftEnd: "00:00", daysOff: [], notes: "🚗 NJ-based driver · 24hrs" },
];

const DAYS = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];
const AM_SLOTS = ["4:00 AM","4:30 AM","5:00 AM","5:30 AM","6:00 AM","6:30 AM","7:00 AM","7:30 AM","8:00 AM","8:30 AM","9:00 AM","9:30 AM","10:00 AM","10:30 AM","11:00 AM","11:30 AM"];
const PM_SLOTS = ["12:00 PM","12:30 PM","1:00 PM","1:30 PM","2:00 PM","2:30 PM","3:00 PM","3:30 PM","4:00 PM","4:30 PM","5:00 PM","5:30 PM","6:00 PM","6:30 PM","7:00 PM","7:30 PM","8:00 PM","8:30 PM","9:00 PM","9:30 PM","10:00 PM","10:30 PM","11:00 PM","11:30 PM"];

function getDriverShift(driver, date) {
  // Parse "YYYY-MM-DD" as local time, not UTC (append T12:00:00 to avoid timezone shift)
  const d = new Date(date + "T12:00:00");
  const dayName = DAYS[d.getDay()];
  const dayOfMonth = d.getDate();
  if (driver.daysOff.includes(dayName)) {
    if (driver.specialShifts) {
      const sp = driver.specialShifts.find(s => s.day === dayName);
      if (sp) return { available: true, start: sp.start, end: sp.end, limited: true };
    }
    return { available: false };
  }
  if (driver.monthlyOff && driver.monthlyOff.includes(dayOfMonth)) return { available: false };
  if (driver.specialShifts) {
    const sp = driver.specialShifts.find(s => s.day === dayName);
    if (sp) return { available: true, start: sp.start, end: sp.end, limited: true };
  }
  return { available: true, start: driver.shiftStart, end: driver.shiftEnd, limited: false };
}

function getShiftLabel(driver) {
  if (driver.shiftStart === "00:00" && driver.shiftEnd === "00:00") return "24hrs";
  const s = parseInt(driver.shiftStart);
  const e = parseInt(driver.shiftEnd);
  if (s >= 17) return "Night";
  if (e <= 17) return "Morning";
  return "All-Day";
}

function formatTime24(t) {
  const [time, period] = t.split(" ");
  let [h, m] = time.split(":").map(Number);
  if (period === "PM" && h !== 12) h += 12;
  if (period === "AM" && h === 12) h = 0;
  return `${String(h).padStart(2,"0")}:${String(m).padStart(2,"0")}`;
}

function formatShiftDisplay(start, end) {
  const fmt = (t) => {
    let [h, m] = t.split(":").map(Number);
    const p = h >= 12 ? "PM" : "AM";
    if (h === 0) h = 12;
    else if (h > 12) h -= 12;
    return `${h}:${String(m).padStart(2,"0")}${p}`;
  };
  return `${fmt(start)} – ${fmt(end)}`;
}

// Check if a 12h time slot falls within a 24h shift window
function isTimeInShift(slot12h, shiftStart, shiftEnd) {
  const t24 = formatTime24(slot12h);
  const slotMins = parseInt(t24.split(":")[0]) * 60 + parseInt(t24.split(":")[1]);
  const startMins = parseInt(shiftStart.split(":")[0]) * 60 + parseInt(shiftStart.split(":")[1]);
  let endMins = parseInt(shiftEnd.split(":")[0]) * 60 + parseInt(shiftEnd.split(":")[1]);
  if (endMins === 0) endMins = 24 * 60;
  if (endMins <= startMins) {
    return slotMins >= startMins || slotMins < endMins;
  }
  return slotMins >= startMins && slotMins < endMins;
}

const INIT_FORM = { customerName: "", pickupAddress: "", dropoffAddress: "", airline: "", flightNumber: "", passengers: "1", luggage: "0", tripType: "one-way", phone: "", paymentAmount: "", driverNumber: "", date: new Date().toISOString().split("T")[0], timeSlot: "", customTime: "" };

// ── Storage helpers (hardened) ──
const STORAGE_KEY     = "taxi-bookings-data";      // plaintext (legacy / migration)
const ENC_STORAGE_KEY = "taxi-bookings-enc";       // encrypted (production)
const ENC_SALT_KEY    = "taxi-bookings-salt";      // PBKDF2 salt (non-secret)

// Load and decrypt bookings using passphrase
async function loadBookingsEncrypted(passphrase) {
  try {
    const encRaw = localStorage.getItem(ENC_STORAGE_KEY);
    if (encRaw) {
      // Encrypted storage exists — decrypt it
      const { encryptedData, iv, salt } = JSON.parse(encRaw);
      const decrypted = await CryptoService.decrypt(encryptedData, iv, salt, passphrase);
      const arr = JSON.parse(decrypted);
      if (!Array.isArray(arr)) throw new Error("Not an array");
      return arr.filter(isValidBooking);
    }
    // No encrypted storage — check for legacy plaintext
    const plain = localStorage.getItem(STORAGE_KEY);
    if (plain) {
      const arr = JSON.parse(plain);
      if (Array.isArray(arr) && arr.length > 0) {
        // Migrate: encrypt existing bookings with this passphrase
        await saveBookingsEncrypted(arr.filter(isValidBooking), passphrase);
        localStorage.removeItem(STORAGE_KEY);
        return arr.filter(isValidBooking);
      }
    }
    return [];
  } catch (err) {
    if (err && (err.message || "").toLowerCase().includes("decrypt") ||
        err instanceof DOMException) {
      throw new Error("WRONG_PASSPHRASE");
    }
    return [];
  }
}

// Encrypt and save bookings using passphrase
async function saveBookingsEncrypted(bookings, passphrase) {
  try {
    const capped = bookings.slice(-5000);
    const encrypted = await CryptoService.encrypt(capped, passphrase);
    localStorage.setItem(ENC_STORAGE_KEY, JSON.stringify(encrypted));
  } catch (err) {
    console.error("Failed to save encrypted bookings:", err);
  }
}
const REQUIRED_BOOKING_FIELDS = ["id","customerName","date","timeSlot"];

function isValidBooking(b) {
  if (b === null || typeof b !== "object" || Array.isArray(b)) return false;
  // Block prototype pollution keys
  // Check for prototype pollution: only flag if key is OWN property (not inherited)
  if (b.hasOwnProperty("__proto__") || b.hasOwnProperty("constructor") || b.hasOwnProperty("prototype")) return false;
  return REQUIRED_BOOKING_FIELDS.every(f => typeof b[f] === "string" && b[f].length > 0);
}

function loadBookings() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    // Validate each booking, drop corrupt entries
    return parsed.filter(isValidBooking).map(b => ({
      id: sanitize(b.id, 20),
      customerName: sanitize(b.customerName),
      pickupAddress: sanitize(b.pickupAddress),
      dropoffAddress: sanitize(b.dropoffAddress),
      airline: sanitize(b.airline, 50),
      flightNumber: sanitize(b.flightNumber, 20),
      passengers: sanitizeNumeric(b.passengers || "1"),
      luggage: sanitizeNumeric(b.luggage || "0"),
      tripType: ["one-way","round-trip"].includes(b.tripType) ? b.tripType : "one-way",
      phone: sanitizePhone(b.phone),
      paymentAmount: sanitizeNumeric(b.paymentAmount),
      driverNumber: sanitizeDriverId(b.driverNumber),
      date: sanitize(b.date, 10),
      timeSlot: sanitize(b.timeSlot, 12),
      createdAt: sanitize(b.createdAt || "", 30),
      flightStatus: sanitize(b.flightStatus || "", 20),
      flightArrival: sanitize(b.flightArrival || "", 30),
      fareRoute: sanitize(b.fareRoute || "", 100),
      fareBreakdown: sanitize(b.fareBreakdown || "", 60)
    }));
  } catch { return []; }
}
function saveBookings(bookings) {
  try {
    const capped = bookings.slice(-5000);
    const data = JSON.stringify(capped);
    if (data.length > 4 * 1024 * 1024) {
      console.warn("Booking data too large, trimming oldest entries");
      saveBookings(capped.slice(Math.floor(capped.length / 2)));
      return;
    }
    localStorage.setItem(STORAGE_KEY, data);
    // Auto-backup after every save
    BackupService.autoSnapshot(capped);
  } catch (e) {
    console.error("Failed to save bookings:", e);
  }
}

// ── Backup Service — Rolling snapshots + log + export/import ──
const BACKUP_PREFIX = "dispatch-hq-backup-";
const BACKUP_LOG_KEY = "dispatch-hq-backup-log";
const MAX_SNAPSHOTS = 5; // Keep last 5 auto-snapshots

const BackupService = {
  // Auto-snapshot: called on every save, throttled to 1 per 10 minutes
  _lastSnapshot: 0,
  autoSnapshot(bookings) {
    const now = Date.now();
    if (now - this._lastSnapshot < 10 * 60 * 1000) return; // Throttle: max 1 every 10 min
    if (!bookings || bookings.length === 0) return;
    this._lastSnapshot = now;
    try {
      const key = BACKUP_PREFIX + new Date().toISOString().replace(/[:.]/g, "-");
      const snapshot = { bookings, timestamp: new Date().toISOString(), count: bookings.length, type: "auto" };
      localStorage.setItem(key, JSON.stringify(snapshot));
      this.addLog("auto", bookings.length, "Auto-backup saved");
      this.pruneOldSnapshots();
    } catch (e) {
      console.warn("Auto-backup failed:", e.message);
    }
  },

  // Manual snapshot: dispatcher clicks "Back Up Now"
  manualSnapshot(bookings) {
    if (!bookings || bookings.length === 0) return { success: false, message: "No bookings to back up" };
    try {
      const key = BACKUP_PREFIX + "manual-" + new Date().toISOString().replace(/[:.]/g, "-");
      const snapshot = { bookings, timestamp: new Date().toISOString(), count: bookings.length, type: "manual" };
      localStorage.setItem(key, JSON.stringify(snapshot));
      this.addLog("manual", bookings.length, "Manual backup by dispatcher");
      this.pruneOldSnapshots();
      return { success: true, message: `Backed up ${bookings.length} bookings` };
    } catch (e) {
      return { success: false, message: "Backup failed: " + e.message };
    }
  },

  // List all available snapshots
  listSnapshots() {
    const snapshots = [];
    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i);
      if (key && key.startsWith(BACKUP_PREFIX)) {
        try {
          const raw = localStorage.getItem(key);
          const snap = JSON.parse(raw);
          snapshots.push({
            key,
            timestamp: snap.timestamp || "Unknown",
            count: snap.count || (snap.bookings ? snap.bookings.length : 0),
            type: snap.type || "auto",
            sizeKB: Math.round((raw.length) / 1024)
          });
        } catch {}
      }
    }
    return snapshots.sort((a, b) => b.timestamp.localeCompare(a.timestamp));
  },

  // Restore from a snapshot
  restoreSnapshot(key) {
    try {
      const raw = localStorage.getItem(key);
      if (!raw) return { success: false, message: "Snapshot not found" };
      const snap = JSON.parse(raw);
      if (!snap.bookings || !Array.isArray(snap.bookings)) return { success: false, message: "Snapshot is corrupt" };
      // Validate each booking before restoring
      const valid = snap.bookings.filter(isValidBooking);
      if (valid.length === 0) return { success: false, message: "Snapshot contains no valid bookings" };
      this.addLog("restore", valid.length, `Restored from ${snap.type} backup (${snap.timestamp})`);
      return { success: true, bookings: valid, message: `Restored ${valid.length} bookings from ${snap.timestamp}` };
    } catch (e) {
      return { success: false, message: "Restore failed: " + e.message };
    }
  },

  // Delete a snapshot
  deleteSnapshot(key) {
    try {
      localStorage.removeItem(key);
      this.addLog("delete", 0, `Deleted backup: ${key}`);
      return { success: true };
    } catch { return { success: false }; }
  },

  // Prune: keep only MAX_SNAPSHOTS most recent
  pruneOldSnapshots() {
    const snapshots = this.listSnapshots();
    if (snapshots.length > MAX_SNAPSHOTS) {
      // Keep manual snapshots longer — only auto-prune auto backups
      const autoSnaps = snapshots.filter(s => s.type === "auto");
      const toPrune = autoSnaps.slice(MAX_SNAPSHOTS);
      toPrune.forEach(s => {
        try { localStorage.removeItem(s.key); } catch {}
      });
    }
  },

  // Export to downloadable JSON file
  exportToFile(bookings) {
    if (!bookings || bookings.length === 0) return { success: false, message: "No bookings to export" };
    try {
      const exportData = {
        app: "Dispatch HQ",
        version: "1.0",
        exportedAt: new Date().toISOString(),
        bookingCount: bookings.length,
        bookings: bookings
      };
      const json = JSON.stringify(exportData, null, 2);
      const blob = new Blob([json], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `dispatch-hq-backup-${new Date().toISOString().split("T")[0]}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      this.addLog("export", bookings.length, "Exported to JSON file");
      return { success: true, message: `Exported ${bookings.length} bookings to file` };
    } catch (e) {
      return { success: false, message: "Export failed: " + e.message };
    }
  },

  // Import from JSON file
  importFromFile(fileContent) {
    try {
      const data = JSON.parse(fileContent);
      let bookingsToImport = [];
      // Support both direct array and wrapped format
      if (Array.isArray(data)) {
        bookingsToImport = data;
      } else if (data.bookings && Array.isArray(data.bookings)) {
        bookingsToImport = data.bookings;
      } else {
        return { success: false, message: "Invalid file format — expected JSON array or {bookings: [...]}" };
      }
      const valid = bookingsToImport.filter(isValidBooking);
      if (valid.length === 0) return { success: false, message: "File contains no valid bookings" };
      this.addLog("import", valid.length, `Imported from file (${valid.length} of ${bookingsToImport.length} valid)`);
      return { success: true, bookings: valid, message: `Imported ${valid.length} bookings (${bookingsToImport.length - valid.length} skipped as invalid)` };
    } catch (e) {
      return { success: false, message: "Import failed: " + e.message };
    }
  },

  // ── Backup Log ──
  addLog(action, count, message) {
    try {
      const log = this.getLog();
      log.unshift({
        timestamp: new Date().toISOString(),
        action,
        count,
        message
      });
      // Keep last 100 log entries
      const trimmed = log.slice(0, 100);
      localStorage.setItem(BACKUP_LOG_KEY, JSON.stringify(trimmed));
    } catch {}
  },

  getLog() {
    try {
      const raw = localStorage.getItem(BACKUP_LOG_KEY);
      if (!raw) return [];
      const parsed = JSON.parse(raw);
      return Array.isArray(parsed) ? parsed : [];
    } catch { return []; }
  },

  clearLog() {
    try { localStorage.removeItem(BACKUP_LOG_KEY); } catch {}
  },

  // Auto-purge bookings older than N days (called on app load)
  autoPurgeOldBookings(bookings, maxAgeDays) {
    if (!maxAgeDays || maxAgeDays <= 0) return bookings;
    const cutoff = new Date();
    cutoff.setDate(cutoff.getDate() - maxAgeDays);
    const cutoffStr = cutoff.toISOString().split("T")[0];
    const kept = bookings.filter(b => b.date >= cutoffStr);
    const purged = bookings.length - kept.length;
    if (purged > 0) {
      this.addLog("auto-purge", purged, "Purged " + purged + " bookings older than " + maxAgeDays + " days (2-year retention policy)");
    }
    return kept;
  },

  // Storage usage summary
  getStorageInfo() {
    let totalBytes = 0;
    let bookingBytes = 0;
    let backupBytes = 0;
    let backupCount = 0;
    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i);
      if (!key) continue;
      const size = (localStorage.getItem(key) || "").length * 2; // UTF-16
      totalBytes += size;
      if (key === STORAGE_KEY) bookingBytes = size;
      if (key.startsWith(BACKUP_PREFIX)) { backupBytes += size; backupCount++; }
    }
    return {
      totalKB: Math.round(totalBytes / 1024),
      bookingKB: Math.round(bookingBytes / 1024),
      backupKB: Math.round(backupBytes / 1024),
      backupCount,
      capacityPercent: Math.round((totalBytes / (5 * 1024 * 1024)) * 100)
    };
  }
};

// ── Main App ──
// ── Time Picker Dropdown — proper component (avoids hooks-in-IIFE crash) ──
function TimePickerDropdown({ selected, onSelect, allSlots }) {
  const PINNED = ["5:00 AM","6:00 AM","7:00 AM","8:00 AM","6:00 PM","10:00 PM"];
  const [q, setQ] = useState("");
  const [showGrid, setShowGrid] = useState(false);

  function parseTypedTime(input) {
    const s = input.trim().toUpperCase().replace(/\./g,":").replace(/\s+/g," ");
    const isPM = s.includes("PM"), isAM = s.includes("AM");
    const clean = s.replace(/AM|PM/g,"").trim();
    const digits = clean.replace(/[^0-9:]/g,"");
    let h, m;
    if (digits.includes(":")) { [h,m] = digits.split(":").map(Number); }
    else if (digits.length<=2) { h=parseInt(digits); m=0; }
    else if (digits.length===3) { h=parseInt(digits[0]); m=parseInt(digits.slice(1)); }
    else if (digits.length===4) { h=parseInt(digits.slice(0,2)); m=parseInt(digits.slice(2)); }
    else return null;
    if (isNaN(h)||isNaN(m)||m>59||h>23) return null;
    let period = isPM?"PM":isAM?"AM":h>=12?"PM":"AM";
    if (h===0) h=12;
    if (h>12) { h=h-12; period="PM"; }
    return `${h}:${String(m).padStart(2,"0")} ${period}`;
  }

  const parsed = q.length >= 1 ? parseTypedTime(q) : null;
  const hasAmPm = q.toUpperCase().includes("AM") || q.toUpperCase().includes("PM");

  // Build dropdown suggestions — AM + PM options for ambiguous input
  const suggestions = [];
  if (q.length >= 1) {
    if (!hasAmPm && parsed) {
      const amVer = parseTypedTime(q + " am");
      const pmVer = parseTypedTime(q + " pm");
      if (amVer) suggestions.push({ label: amVer, badge: "AM" });
      if (pmVer && pmVer !== amVer) suggestions.push({ label: pmVer, badge: "PM" });
    } else if (parsed) {
      suggestions.push({ label: parsed, badge: "CUSTOM" });
    }
    // Also add matching preset slots
    allSlots.filter(slot => {
      const [time] = slot.split(" ");
      const [h, m] = time.split(":");
      return (h+m).startsWith(q) || (h.padStart(2,"0")+m).startsWith(q) || h === q;
    }).slice(0, 3).forEach(t => {
      if (!suggestions.find(s => s.label === t)) suggestions.push({ label: t, badge: null });
    });
  }

  return (
    <div data-picker style={{ position: "absolute", top: "calc(100% + 6px)", left: 0, zIndex: 200, background: "var(--bg-1)", border: "1px solid var(--border-1)", borderRadius: 12, boxShadow: "0 8px 32px rgba(0,0,0,0.5)", width: 260, padding: 10 }}>

      {/* ── Free-form input — DEFAULT, always at top ── */}
      <p style={{ fontSize: 9, color: "var(--green)", fontFamily: "var(--mono)", letterSpacing: "0.16em", marginBottom: 5 }}>ENTER TIME</p>
      <input
        autoFocus
        value={q}
        onChange={e => setQ(e.target.value)}
        placeholder="e.g. 10:45 am · 11:42 pm · 730"
        style={{ width: "100%", padding: "10px 12px", borderRadius: 6, border: "2px solid var(--amber)", background: "#fff", color: "#1a0a00", fontSize: 15, fontWeight: 700, fontFamily: "var(--mono)", outline: "none", marginBottom: suggestions.length ? 0 : 8, boxSizing: "border-box" }}
      />

      {/* ── Popup suggestions — AM/PM options + slot matches ── */}
      {suggestions.length > 0 && (
        <div style={{ borderRadius: 6, overflow: "hidden", border: "1px solid var(--border-1)", marginBottom: 8, marginTop: 4 }}>
          {suggestions.map((s, i) => (
            <button key={s.label} onClick={() => onSelect(s.label)} style={{
              width: "100%", padding: "11px 14px",
              border: "none", borderBottom: i < suggestions.length - 1 ? "1px solid var(--border-0)" : "none",
              background: selected === s.label ? "rgba(240,165,0,0.1)" : i === 0 ? "#fffdf5" : "#fff",
              color: "#1a0a00", fontSize: 15, fontWeight: 700,
              cursor: "pointer", fontFamily: "var(--mono)",
              textAlign: "left", display: "flex", justifyContent: "space-between", alignItems: "center"
            }}>
              <span>{s.label}</span>
              <span style={{
                fontSize: 10, letterSpacing: "0.1em", padding: "2px 7px", borderRadius: 4, fontWeight: 700,
                background: s.badge === "AM" ? "rgba(76,175,106,0.15)" : s.badge === "PM" ? "rgba(240,165,0,0.15)" : s.badge === "CUSTOM" ? "rgba(240,165,0,0.15)" : "rgba(76,175,106,0.08)",
                color: s.badge === "AM" ? "var(--green)" : s.badge === "PM" ? "var(--amber)" : s.badge === "CUSTOM" ? "var(--amber)" : "var(--text-3)",
              }}>{s.badge || "SLOT"}</span>
            </button>
          ))}
        </div>
      )}

      {/* Divider + toggle for pinned/grid */}
      <div style={{ display: "flex", alignItems: "center", gap: 8, margin: "4px 0 8px" }}>
        <div style={{ flex: 1, height: 1, background: "var(--border-0)" }} />
        <button onClick={() => setShowGrid(v => !v)} style={{ fontSize: 9, color: "var(--green)", fontFamily: "var(--mono)", letterSpacing: "0.14em", background: "transparent", border: "none", cursor: "pointer", padding: "2px 6px" }}>
          {showGrid ? "▲ HIDE GRID" : "▼ SHOW GRID"}
        </button>
        <div style={{ flex: 1, height: 1, background: "var(--border-0)" }} />
      </div>

      {/* Pinned + full grid — collapsed by default */}
      {showGrid && (
        <>
          <p style={{ fontSize: 9, color: "var(--green)", fontFamily: "var(--mono)", letterSpacing: "0.16em", marginBottom: 6 }}>COMMON TIMES</p>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 5, marginBottom: 8 }}>
            {PINNED.map(t => {
              const [time, ampm] = t.split(" ");
              return (
                <button key={t} onClick={() => onSelect(t)} style={{ padding: "8px 4px", borderRadius: 6, border: selected === t ? "1px solid var(--amber)" : "1px solid var(--border-0)", background: selected === t ? "rgba(240,165,0,0.1)" : "var(--bg-2)", cursor: "pointer", textAlign: "center" }}>
                  <span style={{ display: "block", fontSize: 13, fontWeight: 700, color: selected === t ? "var(--amber)" : "var(--text-1)", fontFamily: "var(--mono)" }}>{time}</span>
                  <span style={{ display: "block", fontSize: 9, color: "var(--green)" }}>{ampm}</span>
                </button>
              );
            })}
          </div>
          <p style={{ fontSize: 9, color: "var(--green)", fontFamily: "var(--mono)", letterSpacing: "0.16em", marginBottom: 6 }}>ALL TIMES</p>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 3, maxHeight: 180, overflowY: "auto" }}>
            {allSlots.map(t => {
              const [time, ampm] = t.split(" ");
              return (
                <button key={t} onClick={() => onSelect(t)} style={{ padding: "5px 2px", borderRadius: 4, border: selected === t ? "1px solid var(--amber)" : "1px solid var(--border-0)", background: selected === t ? "rgba(240,165,0,0.1)" : "var(--bg-2)", cursor: "pointer", textAlign: "center" }}>
                  <span style={{ display: "block", fontSize: 11, fontWeight: selected === t ? 700 : 400, color: selected === t ? "var(--amber)" : "var(--text-1)", fontFamily: "var(--mono)" }}>{time}</span>
                  <span style={{ display: "block", fontSize: 8, color: "var(--green)" }}>{ampm}</span>
                </button>
              );
            })}
          </div>
        </>
      )}
    </div>
  );
}

function DispatcherApp({ session, onLogout }) {
  const [view, setView] = useState("booking");
  const [priceCheckMode, setPriceCheckMode] = useState(false);
  const [gdprDismissed, setGdprDismissed] = useState(() => {
    try { return localStorage.getItem("dispatch-hq-gdpr-notice") === "dismissed"; } catch { return false; }
  });
  const dismissGdpr = () => {
    setGdprDismissed(true);
    try { localStorage.setItem("dispatch-hq-gdpr-notice", "dismissed"); } catch {}
  };
  const [bookings, setBookings] = useState(() => BackupService.autoPurgeOldBookings(loadBookings(), 730));
  const [form, setForm] = useState({...INIT_FORM});
  const [showConfirm, setShowConfirm] = useState(null);
  const [isListening, setIsListening] = useState(false);
  const [speechLang, setSpeechLang] = useState("en-US");
  const [transcript, setTranscript] = useState("");
  const [searchQuery, setSearchQuery] = useState("");
  const handleSearchChange = (v) => setSearchQuery(v.slice(0, 100));
  const [filters, setFilters] = useState({ dateFrom: "", dateTo: "", driverNumber: "", tripType: "", shift: "", dayType: "" });
  const [editingBooking, setEditingBooking] = useState(null);
  const [showDriverPanel, setShowDriverPanel] = useState(false);
  const [timeMode, setTimeMode] = useState("grid");
  const recognitionRef = useRef(null);

  // ── AI Assist State (Flight + Pricing) ──
  const [aiLoading, setAiLoading] = useState(false);
  const [aiTimer, setAiTimer] = useState(0);
  const aiTimerRef = useRef(null);
  const [flightData, setFlightData] = useState(null);
  const [fareData, setFareData] = useState(null);
  const [aiError, setAiError] = useState("");
  const [aiSummary, setAiSummary] = useState("");
  const [manualFare, setManualFare] = useState(null);

  // ── Voice / UI Error States ──
  const [voiceError, setVoiceError] = useState("");
  const [micPermission, setMicPermission] = useState("unknown"); // unknown | granted | denied | sandbox
  const micPermissionRef = useRef("unknown");
  const [showMicPrompt, setShowMicPrompt] = useState(false);
  const [showTypeInput, setShowTypeInput] = useState(false);
  const [fieldMicActive, setFieldMicActive] = useState(null); // null | "pickupAddress" | "dropoffAddress"
  const fieldMicRef = useRef(null); // Kept for compatibility but never triggered
  const [showCal, setShowCal] = useState(false);
  const [dashPage, setDashPage] = useState(50); // how many bookings to show

  // ── Driver Management state (moved out of IIFE to fix blank screen crash) ──
  const [customDrivers, setCustomDrivers] = useState(() => {
    try { return JSON.parse(localStorage.getItem("dispatch-hq-custom-drivers") || "[]"); } catch { return []; }
  });
  const [showAddDriver, setShowAddDriver] = useState(false);
  const [dForm, setDForm] = useState({ id:"", shiftStart:"06:00", shiftEnd:"18:00", daysOff:"", monthlyOff:"", airportPickup:false, airportDropoff:false, notes:"" });
  const [dFormErr, setDFormErr] = useState("");
  const [showTimePicker, setShowTimePicker] = useState(false);
  const [calViewMonth, setCalViewMonth] = useState(() => { const n = new Date(); return { year: n.getFullYear(), month: n.getMonth() }; });
  const [mapsApiKey, setMapsApiKey] = useState(() => loadMapsKey());
  const [mapsReady, setMapsReady] = useState(true); // always true — proxy handles API calls server-side
  const [deleteConfirmId, setDeleteConfirmId] = useState(null);
  const [formError, setFormError] = useState("");
  const [missingFields, setMissingFields] = useState([]); // field names that failed validation
  // Clear field highlight when user starts filling it
  useEffect(() => {
    if (missingFields.length === 0) return;
    const stillMissing = missingFields.filter(f => {
      if (f === "customerName") return !form.customerName.trim();
      if (f === "phone") return !form.phone.trim();
      if (f === "pickupAddress") return !form.pickupAddress.trim();
      if (f === "dropoffAddress") return !form.dropoffAddress.trim();
      if (f === "date") return !form.date;
      if (f === "timeSlot") return !form.timeSlot && !form.customTime;
      if (f === "driverNumber") return !form.driverNumber;
      if (f === "airline") return isAirportTrip && !form.airline.trim();
      if (f === "flightNumber") return isAirportTrip && !form.flightNumber.trim();
      if (f === "paymentAmount") return !form.paymentAmount.trim();
      return false;
    });
    if (stillMissing.length !== missingFields.length) setMissingFields(stillMissing);
  }, [form, missingFields]);
  const [syncResetConfirm, setSyncResetConfirm] = useState(false);
  const micAvailable = micPermission !== "sandbox" && micPermission !== "denied";

  // ── Backup State ──
  const [backupMsg, setBackupMsg] = useState("");
  const [backupMsgType, setBackupMsgType] = useState(""); // success | error | info
  const [snapshots, setSnapshots] = useState(() => BackupService.listSnapshots());
  const [backupLog, setBackupLog] = useState(() => BackupService.getLog());
  const [storageInfo, setStorageInfo] = useState(() => BackupService.getStorageInfo());
  const [showBackupLog, setShowBackupLog] = useState(false);
  const [restoreConfirmKey, setRestoreConfirmKey] = useState(null);
  const fileInputRef = useRef(null);

  const refreshBackupState = useCallback(() => {
    setSnapshots(BackupService.listSnapshots());
    setBackupLog(BackupService.getLog());
    setStorageInfo(BackupService.getStorageInfo());
  }, []);

  const handleManualBackup = useCallback(() => {
    const result = BackupService.manualSnapshot(bookings);
    setBackupMsg(result.message);
    setBackupMsgType(result.success ? "success" : "error");
    refreshBackupState();
  }, [bookings, refreshBackupState]);

  const handleExport = useCallback(() => {
    const result = BackupService.exportToFile(bookings);
    setBackupMsg(result.message);
    setBackupMsgType(result.success ? "success" : "error");
    refreshBackupState();
  }, [bookings, refreshBackupState]);

  const handleImport = useCallback((e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    // Reject files > 10MB to prevent browser crash
    if (file.size > 10 * 1024 * 1024) {
      setBackupMsg("File too large (max 10MB). Got " + Math.round(file.size / 1024 / 1024) + "MB.");
      setBackupMsgType("error");
      e.target.value = "";
      return;
    }
    const reader = new FileReader();
    reader.onload = (ev) => {
      const result = BackupService.importFromFile(ev.target.result);
      if (result.success) {
        // Merge: imported bookings added, existing kept, duplicates overwritten by import
        const merged = new Map();
        bookings.forEach(b => merged.set(b.id, b));
        result.bookings.forEach(b => merged.set(b.id, b));
        setBookings(Array.from(merged.values()));
        setBackupMsg(result.message);
        setBackupMsgType("success");
      } else {
        setBackupMsg(result.message);
        setBackupMsgType("error");
      }
      refreshBackupState();
    };
    reader.onerror = () => { setBackupMsg("Failed to read file"); setBackupMsgType("error"); };
    reader.readAsText(file);
    e.target.value = ""; // Reset file input
  }, [bookings, refreshBackupState]);

  const handleRestore = useCallback((key) => {
    const result = BackupService.restoreSnapshot(key);
    if (result.success) {
      setBookings(result.bookings);
      setBackupMsg(result.message);
      setBackupMsgType("success");
    } else {
      setBackupMsg(result.message);
      setBackupMsgType("error");
    }
    setRestoreConfirmKey(null);
    refreshBackupState();
  }, [refreshBackupState]);

  const handleDeleteSnapshot = useCallback((key) => {
    BackupService.deleteSnapshot(key);
    refreshBackupState();
  }, [refreshBackupState]);

  // Detect mic availability: requires HTTPS + SpeechRecognition API + not in iframe sandbox
  const isSandboxed = useRef(false);
  useEffect(() => {
    try { isSandboxed.current = window.self !== window.top; } catch { isSandboxed.current = true; }

    // Check 1: Secure context required for getUserMedia + SpeechRecognition
    if (typeof window.isSecureContext !== "undefined" && !window.isSecureContext) {
      setMicPermission("sandbox");
      return;
    }

    // Check 2: SpeechRecognition API exists
    const SR = window.SpeechRecognition || window.webkitSpeechRecognition;
    if (!SR) { setMicPermission("sandbox"); return; }

    // Check 3: Can we instantiate it? (fails in some restricted environments)
    try {
      const test = new SR();
      test.abort();
    } catch { setMicPermission("sandbox"); return; }

    // Check 4: getUserMedia available (needed for permission prompt)
    if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
      setMicPermission("sandbox");
      return;
    }

    // Check existing permission state
    if (navigator.permissions && navigator.permissions.query) {
      navigator.permissions.query({ name: "microphone" }).then(r => {
        if (r.state === "granted") setMicPermission("granted");
        else if (r.state === "denied") setMicPermission("denied");
        // "prompt" = unknown, user will be asked when they tap mic
      }).catch(() => {});
    }
  }, []);

  // Global keyboard shortcuts
  useEffect(() => {
    const handleKeyboard = (e) => {
      // Ctrl/Cmd + Enter = confirm booking (when on booking tab)
      if ((e.ctrlKey || e.metaKey) && e.key === "Enter" && view === "booking" && !showConfirm) {
        e.preventDefault();
        handleSubmit();
      }
      // Escape = close modals / dropdowns
      if (e.key === "Escape") {
        setShowCal(false);
        setShowTimePicker(false);
        if (showConfirm) setShowConfirm(null);
        if (deleteConfirmId) setDeleteConfirmId(null);
      }
      // Ctrl/Cmd + F = focus search (when on dashboard)
      if ((e.ctrlKey || e.metaKey) && e.key === "f" && view === "dashboard") {
        e.preventDefault();
        const searchEl = document.querySelector('input[placeholder*="Search"]') || document.querySelector('input[aria-label*="Search"]');
        if (searchEl) searchEl.focus();
      }
    };
    window.addEventListener("keydown", handleKeyboard);
    return () => window.removeEventListener("keydown", handleKeyboard);
  }, [view, showConfirm, deleteConfirmId, showCal, showTimePicker]);

  // Close calendar/time picker when clicking outside
  useEffect(() => {
    if (!showCal && !showTimePicker) return;
    const handler = (e) => {
      if (!e.target.closest("[data-picker]")) {
        setShowCal(false);
        setShowTimePicker(false);
      }
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, [showCal, showTimePicker]);

  // Keep micPermission ref in sync for closures (SpeechRecognition handlers)
  useEffect(() => { micPermissionRef.current = micPermission; }, [micPermission]);

  // ── Sync State ──
  const [syncConfig, setSyncConfig] = useState(() => loadSyncConfig());

  // ── Device encryption passphrase (memory only, never stored) ──

  // ── Auto-sync ──
  // ── Auth state ──
  // authStatus: "loading" | "unauthenticated" | "authenticated"
  const [authStatus, setAuthStatus]       = useState("loading");
  const [currentUser, setCurrentUser]     = useState(null); // { username, role, displayName, token, expiresAt }
  const AUTH_SESSION_KEY                  = "dispatch-hq-session";

  const saveSession = (userData) => {
    try { localStorage.setItem(AUTH_SESSION_KEY, JSON.stringify(userData)); } catch {}
    setCurrentUser(userData);
    setAuthStatus("authenticated");
  };
  const clearSession = () => {
    try {
      const s = JSON.parse(localStorage.getItem(AUTH_SESSION_KEY) || "{}");
      if (s.token && syncConfig.endpointUrl) {
        fetch(syncConfig.endpointUrl, { method: "POST", headers: { "Content-Type": "text/plain;charset=utf-8" }, body: JSON.stringify({ action: "logout", sessionToken: s.token }) }).catch(() => {});
      }
    } catch {}
    try { localStorage.removeItem(AUTH_SESSION_KEY); } catch {}
    setCurrentUser(null);
    setAuthStatus("unauthenticated");
  };

  // Validate stored session on load
  useEffect(() => {
    const stored = (() => { try { return JSON.parse(localStorage.getItem(AUTH_SESSION_KEY) || "null"); } catch { return null; } })();
    if (!stored || !stored.token || !stored.expiresAt) { setAuthStatus("unauthenticated"); return; }
    if (new Date(stored.expiresAt) < new Date()) { clearSession(); return; }
    // Quick local check passes — set authenticated, then verify with server in background
    setCurrentUser(stored);
    setAuthStatus("authenticated");
    if (syncConfig.endpointUrl) {
      fetch(syncConfig.endpointUrl + "?action=validateSession&sessionToken=" + encodeURIComponent(stored.token), { method: "GET", redirect: "follow" })
        .then(r => r.json())
        .then(d => { if (!d.valid) clearSession(); })
        .catch(() => {}); // network error → keep local session
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  const [passphrase, setPassphrase] = useState(""); // Cleared after key derivation

  const derivedKeyRef = useRef(null); // Holds non-extractable CryptoKey
  const [syncStatus, setSyncStatus] = useState("idle"); // idle | syncing | success | error
  const [syncMessage, setSyncMessage] = useState("");
  const [syncEndpointInput, setSyncEndpointInput] = useState(() => loadSyncConfig().endpointUrl);
  const [passphraseInput, setPassphraseInput] = useState("");
  const [showPassphraseEntry, setShowPassphraseEntry] = useState(false);
  const [syncConfigured, setSyncConfigured] = useState(() => {
    const c = loadSyncConfig();
    return !!(c.endpointUrl && c.passphraseHash);
  });

  useEffect(() => { saveBookings(bookings); }, [bookings]);

  // ── Sync Functions ──
  const testConnection = useCallback(async () => {
    if (!syncEndpointInput.trim()) { setSyncMessage("Enter an endpoint URL first"); return; }
    if (!syncEndpointInput.trim().startsWith("https://script.google.com/")) {
      setSyncMessage("URL must start with https://script.google.com/"); setSyncStatus("error"); return;
    }
    setSyncStatus("syncing"); setSyncMessage("Testing connection...");
    try {
      const result = await SyncService.ping(syncEndpointInput.trim(), syncConfig.authToken);
      if (result.success) {
        setSyncStatus("success");
        setSyncMessage(`Connected to "${result.sheetName}" — ${result.recordCount} records stored`);
      } else {
        setSyncStatus("error"); setSyncMessage("Server responded with error: " + (result.error || "Unknown"));
      }
    } catch (err) {
      setSyncStatus("error"); setSyncMessage("Connection failed: " + sanitizeErrorMsg(err));
    }
  }, [syncEndpointInput]);

  const saveSyncSettings = useCallback(async () => {
    if (!syncEndpointInput.trim() || !passphraseInput || passphraseInput.length < 8) {
      setSyncMessage("URL required and passphrase must be 8+ characters"); setSyncStatus("error"); return;
    }
    if (!syncEndpointInput.trim().startsWith("https://script.google.com/")) {
      setSyncMessage("URL must be a Google Apps Script endpoint (https://script.google.com/...)"); setSyncStatus("error"); return;
    }
    try {
      const hash = await CryptoService.hashPassphrase(passphraseInput);
      const newConfig = { endpointUrl: syncEndpointInput.trim(), passphraseHash: hash, lastSync: syncConfig.lastSync, authToken: syncConfig.authToken || "" };
      saveSyncConfig(newConfig);
      setSyncConfig(newConfig);
      setPassphrase(passphraseInput);
      setSyncConfigured(true);
      setSyncStatus("success"); setSyncMessage("Settings saved and encryption key derived");
    } catch (err) {
      setSyncStatus("error"); setSyncMessage("Failed to save: " + sanitizeErrorMsg(err));
    }
  }, [syncEndpointInput, passphraseInput, syncConfig.lastSync]);

  const unlockWithPassphrase = useCallback(async () => {
    if (!passphraseInput) return;
    try {
      const hash = await CryptoService.hashPassphrase(passphraseInput);
      if (hash === syncConfig.passphraseHash) {
        setPassphrase(passphraseInput);
        setShowPassphraseEntry(false);
        setSyncStatus("success"); setSyncMessage("Unlocked — ready to sync");
      } else {
        setSyncStatus("error"); setSyncMessage("Incorrect passphrase");
      }
    } catch (err) {
      setSyncStatus("error"); setSyncMessage("Verification failed: " + sanitizeErrorMsg(err));
    }
  }, [passphraseInput, syncConfig.passphraseHash]);

  const syncNow = useCallback(async () => {
    if (!syncConfig.endpointUrl || !passphrase) {
      setSyncMessage("Configure endpoint and enter passphrase first");
      setSyncStatus("error"); return;
    }
    setSyncStatus("syncing"); setSyncMessage("Encrypting and uploading...");
    try {
      // Derive key ONCE for the entire batch (310K PBKDF2 iterations only once)
      const batchSalt = crypto.getRandomValues(new Uint8Array(16));
      const batchKey = await CryptoService.deriveKey(passphrase, batchSalt);
      const batchSaltB64 = CryptoService._bufToBase64(batchSalt);

      // Encrypt all bookings with shared key, unique IV per record
      const encryptedRecords = [];
      for (const booking of bookings) {
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const ciphertext = await crypto.subtle.encrypt(
          { name: "AES-GCM", iv }, batchKey,
          new TextEncoder().encode(JSON.stringify(booking))
        );
        encryptedRecords.push({
          id: booking.id,
          encryptedData: CryptoService._bufToBase64(ciphertext),
          iv: CryptoService._bufToBase64(iv),
          salt: batchSaltB64,
          deleted: false
        });
      }
      // Push to remote
      const result = await SyncService.batchSync(syncConfig.endpointUrl, encryptedRecords, syncConfig.authToken);
      if (result.success) {
        const now = new Date().toISOString();
        const newConfig = { ...syncConfig, lastSync: now };
        saveSyncConfig(newConfig); setSyncConfig(newConfig);
        setSyncStatus("success");
        setSyncMessage(`Synced ${result.created} new, ${result.updated} updated — ${result.totalRecords} total remote records`);
      } else {
        setSyncStatus("error"); setSyncMessage("Sync failed: " + (result.error || "Unknown"));
      }
    } catch (err) {
      setSyncStatus("error"); setSyncMessage("Sync error: " + sanitizeErrorMsg(err));
    }
  }, [syncConfig, passphrase, bookings]);

  const pullFromRemote = useCallback(async () => {
    if (!syncConfig.endpointUrl || !passphrase) {
      setSyncMessage("Configure endpoint and enter passphrase first");
      setSyncStatus("error"); return;
    }
    setSyncStatus("syncing"); setSyncMessage("Downloading and decrypting...");
    try {
      const result = await SyncService.fetchAll(syncConfig.endpointUrl, null, syncConfig.authToken);
      if (!result.success) { setSyncStatus("error"); setSyncMessage("Fetch failed: " + result.error); return; }
      // Decrypt all records
      const decrypted = [];
      let decryptErrors = 0;
      // Group records by salt for batch decryption (same salt = same derived key)
      const saltGroups = {};
      for (const record of result.records) {
        if (record.deleted) continue;
        if (!saltGroups[record.salt]) saltGroups[record.salt] = [];
        saltGroups[record.salt].push(record);
      }
      // Derive key once per unique salt, then decrypt all records with that key
      for (const [salt, records] of Object.entries(saltGroups)) {
        let key;
        try {
          key = await CryptoService.deriveKey(passphrase, CryptoService._base64ToBuf(salt));
        } catch { decryptErrors += records.length; continue; }
        for (const record of records) {
          try {
            const ivBuf = CryptoService._base64ToBuf(record.iv);
            const dataBuf = CryptoService._base64ToBuf(record.encryptedData);
            const plainBuf = await crypto.subtle.decrypt({ name: "AES-GCM", iv: ivBuf }, key, dataBuf);
            const data = JSON.parse(new TextDecoder().decode(plainBuf));
            if (data && data.id && data.customerName) decrypted.push(data);
          } catch { decryptErrors++; }
        }
      }
      // Merge: keep newer version by modifiedAt timestamp
      const merged = new Map();
      let overwrittenCount = 0;
      bookings.forEach(b => merged.set(b.id, b));
      decrypted.forEach(b => {
        const existing = merged.get(b.id);
        if (!existing) {
          merged.set(b.id, b);
        } else if ((b.modifiedAt || "") > (existing.modifiedAt || "")) {
          merged.set(b.id, b);
          overwrittenCount++;
        }
      });
      setBookings(Array.from(merged.values()));
      const now = new Date().toISOString();
      const newConfig = { ...syncConfig, lastSync: now };
      saveSyncConfig(newConfig); setSyncConfig(newConfig);
      setSyncStatus("success");
      const baseMsg = `Pulled ${decrypted.length} records${decryptErrors ? ` (${decryptErrors} failed to decrypt)` : ""}`;
      const conflictNote = overwrittenCount > 0 ? ` — ⚠️ ${overwrittenCount} booking${overwrittenCount > 1 ? "s" : ""} updated from server (another device had a newer version)` : "";
      setSyncMessage(baseMsg + conflictNote);
    } catch (err) {
      setSyncStatus("error"); setSyncMessage("Pull error: " + sanitizeErrorMsg(err));
    }
  }, [syncConfig, passphrase, bookings]);

  // Track if dispatcher manually edited payment (prevents auto-fill overwrite)

  // ── Auto-sync (declared after passphrase to avoid temporal dead zone) ──
  const [autoSyncEnabled, setAutoSyncEnabled] = useState(() => {
    try { return localStorage.getItem("dispatch-hq-autosync") === "true"; } catch { return false; }
  });
  const [autoSyncInterval, setAutoSyncInterval] = useState(() => {
    try { return parseInt(localStorage.getItem("dispatch-hq-autosync-interval") || "30"); } catch { return 30; }
  });
  const autoSyncRef = useRef(null);

  useEffect(() => {
    if (autoSyncRef.current) { clearInterval(autoSyncRef.current); autoSyncRef.current = null; }
    if (!autoSyncEnabled || !syncConfig.endpointUrl || !passphrase) return;
    autoSyncRef.current = setInterval(async () => {
      if (syncStatus === "syncing") return;
      syncNow();
    }, autoSyncInterval * 60 * 1000);
    return () => { if (autoSyncRef.current) clearInterval(autoSyncRef.current); };
  }, [autoSyncEnabled, autoSyncInterval, syncConfig.endpointUrl, passphrase, syncStatus]);

  const [paymentManuallyEdited, setPaymentManuallyEdited] = useState(false);
  const [autoFareLabel, setAutoFareLabel] = useState(""); // shows what was auto-calculated

  // ── Instant local fare lookup — auto-fills payment when addresses match pricebook ──
  useEffect(() => {
    if (!form.pickupAddress || !form.dropoffAddress) {
      setManualFare(null);
      setAutoFareLabel("");
      return;
    }

    const result = lookupFlatRate(form.pickupAddress, form.dropoffAddress);
    setManualFare(result);

    if (!result) {
      setAutoFareLabel("");
      return;
    }

    // Build total with passengers and trip type
    let total = result.fare;
    const pax = parseInt(form.passengers) || 1;
    const bags = parseInt(form.luggage) || 0;
    const pAnchor = getAnchorCode(form.pickupAddress || "");
    const dAnchor = getAnchorCode(form.dropoffAddress || "");
    const isAirport = pAnchor || dAnchor;
    const extraNotes = [...(result.breakdown ? [result.breakdown] : [])];

    if (isAirport) {
      if (pax === 4 || pax === 5) { total = Math.round(total * 1.5); extraNotes.push("×1.5 (4–5 pax)"); }
      else if (pax >= 6) { total = Math.round(total * 2); extraNotes.push("×2 (6+ pax)"); }
    } else {
      if (pax > 3) { const e = (pax - 3) * 10; total += e; extraNotes.push(`+$${e} extra pax`); }
      if (bags > 3) { const e = (bags - 3) * 5; total += e; extraNotes.push(`+$${e} extra bags`); }
    }
    if (form.tripType === "round-trip") { total *= 2; extraNotes.push("×2 RT"); }
    total = Math.round(total);

    const label = `Auto: ${result.route} = $${total}${extraNotes.length ? " (" + extraNotes.join(", ") + ")" : ""}`;
    setAutoFareLabel(label);

    if (!paymentManuallyEdited) {
      setForm(p => ({
        ...p,
        paymentAmount: String(total),
        fareRoute: result.route || "",
        fareBreakdown: extraNotes.join(", "),
      }));
    }
  }, [form.pickupAddress, form.dropoffAddress, form.tripType, form.passengers, form.luggage, paymentManuallyEdited]);

  // ── AI Assist: Parallel flight + fare lookup via Anthropic API ──
  const runAIAssistHandler = useCallback(async () => {
    setAiLoading(true); setAiError(""); setFlightData(null); setFareData(null); setAiSummary("");
    setAiTimer(0);
    aiTimerRef.current = setInterval(() => setAiTimer(t => t + 1), 1000);
    try {
      const result = await runAIAssist(
        form.flightNumber, form.airline, "", form.date,
        form.pickupAddress, form.dropoffAddress, form.tripType,
        parseInt(form.passengers) || 1
      );
      if (result.error) setAiError(result.error);
      // Validate flight result — must have at least status or flight_number to display
      if (result.flight && !result.flight.error && (result.flight.status || result.flight.flight_number)) {
        if (result.flight.delay_minutes != null) result.flight.delay_minutes = Number(result.flight.delay_minutes) || 0;
        setFlightData(result.flight);
        if (result.flight.airline && result.flight.flight_number && !form.airline) {
          setForm(p => ({ ...p, airline: sanitize(result.flight.airline, 50) }));
        }
        if (result.flight.flight_number && result.flight.flight_number !== form.flightNumber) {
          setForm(p => ({ ...p, flightNumber: sanitize(result.flight.flight_number, 20) }));
        }
      }
      // Validate fare result
      if (result.fare && (result.fare.found || result.fare.total)) {
        setFareData(result.fare);
        if (result.fare.total) {
          setForm(p => ({ ...p, paymentAmount: String(result.fare.total) }));
        }
      }
      if (result.summary) setAiSummary(result.summary);
      if (result.text && !result.summary) setAiSummary(result.text);
    } catch (err) {
      setAiError("AI Assist error: " + sanitizeErrorMsg(err));
    } finally {
      setAiLoading(false);
      clearInterval(aiTimerRef.current);
    }
  }, [form.flightNumber, form.airline, form.date, form.pickupAddress, form.dropoffAddress, form.tripType, form.passengers]);

  // ── Quick flight-only lookup ──
  const lookupFlightOnly = useCallback(async () => {
    if (!form.flightNumber && !form.airline) return;
    setAiLoading(true); setAiError(""); setFlightData(null); setFareData(null); setAiSummary("");
    setAiTimer(0);
    aiTimerRef.current = setInterval(() => setAiTimer(t => t + 1), 1000);
    try {
      const result = await executeFlight({
        flight_number: form.flightNumber,
        airline: form.airline,
        city: "",
        date: form.date
      });
      if (result.error || result.status === "error") {
        setAiError(result.error || "Flight lookup failed");
        // If there's raw_info, show it as a summary instead of broken card
        // raw_info removed for security — don't expose raw API responses
      } else {
        setFlightData(result);
        // Auto-fill airline only from valid structured results
        if (result.airline && result.flight_number && !form.airline) {
          setForm(p => ({ ...p, airline: sanitize(result.airline, 50) }));
        }
        // Auto-fill flight number if returned in different format
        if (result.flight_number && result.flight_number !== form.flightNumber) {
          setForm(p => ({ ...p, flightNumber: sanitize(result.flight_number, 20) }));
        }
      }
    } catch (err) {
      setAiError("Flight lookup error: " + sanitizeErrorMsg(err));
    } finally {
      setAiLoading(false);
      clearInterval(aiTimerRef.current);
    }
  }, [form.flightNumber, form.airline, form.date]);

  // ── Speech Recognition (sandbox-aware, mic optional) ──
  const isStoppingRef = useRef(false);
  const finalTranscriptRef = useRef("");
  const interimRef = useRef("");
  const silenceTimerRef = useRef(null);

  const startRecognition = useCallback(() => {
    const SR = window.SpeechRecognition || window.webkitSpeechRecognition;
    if (!SR) { setMicPermission("sandbox"); return; }
    if (recognitionRef.current) {
      try { recognitionRef.current.abort(); } catch {}
    }
    isStoppingRef.current = false;
    finalTranscriptRef.current = "";
    interimRef.current = "";
    setTranscript("");

    const r = new SR();
    r.lang = speechLang;
    r.interimResults = true;
    r.continuous = true;
    r.maxAlternatives = 1;

    // Auto-shutoff: stop mic after 10 seconds of silence
    const resetSilenceTimer = () => {
      if (silenceTimerRef.current) clearTimeout(silenceTimerRef.current);
      silenceTimerRef.current = setTimeout(() => {
        if (recognitionRef.current && !isStoppingRef.current) {
          isStoppingRef.current = true;
          try { recognitionRef.current.stop(); } catch {}
          setIsListening(false);
          if (finalTranscriptRef.current) {
            setTranscript(finalTranscriptRef.current);
            setVoiceError("Mic auto-stopped after 10s of silence. Tap Quick Fill to parse, or tap mic to record again.");
          } else {
            setVoiceError("No speech detected — mic stopped. Tap the mic button to try again, or type below.");
          }
        }
      }, 10000);
    };

    r.onstart = () => {
      setIsListening(true); setVoiceError(""); setMicPermission("granted");
      resetSilenceTimer(); // Start the 10s countdown
    };
    r.onresult = (e) => {
      let fin = "", inter = "";
      for (let i = 0; i < e.results.length; i++) {
        if (e.results[i].isFinal) fin += e.results[i][0].transcript;
        else inter += e.results[i][0].transcript;
      }
      finalTranscriptRef.current = fin;
      interimRef.current = inter;
      setTranscript(fin + (inter ? "..." + inter : ""));
      resetSilenceTimer(); // Reset the timer — speech was detected
    };
    r.onerror = (e) => {
      if (silenceTimerRef.current) { clearTimeout(silenceTimerRef.current); silenceTimerRef.current = null; }
      if (e.error === "not-allowed" || e.error === "permission-denied") {
        setMicPermission("denied"); setIsListening(false);
        setVoiceError("Mic access denied. On iOS: Settings \u2192 Safari \u2192 Microphone \u2192 Allow. Or just type below.");
        return;
      }
      if (e.error === "no-speech" || e.error === "aborted") return;
      if (e.error === "network" || e.error === "service-not-allowed") {
        setIsListening(false);
        setVoiceError("Speech service error — check your internet connection and try again. If this persists, type below and use Quick Fill.");
        return;
      }
    };
    r.onend = () => {
      if (silenceTimerRef.current) { clearTimeout(silenceTimerRef.current); silenceTimerRef.current = null; }
      // Only auto-restart if user didn't manually stop AND mic permission is confirmed
      // Use ref (not closure) because micPermission state may have changed since startRecognition was called
      if (!isStoppingRef.current && recognitionRef.current && micPermissionRef.current === "granted") {
        try { recognitionRef.current.start(); } catch { setIsListening(false); }
        return;
      }
      setIsListening(false);
      if (finalTranscriptRef.current) setTranscript(finalTranscriptRef.current);
    };
    try { r.start(); recognitionRef.current = r; }
    catch { setMicPermission("sandbox"); setIsListening(false); }
  }, [speechLang]);

  // Request mic via getUserMedia (triggers native iOS/browser permission dialog)
  const requestMicPermission = useCallback(async () => {
    setShowMicPrompt(false);
    setVoiceError("");
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
      stream.getTracks().forEach(t => t.stop());
      setMicPermission("granted");
      startRecognition();
    } catch (err) {
      if (err.name === "NotAllowedError" || err.name === "PermissionDeniedError") {
        setMicPermission("denied");
        setVoiceError("Mic access denied. Reload the page and tap Allow when prompted.");
      } else if (err.name === "NotFoundError") {
        setMicPermission("sandbox");
        setVoiceError("No microphone detected on this device. Type your booking info below and tap Quick Fill.");
      } else {
        setVoiceError("Microphone error: " + (err.message || "unknown") + ". Try reloading the page. Or type below and use Quick Fill.");
      }
    }
  }, [startRecognition]);

  // Main mic button handler — ONE prompt only (browser's native SpeechRecognition prompt)
  const startListening = useCallback(() => {
    setVoiceError("");
    if (micPermission === "sandbox") {
      setVoiceError("Microphone requires HTTPS. Deploy to a web host (Netlify, GitHub Pages) or use localhost. For now, type below and tap Quick Fill.");
      return;
    }
    if (micPermission === "denied") {
      const isIOS = /iPad|iPhone|iPod/.test(navigator.userAgent);
      const hint = isIOS ? "On iOS: Settings → Safari → Microphone → Allow"
        : "Click the mic icon in your browser's address bar, or go to site settings to allow microphone";
      setVoiceError("Mic access denied. " + hint + ". Then tap the mic button again.");
      return;
    }
    // For both "granted" AND "unknown" — just start SpeechRecognition directly.
    // The browser will show its own single native permission prompt if needed.
    // No custom modal. No getUserMedia. One prompt, maximum.
    startRecognition();
  }, [micPermission, startRecognition]);

  // Per-field mic — speaks into one address field only
  const startFieldMic = useCallback((fieldName) => {
    const SR = window.SpeechRecognition || window.webkitSpeechRecognition;
    if (!SR) { setVoiceError("Speech recognition not available in this browser. Use Chrome or Safari."); return; }
    if (!window.isSecureContext) { setVoiceError("Microphone requires HTTPS."); return; }
    if (fieldMicRef.current) { try { fieldMicRef.current.abort(); } catch {} }
    const r = new SR();
    r.continuous = false;
    r.interimResults = false;
    r.lang = speechLang || "en-US";
    r.maxAlternatives = 1;
    r.onstart = () => setFieldMicActive(fieldName);
    r.onresult = (e) => {
      const spoken = (e.results[0][0].transcript || "").trim();
      if (spoken) setForm(p => ({ ...p, [fieldName]: sanitize(spoken, 200) }));
    };
    r.onerror = (e) => {
      if (e.error !== "no-speech" && e.error !== "aborted") {
        setVoiceError(e.error === "not-allowed" ? "Mic access denied. Click the mic icon in your address bar to allow." : "Mic error: " + e.error + ". Try again.");
      }
      setFieldMicActive(null);
    };
    r.onend = () => setFieldMicActive(null);
    fieldMicRef.current = r;
    try { r.start(); } catch (err) { setFieldMicActive(null); setVoiceError("Could not start microphone. Try again."); }
  }, [speechLang]);

  const stopFieldMic = useCallback(() => {
    if (fieldMicRef.current) { try { fieldMicRef.current.stop(); } catch {} }
    setFieldMicActive(null);
  }, []);

  const stopListening = useCallback(() => {
    isStoppingRef.current = true;
    if (silenceTimerRef.current) { clearTimeout(silenceTimerRef.current); silenceTimerRef.current = null; }
    if (recognitionRef.current) { try { recognitionRef.current.stop(); } catch {} }
    setIsListening(false);
    // Consolidate: merge final + interim into one clean string
    const final = (finalTranscriptRef.current || "").trim();
    const interim = (interimRef.current || "").trim();
    const combined = (final + (interim ? " " + interim : "")).trim();
    if (combined) {
      finalTranscriptRef.current = combined;
      setTranscript(combined);
    }
  }, []);

  // ── Local Regex Fallback Parser (no API needed) ──
  const parseTranscriptLocal = useCallback(() => {
    // Read visible text from state (more reliable than ref which may miss interim results)
    const raw = transcript || finalTranscriptRef.current || "";
    // Strip leading "..." from interim speech results
    const text = raw.replace(/^\.{2,}\s*/, "").replace(/\.{2,}/g, " ").trim();
    if (!text || text.length < 3) return;
    const t = text.toLowerCase().trim();
    const updates = {};

    // ── Date — "March 30", "3/30", "March 30th", "Jan 2", "2025-03-30", "tomorrow", "today" ──
    const months = { jan:1,january:1,feb:2,february:2,mar:3,march:3,apr:4,april:4,may:5,jun:6,june:6,jul:7,july:7,aug:8,august:8,sep:9,september:9,oct:10,october:10,nov:11,november:11,dec:12,december:12 };
    const dateMatch = t.match(/(\d{4})[\/\-](\d{1,2})[\/\-](\d{1,2})/)  // 2025-03-30
      || t.match(/(\d{1,2})[\/\-](\d{1,2})[\/\-](\d{2,4})/)  // 3/30/2025 or 3/30/25
      || t.match(/(\d{1,2})[\/\-](\d{1,2})(?!\d)/);  // 3/30
    const dateWordMatch = t.match(/(january|february|march|april|may|june|july|august|september|october|november|december|jan|feb|mar|apr|jun|jul|aug|sep|oct|nov|dec)\s+(\d{1,2})(?:st|nd|rd|th)?(?:\s*,?\s*(\d{4}))?/i);
    
    if (dateMatch) {
      if (dateMatch[0].match(/^\d{4}/)) {
        // YYYY-MM-DD
        updates.date = `${dateMatch[1]}-${dateMatch[2].padStart(2,"0")}-${dateMatch[3].padStart(2,"0")}`;
      } else if (dateMatch[3]) {
        // M/D/YYYY
        const yr = dateMatch[3].length === 2 ? "20" + dateMatch[3] : dateMatch[3];
        updates.date = `${yr}-${dateMatch[1].padStart(2,"0")}-${dateMatch[2].padStart(2,"0")}`;
      } else {
        // M/D (current year)
        const yr = new Date().getFullYear();
        updates.date = `${yr}-${dateMatch[1].padStart(2,"0")}-${dateMatch[2].padStart(2,"0")}`;
      }
    } else if (dateWordMatch) {
      const m = months[dateWordMatch[1].toLowerCase()];
      const d = parseInt(dateWordMatch[2]);
      const yr = dateWordMatch[3] ? parseInt(dateWordMatch[3]) : new Date().getFullYear();
      if (m && d) updates.date = `${yr}-${String(m).padStart(2,"0")}-${String(d).padStart(2,"0")}`;
    } else if (/\btomorrow\b|내일/.test(t)) {
      const tm = new Date(); tm.setDate(tm.getDate() + 1);
      updates.date = tm.toISOString().split("T")[0];
    } else if (/\btoday\b|오늘/.test(t)) {
      updates.date = new Date().toISOString().split("T")[0];
    }

    // ── Time — "3 PM", "3:30 PM", "15:00", "at 10 AM", "오후 3시" ──
    const timeMatch = t.match(/(?:at\s+)?(\d{1,2})\s*:\s*(\d{2})\s*(am|pm|a\.m\.|p\.m\.)?/i)
      || t.match(/(?:at\s+)?(\d{1,2})\s*(am|pm|a\.m\.|p\.m\.)/i)
      || t.match(/오전\s*(\d{1,2})\s*시/)
      || t.match(/오후\s*(\d{1,2})\s*시/);
    if (timeMatch) {
      let hr = parseInt(timeMatch[1]);
      let min = timeMatch[2] && /^\d+$/.test(timeMatch[2]) ? timeMatch[2] : "00";
      let ampm = (timeMatch[3] || timeMatch[2] || "").toLowerCase().replace(/\./g, "");
      // Korean 오후 = PM
      if (/오후/.test(t.slice(Math.max(0, t.indexOf(timeMatch[0]) - 3), t.indexOf(timeMatch[0]) + timeMatch[0].length))) ampm = "pm";
      if (/오전/.test(t.slice(Math.max(0, t.indexOf(timeMatch[0]) - 3), t.indexOf(timeMatch[0]) + timeMatch[0].length))) ampm = "am";
      
      if (ampm === "pm" && hr < 12) hr += 12;
      if (ampm === "am" && hr === 12) hr = 0;
      
      // Convert to 12h slot format matching AM_SLOTS/PM_SLOTS
      const h12 = hr === 0 ? 12 : hr > 12 ? hr - 12 : hr;
      const suffix = hr >= 12 ? "PM" : "AM";
      const minRound = parseInt(min) >= 30 ? "30" : "00";
      updates.timeSlot = `${h12}:${minRound} ${suffix}`;
    }

    // ── Payment — "$70", "70 dollars", "70달러" — match BEFORE pickup/dropoff so we can exclude it ──
    const payMatch = t.match(/\$\s?(\d+(?:[.,]\d+)?)/i)
      || t.match(/(\d+(?:[.,]\d+)?)\s*(?:dollar|dollars|달러|불)/i)
      || t.match(/(?:payment|pay|금액|fare)\s*[:]?\s*\$?\s*(\d+(?:[.,]\d+)?)/i);
    if (payMatch) updates.paymentAmount = payMatch[1].replace(/[,.]/g, "");

    // ── Flight — "KE81", "flight KE 81", IATA code — match BEFORE pickup/dropoff ──
    const flightMatch = t.match(/(?:flight|편명?|편\s*)\s*[:]?\s*([a-z]{2}\s?\d{1,5})/i)
      || t.match(/\b([a-z]{2}\s?\d{2,5})\b/i);
    if (flightMatch) updates.flightNumber = flightMatch[1].toUpperCase().replace(/\s/g, "");

    // ── Airline — known carriers or keyword ──
    const airlineMatch = t.match(/\b(korean\s*air|asiana|united(?:\s*airlines?)?|delta(?:\s*(?:air\s*lines?)?)?|american(?:\s*airlines?)?|jetblue|southwest|spirit|frontier|alaska(?:\s*airlines?)?|eva\s*air|cathay\s*pacific|japan\s*airlines?|ana|대한항공|아시아나)\b/i)
      || t.match(/(?:airline|항공|항공사)\s*[:]?\s*([a-z가-힣][a-z가-힣\s]{1,25}?)(?=\s+(?:flight|편|\b[a-z]{2}\d))/i);
    if (airlineMatch) updates.airline = airlineMatch[1].trim();

    // ── Driver — "driver 19", "기사 08" ──
    const drvMatch = t.match(/(?:driver|기사|드라이버)\s*[#]?\s*(\d{1,2})/i);
    if (drvMatch) updates.driverNumber = drvMatch[1].padStart(3, "0");

    // ── Name — "name X", "고객 X", or first capitalized words in original text ──
    const nameMatch = t.match(/(?:name\s*(?:is)?|이름\s*(?:은|이)?|customer|고객)\s*[:]?\s*([a-z가-힣][a-z가-힣\s.]{1,30}?)(?=\s*(?:pickup|pick\s*up|phone|from|to|에서|까지|airline|flight|passenger|luggage|편도|왕복|드라이버|driver|at\s+\d|\d{3,}|\$))/i)
      || t.match(/(?:name\s*(?:is)?|이름\s*(?:은|이)?|customer|고객)\s*[:]?\s*([a-z가-힣][a-z가-힣\s.]{1,30})/i);
    if (nameMatch) {
      const n = nameMatch[1].trim();
      // Only accept if it looks like a name (not an airport or address keyword)
      if (n.length >= 2 && !/^(jfk|lga|ewr|newark|laguardia|manhattan|brooklyn|queens|flushing|from|to|pickup|drop)$/i.test(n)) {
        updates.customerName = n;
      }
    }
    // Fallback: if no name keyword, try first word(s) from original text that look like a name
    if (!updates.customerName) {
      const origWords = text.trim().split(/\s+/);
      const nameWords = [];
      for (const w of origWords) {
        // Stop at keywords/numbers
        if (/^(from|to|pickup|drop|phone|flight|airline|driver|at|\d|JFK|LGA|EWR)/i.test(w)) break;
        if (/^[A-Z가-힣]/.test(w) && w.length >= 2) nameWords.push(w);
        else break;
      }
      if (nameWords.length >= 1 && nameWords.length <= 4) {
        const candidate = nameWords.join(" ");
        if (!/^(JFK|LGA|EWR|Manhattan|Brooklyn|Queens)/i.test(candidate)) {
          updates.customerName = candidate;
        }
      }
    }

    // ── Phone — "phone X", or standalone phone pattern ──
    const phoneMatch = t.match(/(?:phone|전화|번호|call|연락처)\s*[:]?\s*([\d\s\-().]{7,})/i)
      || t.match(/((?:\+?1[\s-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4})/);
    if (phoneMatch) updates.phone = phoneMatch[1].replace(/[\s\-().]/g, "");

    // ── Trip type ──
    if (/round\s*trip|왕복/.test(t)) updates.tripType = "round-trip";
    else if (/one\s*way|편도/.test(t)) updates.tripType = "one-way";

    // ── Passengers ──
    const paxMatch = t.match(/(\d+)\s*(?:passenger|passengers|명|사람|people|person|pax)/i);
    if (paxMatch) updates.passengers = paxMatch[1];

    // ── Luggage ──
    const lugMatch = t.match(/(\d+)\s*(?:luggage|bag|bags|짐|가방|개|suitcase|캐리어)/i);
    if (lugMatch) updates.luggage = lugMatch[1];

    // ── Pickup & Dropoff — parse LAST so we can exclude already-matched fields ──
    // Build a "cleaned" version of the text with matched items removed to prevent bleed
    let cleaned = t;
    // Remove known matches to avoid them bleeding into pickup/dropoff
    if (updates.date) cleaned = cleaned.replace(dateWordMatch ? dateWordMatch[0].toLowerCase() : (dateMatch ? dateMatch[0] : ""), " ");
    if (timeMatch) cleaned = cleaned.replace(timeMatch[0].toLowerCase(), " ");
    if (payMatch) cleaned = cleaned.replace(payMatch[0].toLowerCase(), " ");
    if (flightMatch) cleaned = cleaned.replace(flightMatch[0].toLowerCase(), " ");
    if (drvMatch) cleaned = cleaned.replace(drvMatch[0].toLowerCase(), " ");
    if (paxMatch) cleaned = cleaned.replace(paxMatch[0].toLowerCase(), " ");
    if (lugMatch) cleaned = cleaned.replace(lugMatch[0].toLowerCase(), " ");
    cleaned = cleaned.replace(/\s+/g, " ").trim();

    // Airport codes as standalone pickup
    const airportCodes = { jfk: "JFK", lga: "LaGuardia", ewr: "Newark EWR", "la guardia": "LaGuardia", laguardia: "LaGuardia", newark: "Newark EWR", kennedy: "JFK" };

    const pickupMatch = cleaned.match(/(?:pickup|pick\s*up|from|출발|에서)\s*[:]?\s*(.+?)(?=\s*(?:\bto\b|\bdrop|도착|까지)|$)/i);
    const dropoffMatch = cleaned.match(/(?:\bto\b|drop\s*off?|도착|까지)\s*[:]?\s*(.+?)(?=\s*(?:airline|항공|korean|united|delta|american|asiana|jetblue|driver|기사|one\s*way|round|편도|왕복)|$)/i);

    if (pickupMatch) {
      let pu = pickupMatch[1].trim().replace(/\s+/g, " ");
      // Normalize airport codes
      for (const [key, val] of Object.entries(airportCodes)) {
        if (pu.toLowerCase() === key || pu.toLowerCase().startsWith(key + " ")) { pu = val; break; }
      }
      if (pu.length >= 2) updates.pickupAddress = pu;
    }

    if (dropoffMatch) {
      let doff = dropoffMatch[1].trim().replace(/\s+/g, " ");
      for (const [key, val] of Object.entries(airportCodes)) {
        if (doff.toLowerCase() === key || doff.toLowerCase().startsWith(key + " ")) { doff = val; break; }
      }
      if (doff.length >= 2) updates.dropoffAddress = doff;
    }

    // Fallback: if no keywords, try "AIRPORT to DESTINATION" pattern
    if (!updates.pickupAddress && !updates.dropoffAddress) {
      const simpleMatch = cleaned.match(/\b(jfk|lga|ewr|laguardia|newark|kennedy)\b\s+(?:to)\s+(.+?)(?=\s+(?:korean|united|delta|american|airline|driver|기사|\d+\s*dollar)|$)/i);
      if (simpleMatch) {
        updates.pickupAddress = airportCodes[simpleMatch[1].toLowerCase()] || simpleMatch[1].toUpperCase();
        updates.dropoffAddress = simpleMatch[2].trim();
      }
    }

    if (Object.keys(updates).length > 0) {
      setForm(prev => ({
        ...prev,
        ...(updates.customerName && { customerName: sanitize(updates.customerName) }),
        ...(updates.phone && { phone: sanitizePhone(updates.phone) }),
        ...(updates.pickupAddress && { pickupAddress: sanitize(updates.pickupAddress) }),
        ...(updates.dropoffAddress && { dropoffAddress: sanitize(updates.dropoffAddress) }),
        ...(updates.airline && { airline: sanitize(updates.airline, 50) }),
        ...(updates.flightNumber && { flightNumber: sanitize(updates.flightNumber, 20) }),
        ...(updates.passengers && { passengers: sanitizeNumeric(updates.passengers) }),
        ...(updates.luggage && { luggage: sanitizeNumeric(updates.luggage) }),
        ...(updates.tripType && { tripType: updates.tripType }),
        ...(updates.paymentAmount && { paymentAmount: sanitizeNumeric(updates.paymentAmount) }),
        ...(updates.driverNumber && { driverNumber: sanitizeDriverId(updates.driverNumber) }),
        ...(updates.date && { date: updates.date }),
        ...(updates.timeSlot && { timeSlot: updates.timeSlot }),
      }));
      setParsedFields(updates);
      setParseStatus("done");
    } else {
      setVoiceError("Could not parse any fields. Try saying something like: 'Kim Min Ho from JFK to Manhattan March 30 3 PM Korean Air KE81 driver 19 $70'");
      setParseStatus("idle");
    }
  }, [transcript]);

  // Auto-fill form when mic stops and there's text
  const wasListeningRef = useRef(false);
  useEffect(() => {
    if (wasListeningRef.current && !isListening && transcript.trim().length >= 3) {
      // Small delay to let React state flush
      const timer = setTimeout(() => { parseTranscriptLocal(); }, 300);
      return () => clearTimeout(timer);
    }
    wasListeningRef.current = isListening;
  }, [isListening, transcript, parseTranscriptLocal]);

  // ── AI-Powered Transcript Parser (handles Konglish naturally) ──
  const [parseStatus, setParseStatus] = useState("idle"); // idle | parsing | done
  const [parsedFields, setParsedFields] = useState(null);

  const parseTranscriptAI = useCallback(async () => {
    const text = finalTranscriptRef.current || transcript;
    if (!text || text.trim().length < 3) return;

    setParseStatus("parsing");
    try {
      const resp = await fetch("https://api.anthropic.com/v1/messages", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          model: "claude-sonnet-4-20250514",
          max_tokens: 1000,
          system: `You extract taxi booking fields from dispatcher speech (often Konglish — mixed Korean/English).
Return ONLY a JSON object (no markdown, no backticks, no explanation). Every field is a string or null.
Fields: customer_name, phone, pickup_address, dropoff_address, airline, flight_number, passengers (number as string), luggage (number as string), trip_type ("one-way" or "round-trip" or null), payment_amount (number as string), driver_number (two-digit string like "08").

Rules:
- Extract what you can, null for anything not mentioned
- Korean names: romanize (e.g. 김민호 → Kim Minho) AND keep hangul in parentheses
- Phone: digits only, no spaces
- Airports: normalize to code (JFK, LGA, EWR)
- Flight: uppercase IATA format (e.g. KE81, UA123)
- Driver: pad to 2 digits (8 → "08")
- If they say a city/area name for pickup/dropoff, keep it as-is
- payment_amount: digits only, strip currency words
- "편도" = one-way, "왕복" = round-trip
- "명" or "사람" after a number = passengers
- "개" or "짐" or "가방" after a number = luggage`,
          messages: [{ role: "user", content: `Dispatcher said: "${text}"` }]
        })
      });
      const data = await resp.json();
      const aiText = (data.content || []).filter(b => b.type === "text").map(b => b.text).join("");
      const parsed = JSON.parse(aiText.replace(/```json|```/g, "").trim());
      setParsedFields(parsed);

      // Auto-fill form with parsed fields
      const updates = {};
      if (parsed.customer_name) updates.customerName = sanitize(parsed.customer_name);
      if (parsed.phone) updates.phone = sanitizePhone(parsed.phone);
      if (parsed.pickup_address) updates.pickupAddress = sanitize(parsed.pickup_address);
      if (parsed.dropoff_address) updates.dropoffAddress = sanitize(parsed.dropoff_address);
      if (parsed.airline) updates.airline = sanitize(parsed.airline, 50);
      if (parsed.flight_number) updates.flightNumber = sanitize(parsed.flight_number, 20);
      if (parsed.passengers) updates.passengers = sanitizeNumeric(parsed.passengers);
      if (parsed.luggage) updates.luggage = sanitizeNumeric(parsed.luggage);
      if (parsed.trip_type === "one-way" || parsed.trip_type === "round-trip") updates.tripType = parsed.trip_type;
      if (parsed.payment_amount) updates.paymentAmount = sanitizeNumeric(parsed.payment_amount);
      if (parsed.driver_number) updates.driverNumber = sanitizeDriverId(parsed.driver_number);

      if (Object.keys(updates).length > 0) {
        setForm(prev => ({ ...prev, ...updates }));
      }
      setParseStatus("done");
    } catch (err) {
      console.error("AI parse error:", err);
      // Fallback to local regex parsing
      parseTranscriptLocal();
      setParseStatus("done");
    }
  }, [transcript]);


  // Airport detection — drives airline/flight requirement and greying
  const isAirportTrip = useMemo(() => {
    const AIRPORT_CODES = ["JFK", "LGA", "EWR"];
    const pu = normalizeLocation(form.pickupAddress);
    const do_ = normalizeLocation(form.dropoffAddress);
    return AIRPORT_CODES.includes(pu) || AIRPORT_CODES.includes(do_);
  }, [form.pickupAddress, form.dropoffAddress]);

  // Arrival: pickup=airport → customer is ARRIVING → need airline + flight
  const isArrivalTrip = useMemo(() => {
    const AIRPORT_CODES = ["JFK", "LGA", "EWR"];
    return AIRPORT_CODES.includes(normalizeLocation(form.pickupAddress));
  }, [form.pickupAddress]);

  // Departure: dropoff=airport → customer is DEPARTING → no airline/flight needed
  const isDepartureTrip = useMemo(() => {
    const AIRPORT_CODES = ["JFK", "LGA", "EWR"];
    return AIRPORT_CODES.includes(normalizeLocation(form.dropoffAddress));
  }, [form.dropoffAddress]);

  const [isSubmitting, setIsSubmitting] = useState(false);
  const handleSubmit = () => {
    if (isSubmitting) return;
    setFormError("");
    setMissingFields([]);

    // Validate ALL fields — collect every missing one with clear labels
    const checks = [
      { key: "customerName", label: "Customer Name", required: true, empty: !form.customerName.trim() },
      { key: "phone", label: "Phone Number", required: true, empty: !form.phone.trim() || form.phone.replace(/[^0-9]/g,"").length < 7 },
      { key: "pickupAddress", label: "Pickup Address", required: true, empty: !form.pickupAddress.trim() },
      { key: "dropoffAddress", label: "Dropoff Address", required: true, empty: !form.dropoffAddress.trim() },
      { key: "date", label: "Date", required: true, empty: !form.date },
      { key: "timeSlot", label: "Fleet Assignment", required: true, empty: !form.timeSlot && !form.customTime },
      { key: "airline", label: "Airline", required: isArrivalTrip, empty: isArrivalTrip && !form.airline.trim() },
      { key: "flightNumber", label: "Flight #", required: isArrivalTrip, empty: isArrivalTrip && !form.flightNumber.trim() },
      { key: "driverNumber", label: "Driver", required: true, empty: !form.driverNumber },
      { key: "paymentAmount", label: "Payment", required: true, empty: !form.paymentAmount.trim() || parseFloat(form.paymentAmount) === 0 },
    ];

    const requiredMissing = checks.filter(c => c.required && c.empty);
    const optionalMissing = checks.filter(c => !c.required && c.empty);
    const allMissingKeys = checks.filter(c => c.empty).map(c => c.key);

    if (requiredMissing.length > 0) {
      setMissingFields(allMissingKeys); // Highlight ALL empty fields (required + optional)
      setFormError("__FIELDS__:" + JSON.stringify(requiredMissing.map(c => c.label)) + "|" + JSON.stringify(optionalMissing.map(c => c.label)));
      return;
    }

    // If only optional fields missing, warn once then allow
    if (optionalMissing.length > 0 && !formError.startsWith("__OK__")) {
      setMissingFields(allMissingKeys);
      setFormError("__OK__:" + JSON.stringify(optionalMissing.map(c => c.label)));
      return;
    }

    setIsSubmitting(true);
    setMissingFields([]);
    setTimeout(() => setIsSubmitting(false), 1000);

    // Duplicate booking check
    const dupBooking = bookings.find(b =>
      !b.deleted && (!editingBooking || b.id !== editingBooking.id) &&
      b.phone && form.phone &&
      b.phone.replace(/[^0-9]/g,"") === form.phone.replace(/[^0-9]/g,"") &&
      b.date === form.date && b.timeSlot === form.timeSlot
    );
    if (dupBooking && !window.dupConfirmed) {
      window.dupConfirmed = true;
      setIsSubmitting(false);
      setFormError(`⚠️ Possible duplicate — a booking already exists for this phone at ${form.timeSlot}. Tap Confirm again to book anyway. | 중복 예약 — 이 전화번호로 ${form.timeSlot}에 예약이 이미 있습니다. 다시 확인을 누르면 예약됩니다.`);
      setTimeout(() => { window.dupConfirmed = false; }, 5000);
      return;
    }
    window.dupConfirmed = false;
    // Past-date warning
    const todayDateStr = new Date().toISOString().split("T")[0];
    if (form.date && form.date < todayDateStr) {
      if (!window.pastDateConfirmed) {
        window.pastDateConfirmed = true;
        setIsSubmitting(false);
        setFormError("⚠️ This date is in the past. Tap Confirm again to book anyway. | 날짜가 과거입니다. 다시 확인을 누르면 예약됩니다.");
        setTimeout(() => { window.pastDateConfirmed = false; }, 4000);
        return;
      }
      window.pastDateConfirmed = false;
    }
    // Sanitize all fields before saving
    const booking = {
      customerName: sanitize(form.customerName),
      pickupAddress: sanitize(form.pickupAddress),
      dropoffAddress: sanitize(form.dropoffAddress),
      airline: sanitize(form.airline, 50),
      flightNumber: sanitize(form.flightNumber, 20),
      passengers: sanitizeNumeric(form.passengers) || "1",
      luggage: sanitizeNumeric(form.luggage) || "0",
      tripType: ["one-way","round-trip"].includes(form.tripType) ? form.tripType : "one-way",
      phone: sanitizePhone(form.phone),
      paymentAmount: sanitizeNumeric(form.paymentAmount),
      driverNumber: sanitizeDriverId(form.driverNumber),
      date: sanitize(form.date, 10),
      timeSlot: sanitize(form.timeSlot || form.customTime, 12),
      id: editingBooking ? editingBooking.id : generateSecureId(),
      createdAt: editingBooking ? editingBooking.createdAt : new Date().toISOString(),
      modifiedAt: new Date().toISOString(),
      // Attach flight & fare data if available
      flightStatus: flightData ? sanitize(flightData.status || "", 20) : "",
      flightArrival: flightData ? sanitize(flightData.scheduled_arrival || flightData.actual_arrival || "", 30) : "",
      fareRoute: fareData && fareData.route ? sanitize(fareData.route, 60) : (manualFare && manualFare.found ? manualFare.message : ""),
      fareBreakdown: fareData ? `$${fareData.base_fare || 0}${fareData.toll ? ` +$${fareData.toll} toll` : ""}` : ""
    };
    if (editingBooking) {
      setBookings(prev => prev.map(b => b.id === editingBooking.id ? { ...booking, id: editingBooking.id } : b));
      setEditingBooking(null);
    } else {
      setBookings(prev => [...prev, booking]);
    }
    setShowConfirm(booking);
    setForm({...INIT_FORM});
    setPaymentManuallyEdited(false);
    setAutoFareLabel("");
    // Clear AI state + manual payment flag
    setFlightData(null); setFareData(null); setAiSummary(""); setAiError(""); setManualFare(null);
    setPaymentManuallyEdited(false);
    setMissingFields([]);
  };

  const deleteBooking = (id) => {
    setDeleteConfirmId(id);
  };
  const confirmDelete = () => {
    if (deleteConfirmId) {
      setBookings(prev => prev.filter(b => b.id !== deleteConfirmId));
      setDeleteConfirmId(null);
    }
  };

  const editBooking = (b) => {
    setForm({ customerName: b.customerName, pickupAddress: b.pickupAddress, dropoffAddress: b.dropoffAddress, airline: b.airline, flightNumber: b.flightNumber, passengers: b.passengers, luggage: b.luggage, tripType: b.tripType, phone: b.phone, paymentAmount: b.paymentAmount, driverNumber: b.driverNumber, date: b.date, timeSlot: b.timeSlot, customTime: "" });
    setEditingBooking(b);
    // Restore flight/fare data if present on the booking
    if (b.flightStatus) setFlightData({ status: b.flightStatus, scheduled_arrival: b.flightArrival, flight_number: b.flightNumber, airline: b.airline });
    if (b.fareRoute) setFareData({ found: true, route: b.fareRoute, total: b.paymentAmount });
    setView("booking");
  };

  // ── Filtered bookings ──
  const filteredBookings = useMemo(() => {
    let result = [...bookings];
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      result = result.filter(b =>
        b.customerName.toLowerCase().includes(q) || b.phone.includes(q) || b.driverNumber.includes(q) || b.date.includes(q) || b.airline.toLowerCase().includes(q) || b.flightNumber.toLowerCase().includes(q)
      );
    }
    if (filters.dateFrom) result = result.filter(b => b.date >= filters.dateFrom);
    if (filters.dateTo) result = result.filter(b => b.date <= filters.dateTo);
    if (filters.driverNumber) result = result.filter(b => b.driverNumber === filters.driverNumber);
    if (filters.tripType) result = result.filter(b => b.tripType === filters.tripType);
    if (filters.dayType) {
      result = result.filter(b => {
        const day = new Date(b.date + "T12:00:00").getDay();
        return filters.dayType === "weekday" ? (day >= 1 && day <= 5) : (day === 0 || day === 6);
      });
    }
    if (filters.shift) {
      result = result.filter(b => {
        const t24 = formatTime24(b.timeSlot);
        const h = parseInt(t24);
        if (filters.shift === "morning") return h >= 5 && h < 16;
        if (filters.shift === "night") return h >= 17 || h < 5;
        return true;
      });
    }
    return result.sort((a, b) => {
      if (a.date !== b.date) return a.date.localeCompare(b.date);
      return (a.timeSlot || "").localeCompare(b.timeSlot || "");
    });
  }, [bookings, searchQuery, filters]);

  // Group bookings
  const groupedBookings = useMemo(() => {
    const weekday = [], weekend = [];
    filteredBookings.forEach(b => {
      const day = new Date(b.date + "T12:00:00").getDay();
      if (day === 0 || day === 6) weekend.push(b);
      else weekday.push(b);
    });
    return { weekday, weekend };
  }, [filteredBookings]);

  // Driver availability for selected date
  const driverAvailability = useMemo(() => {
    if (!form.date) return {};
    const result = {};
    DRIVERS.forEach(d => {
      result[d.id] = getDriverShift(d, form.date);
    });
    return result;
  }, [form.date]);

  const selectedDriver = DRIVERS.find(d => d.id === form.driverNumber);

  // For each time slot: count of available drivers & whether selected driver can work it
  const slotInfo = useMemo(() => {
    if (!form.date) return {};
    const allSlots = [...AM_SLOTS, ...PM_SLOTS];
    const info = {};
    allSlots.forEach(slot => {
      const availDrivers = DRIVERS.filter(d => {
        const shift = getDriverShift(d, form.date);
        if (!shift.available) return false;
        return isTimeInShift(slot, shift.start, shift.end);
      });
      const selectedOk = selectedDriver
        ? (() => { const sh = getDriverShift(selectedDriver, form.date); return sh.available && isTimeInShift(slot, sh.start, sh.end); })()
        : null;
      info[slot] = { count: availDrivers.length, selectedDriverOk: selectedOk, driverIds: availDrivers.map(d => d.id) };
    });
    return info;
  }, [form.date, form.driverNumber, selectedDriver]);

  // For each driver: whether they cover the currently selected time slot
  // Drivers already booked at the selected date+time (prevents double-booking)
  const bookedDrivers = useMemo(() => {
    if (!form.date || !form.timeSlot) return new Set();
    const booked = new Set();
    bookings.filter(b => !b.deleted && b.date === form.date && b.timeSlot === form.timeSlot)
      .forEach(b => { if (b.driverNumber && (!editingBooking || b.id !== editingBooking.id)) booked.add(b.driverNumber); });
    return booked;
  }, [bookings, form.date, form.timeSlot, editingBooking]);

  const driverTimeMatch = useMemo(() => {
    if (!form.date || !form.timeSlot) return {};
    const result = {};
    DRIVERS.forEach(d => {
      const shift = getDriverShift(d, form.date);
      if (!shift.available) { result[d.id] = { available: false, reason: "day-off" }; return; }
      const covers = isTimeInShift(form.timeSlot, shift.start, shift.end);
      result[d.id] = { available: covers, reason: covers ? "ok" : "out-of-shift" };
    });
    return result;
  }, [form.date, form.timeSlot]);

  // ── Auth gate ──
  if (authStatus === "loading") {
    return (
      <div style={{ minHeight: "100vh", background: "var(--bg-0)", display: "flex", alignItems: "center", justifyContent: "center" }}>
        <div style={{ textAlign: "center" }}>
          <div style={{ fontSize: 48, marginBottom: 16 }}>🚖</div>
          <p style={{ color: "#7a8498", fontSize: 14 }}>Loading…</p>
        </div>
      </div>
    );
  }

  if (authStatus === "unauthenticated") {
    return (
      <LoginPage
        endpointUrl={syncConfig.endpointUrl}
        onLogin={(userData) => saveSession(userData)}
        onSaveEndpoint={(url) => {
          const newConfig = { ...syncConfig, endpointUrl: url };
          saveSyncConfig(newConfig);
          setSyncConfig(newConfig);
        }}
      />
    );
  }

  // Admin gets the admin dashboard instead of the booking app
  if (currentUser && currentUser.role === "admin") {
    return (
      <AdminDashboard
        currentUser={currentUser}
        endpointUrl={syncConfig.endpointUrl}
        onSignOut={() => clearSession()}
      />
    );
  }

  // Dispatcher: load bookings directly (local encryption pending user decision)
  return (
    <div style={{ minHeight: "100vh", background: "var(--bg-0)", color: "var(--text-1)", fontFamily: "var(--sans)", background: "var(--bg-0)" }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;600;700&family=Noto+Sans+KR:wght@300;400;500;700&display=swap');
        * { box-sizing: border-box; margin: 0; padding: 0; }
        ::-webkit-scrollbar { width: 6px; }
        ::-webkit-scrollbar-track { background: #111318; }
        ::-webkit-scrollbar-thumb { background: var(--border-1); border-radius: 3px; }
        input, select, textarea { font-family: inherit; }
        @keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: 0.4; } }
        @keyframes slideUp { from { opacity: 0; transform: translateY(12px); } to { opacity: 1; transform: translateY(0); } }
        @keyframes glow { 0%,100% { box-shadow: 0 0 8px rgba(76,175,106,0.25); } 50% { box-shadow: 0 0 20px rgba(139,94,60,0.35); } }
        .card-enter { animation: slideUp 0.25s ease-out forwards; }
        .rec-pulse { animation: glow 1.2s ease-in-out infinite; }
        .booking-card-grid span { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        /* Responsive: collapse grids on narrow screens */
        @media (max-width: 480px) {
          .resp-grid-2 { grid-template-columns: 1fr !important; }
          .resp-grid-3 { grid-template-columns: 1fr 1fr !important; }
          .resp-grid-4 { grid-template-columns: repeat(3, 1fr) !important; }
        }
        @media (max-width: 360px) {
          .resp-grid-3 { grid-template-columns: 1fr !important; }
          .resp-grid-4 { grid-template-columns: repeat(2, 1fr) !important; }
        }
        /* Accessibility: reduced motion */
        @media (prefers-reduced-motion: reduce) {
          .card-enter, .rec-pulse { animation: none !important; }
          * { transition-duration: 0.01ms !important; animation-duration: 0.01ms !important; }
        }
        /* Accessibility: visible focus indicator */
        input:focus, select:focus, textarea:focus, button:focus-visible {
          outline: 2px solid #ff6b35 !important;
          outline-offset: 2px;
        }
      `}</style>

      {/* ── Header ── */}
      <header className="safe-header" style={{ background: "rgba(9,21,8,0.97)", backdropFilter: "blur(20px)", WebkitBackdropFilter: "blur(20px)", borderBottom: "1px solid var(--border-0)", boxShadow: "0 1px 0 rgba(76,175,106,0.1)", paddingLeft: 16, paddingRight: 16, paddingTop: "max(env(safe-area-inset-top), 44px)", paddingBottom: 0, position: "sticky", top: 0, zIndex: 100, display: "flex", alignItems: "flex-end", justifyContent: "space-between", minHeight: "calc(54px + max(env(safe-area-inset-top), 44px))", boxSizing: "border-box" }}>
        <div style={{ position: "absolute", top: 0, left: 0, right: 0, height: 2, background: "linear-gradient(90deg, var(--amber) 0%, rgba(240,165,0,0.2) 50%, transparent 100%)", pointerEvents: "none" }} />
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <div style={{ width: 28, height: 28, borderRadius: 7, background: "linear-gradient(135deg, #8a6000, var(--amber))", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 13, boxShadow: "0 0 12px rgba(240,165,0,0.2)" }}>🚖</div>
          <div>
            <h1 style={{ fontSize: 15, fontWeight: 700, letterSpacing: "0.1em", color: "var(--amber)", fontFamily: "var(--display)", lineHeight: 1 }}>DISPATCH HQ</h1>
            <p style={{ fontSize: 9, color: "var(--text-3)", fontFamily: "var(--mono)", letterSpacing: "0.1em", marginTop: 2, lineHeight: 1 }}>{session ? (session.displayName || session.username).toUpperCase() : "DISPATCHER"}</p>
          </div>
        </div>
        {/* Desktop nav — hidden on mobile */}
        <nav role="navigation" aria-label="Main tabs" className="top-nav-tabs" style={{ display: "flex", gap: 0, alignItems: "center", overflowX: "auto", WebkitOverflowScrolling: "touch", msOverflowStyle: "none", scrollbarWidth: "none", height: 54 }}>
          {syncConfigured && (
            <span style={{ fontSize: 10, marginRight: 12, color: syncStatus === "syncing" ? "var(--green)" : passphrase ? "var(--green)" : "var(--text-3)", display: "flex", alignItems: "center", gap: 5, fontFamily: "var(--mono)", letterSpacing: "0.1em" }}>
              <span style={{ width: 5, height: 5, borderRadius: "50%", background: syncStatus === "syncing" ? "var(--green)" : passphrase ? "var(--green)" : "var(--text-3)", display: "inline-block", animation: "pulse-dot 1.5s infinite" }} />
              {syncStatus === "syncing" ? "SYNC" : passphrase ? "LIVE" : "OFF"}
            </span>
          )}
          {[["booking","BOOK"],["dashboard","DASH"],["drivers","FLEET"],["sync","SYNC"],["backup","BACKUP"]].map(([v, label]) => (
            <button key={v} onClick={() => setView(v)} style={{
              padding: "0 12px", height: 54, borderRadius: 0, border: "none",
              borderBottom: view === v ? "2px solid var(--amber)" : "2px solid transparent",
              borderTop: "2px solid transparent", background: "transparent",
              color: view === v ? "var(--amber)" : "var(--text-2)",
              fontSize: 13, fontWeight: view === v ? 700 : 500, cursor: "pointer",
              fontFamily: "var(--mono)", letterSpacing: "0.08em",
              transition: "color 0.15s, border-color 0.15s", whiteSpace: "nowrap"
            }}>{label}</button>
          ))}
          <div style={{ width: 1, height: 18, background: "var(--border-0)", margin: "0 8px" }} />
          <button onClick={() => clearSession()} style={{ padding: "5px 10px", borderRadius: "var(--r)", border: "1px solid var(--border-0)", background: "transparent", color: "var(--text-2)", fontSize: 12, fontWeight: 600, cursor: "pointer", fontFamily: "var(--mono)", letterSpacing: "0.08em" }}>EXIT</button>
        </nav>
      </header>

      {/* ── Bottom Nav — iPhone only, 44px icons ── */}
      <nav role="navigation" aria-label="Main navigation" className="bottom-nav">
        {[["booking","BOOK"],["dashboard","DASH"],["drivers","FLEET"],["sync","SYNC"],["backup","BAK"]].map(([v, label]) => (
          <button key={v} onClick={() => setView(v)} className={`bottom-nav-btn${view === v ? " active" : ""}`} aria-label={v}>
            <span>{label}</span>
          </button>
        ))}
        <button onClick={() => clearSession()} className="bottom-nav-btn" aria-label="Sign out">
          <span>EXIT</span>
        </button>
      </nav>

      <main role="main" aria-label="Dispatch HQ Application" className="safe-main" style={{ maxWidth: 980, margin: "0 auto", padding: "20px 16px" }}>

        {!gdprDismissed && (
          <div role="alert" style={{ padding: "14px 18px", borderRadius: 10, marginBottom: 20, background: "rgba(61,159,255,0.05)", border: "1px solid rgba(61,159,255,0.15)", display: "flex", alignItems: "flex-start", gap: 12 }}>
            <span style={{ fontSize: 14, marginTop: 1 }}>🔒</span>
            <div style={{ flex: 1 }}>
              <p style={{ fontSize: 13, fontWeight: 600, color: "var(--green)", marginBottom: 4, fontFamily: "var(--sans)" }}>Privacy Notice</p>
              <p style={{ fontSize: 14, color: "var(--text-2)", lineHeight: 1.6 }}>This app stores customer booking data on your device. Cloud Backup encrypts all data before transmission. AI Smart Fill sends booking text to Anthropic's API — don't include sensitive data beyond what's needed. Bookings auto-purge after 2 years.</p>
            </div>
            <button onClick={dismissGdpr} style={{ padding: "5px 14px", borderRadius: 6, border: "none", background: "rgba(61,159,255,0.15)", color: "var(--green)", fontSize: 12, fontWeight: 600, cursor: "pointer", fontFamily: "var(--sans)", flexShrink: 0, whiteSpace: "nowrap" }}>Got it</button>
          </div>
        )}

        {/* ══════════════ BOOKING FORM ══════════════ */}
        {view === "booking" && (<div role="form" aria-label="New booking form">
          <div className="card-enter booking-form-mobile">
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 16 }}>
              <div>
                <h2 style={{ fontSize: 26, fontWeight: 800, color: "var(--text-1)", fontFamily: "var(--sans)", background: "var(--bg-0)", letterSpacing: "-0.01em" }}>{editingBooking ? "EDIT BOOKING" : priceCheckMode ? "PRICE CHECK" : "NEW BOOKING"}</h2>
                <p style={{ fontSize: 11, color: "var(--text-3)", fontFamily: "var(--mono)", letterSpacing: "0.12em", marginTop: 2 }}>{new Date().toLocaleDateString("en-US", { weekday: "long", month: "short", day: "numeric" }).toUpperCase()}</p>
              </div>
              <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                {/* Price Check toggle */}
                {!editingBooking && (
                  <button onClick={() => { setPriceCheckMode(v => !v); setForm(p=>({...INIT_FORM, pickupAddress: p.pickupAddress, dropoffAddress: p.dropoffAddress, passengers: p.passengers, tripType: p.tripType})); setPaymentManuallyEdited(false); setAutoFareLabel(""); }}
                    style={{ padding: "7px 14px", borderRadius: 8, border: `1px solid ${priceCheckMode ? "var(--amber)" : "var(--border-0)"}`, background: priceCheckMode ? "rgba(240,165,0,0.06)" : "var(--bg-1)", color: priceCheckMode ? "var(--amber)" : "var(--text-2)", fontSize: 11, fontWeight: 700, cursor: "pointer", fontFamily: "var(--mono)", letterSpacing: "0.1em", transition: "all 0.2s" }}>
                    {priceCheckMode ? "✕ CLOSE" : "💲 PRICE"}
                  </button>
                )}
                {/* Today / Tomorrow quick buttons */}
                {!editingBooking && !priceCheckMode && (
                  <div style={{ display: "flex", gap: 5 }}>
                    {["Today","Tomorrow"].map((label, i) => {
                      const d = new Date(); d.setDate(d.getDate() + i);
                      const val = d.toISOString().split("T")[0];
                      return (
                        <button key={label} onClick={() => setForm(p=>({...p, date: val}))}
                          style={{ padding: "6px 12px", borderRadius: 7, border: `1px solid ${form.date === val ? "var(--green)" : "var(--border-1)"}`, background: form.date === val ? "rgba(76,175,106,0.08)" : "transparent", color: form.date === val ? "var(--green)" : "var(--text-2)", fontSize: 11, fontWeight: 700, cursor: "pointer", fontFamily: "var(--mono)", letterSpacing: "0.06em", whiteSpace: "nowrap" }}>
                          {label.toUpperCase()}
                        </button>
                      );
                    })}
                  </div>
                )}
                {editingBooking && <button onClick={() => { setEditingBooking(null); setForm({...INIT_FORM}); }} style={{ padding: "7px 16px", background: "var(--bg-2)", border: "1px solid var(--border-1)", borderRadius: 8, color: "var(--text-2)", fontSize: 13, cursor: "pointer", fontFamily: "var(--sans)" }}>Cancel</button>}
              </div>
            </div>

            {/* ══ PRICE CHECK MODE ══ */}
            {priceCheckMode && (
              <div style={{ animation: "fadeUp 0.25s ease forwards" }}>
                {/* Price result display */}
                {autoFareLabel ? (
                  <div style={{ background: "linear-gradient(135deg, rgba(76,175,106,0.06), rgba(245,166,35,0.04))", border: "2px solid var(--amber-border)", borderRadius: 16, padding: "24px 20px", marginBottom: 16, textAlign: "center", position: "relative", overflow: "hidden" }}>
                    <div style={{ position: "absolute", top: 0, left: 0, right: 0, height: 3, background: "linear-gradient(90deg, var(--amber), transparent)" }} />
                    <p style={{ fontSize: 11, fontWeight: 700, color: "var(--text-3)", letterSpacing: "0.2em", fontFamily: "var(--mono)", marginBottom: 8 }}>ESTIMATED FARE</p>
                    <p style={{ fontSize: 64, fontWeight: 400, color: "var(--green)", fontFamily: "var(--sans)", letterSpacing: "0.05em", lineHeight: 1, marginBottom: 6 }}>
                      ${form.paymentAmount || "—"}
                    </p>
                    <p style={{ fontSize: 12, color: "var(--text-2)", fontFamily: "var(--mono)", letterSpacing: "0.06em" }}>{autoFareLabel.replace("Auto: ","").replace("Auto:","")}</p>
                    {/* Book This button */}
                    <button onClick={() => setPriceCheckMode(false)}
                      style={{ marginTop: 20, padding: "12px 32px", borderRadius: 10, border: "none", background: "linear-gradient(135deg, #c47a0a, var(--amber))", color: "#000", fontSize: 14, fontWeight: 800, cursor: "pointer", fontFamily: "var(--sans)", letterSpacing: "0.12em", boxShadow: "0 4px 20px rgba(76,175,106,0.25)" }}>
                      + BOOK THIS TRIP
                    </button>
                  </div>
                ) : (
                  <div style={{ background: "var(--bg-1)", border: "1px solid var(--border-1)", borderRadius: 12, padding: "20px", marginBottom: 16, textAlign: "center" }}>
                    <p style={{ fontSize: 32, color: "var(--text-3)", marginBottom: 8 }}>💲</p>
                    <p style={{ fontSize: 14, color: "var(--text-2)", fontFamily: "var(--mono)", letterSpacing: "0.08em" }}>ENTER PICKUP &amp; DROPOFF TO SEE PRICE</p>
                  </div>
                )}

                {/* Minimal fields — addresses + pax + trip type only */}
                <div className="form-section" style={{ background: "var(--bg-1)", border: "1.5px solid var(--border-0)", borderRadius: 12, padding: 16, marginBottom: 10, boxShadow: "0 1px 0 rgba(76,175,106,0.1)" }}>
                  <p className="form-section-label" style={{ fontSize: 10, fontWeight: 500, color: "var(--green)", letterSpacing: "0.18em", fontFamily: "var(--mono)", marginBottom: 12 }}>ROUTE</p>
                  <AddressField label="Pickup Address" value={form.pickupAddress}
                    onChange={v => { const norm = normalizeLocation(v); const doNorm = normalizeLocation(form.dropoffAddress); const airport = ["JFK","LGA","EWR"].includes(norm) || ["JFK","LGA","EWR"].includes(doNorm); setForm(p=>({...p,pickupAddress:v,...(!airport && {airline:"",flightNumber:""})})); }}
                    highlight={false} mapsReady={mapsReady} speechLang={speechLang} />
                  <div style={{ marginTop: 10 }}>
                    <AddressField label="Dropoff Address" value={form.dropoffAddress}
                      onChange={v => { const norm = normalizeLocation(v); const puNorm = normalizeLocation(form.pickupAddress); const airport = ["JFK","LGA","EWR"].includes(norm) || ["JFK","LGA","EWR"].includes(puNorm); setForm(p=>({...p,dropoffAddress:v,...(!airport && {airline:"",flightNumber:""})})); }}
                      highlight={false} mapsReady={mapsReady} speechLang={speechLang} />
                  </div>
                </div>

                {/* Pax + Trip type */}
                <div className="form-section" style={{ background: "var(--bg-1)", border: "1.5px solid var(--border-0)", borderRadius: 12, padding: 16, marginBottom: 10, boxShadow: "0 1px 0 rgba(76,175,106,0.1)" }}>
                  <p className="form-section-label" style={{ fontSize: 10, fontWeight: 500, color: "var(--green)", letterSpacing: "0.18em", fontFamily: "var(--mono)", marginBottom: 12 }}>PASSENGERS &amp; TRIP</p>
                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginBottom: 12 }}>
                    <div>
                      <label style={labelStyle}>Passengers</label>
                      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                        <button onClick={() => setForm(p=>({...p,passengers:String(Math.max(1,parseInt(p.passengers||1)-1))}))}
                          style={{ width: 44, height: 44, borderRadius: 8, border: "1px solid var(--border-1)", background: "var(--bg-2)", color: "var(--text-2)", fontSize: 20, cursor: "pointer", display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0, boxShadow: "0 1px 0 rgba(76,175,106,0.1)" }}>−</button>
                        <span style={{ flex: 1, textAlign: "center", fontSize: 20, fontWeight: 700, color: "var(--amber)", fontFamily: "var(--mono)", letterSpacing: "0.04em" }}>{form.passengers}</span>
                        <button onClick={() => setForm(p=>({...p,passengers:String(Math.min(12,parseInt(p.passengers||1)+1))}))}
                          style={{ width: 44, height: 44, borderRadius: 8, border: "1px solid var(--border-1)", background: "var(--bg-2)", color: "var(--amber)", fontSize: 20, cursor: "pointer", display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0, boxShadow: "0 1px 0 rgba(76,175,106,0.1)" }}>+</button>
                      </div>
                    </div>
                    <div>
                      <label style={labelStyle}>Luggage</label>
                      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                        <button onClick={() => setForm(p=>({...p,luggage:String(Math.max(0,parseInt(p.luggage||0)-1))}))}
                          style={{ width: 44, height: 44, borderRadius: 8, border: "1px solid var(--border-1)", background: "var(--bg-2)", color: "var(--text-2)", fontSize: 20, cursor: "pointer", display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0, boxShadow: "0 1px 0 rgba(76,175,106,0.1)" }}>−</button>
                        <span style={{ flex: 1, textAlign: "center", fontSize: 20, fontWeight: 700, color: "var(--amber)", fontFamily: "var(--mono)", letterSpacing: "0.04em" }}>{form.luggage}</span>
                        <button onClick={() => setForm(p=>({...p,luggage:String(Math.min(12,parseInt(p.luggage||0)+1))}))}
                          style={{ width: 44, height: 44, borderRadius: 8, border: "1px solid var(--border-1)", background: "var(--bg-2)", color: "var(--amber)", fontSize: 20, cursor: "pointer", display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0, boxShadow: "0 1px 0 rgba(76,175,106,0.1)" }}>+</button>
                      </div>
                    </div>
                  </div>
                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8 }}>
                    {[["one-way","One Way →"],["round-trip","Round Trip ⇄"]].map(([t, label]) => (
                      <button key={t} onClick={() => setForm(p=>({...p,tripType:t}))} style={{
                        padding: "14px 0", borderRadius: 10, border: form.tripType === t ? "2px solid var(--amber)" : "1px solid var(--border-1)",
                        background: form.tripType === t ? "rgba(76,175,106,0.08)" : "var(--bg-2)",
                        color: form.tripType === t ? "var(--amber)" : "var(--text-2)",
                        fontSize: 13, fontWeight: 600, cursor: "pointer", fontFamily: "var(--mono)", letterSpacing: "0.06em", transition: "all 0.15s"
                      }}>{label}</button>
                    ))}
                  </div>
                </div>
              </div>
            )}

            {/* ══ FULL BOOKING FORM (hidden in price check mode) ══ */}
            {!priceCheckMode && (<div>
              <div className="form-section" style={{ background: "var(--bg-1)", border: "1.5px solid var(--border-0)", borderRadius: 12, padding: 16, marginBottom: 10, boxShadow: "0 1px 0 rgba(76,175,106,0.1)" }}>
              <p className="form-section-label" style={{ fontSize: 10, fontWeight: 500, color: "var(--green)", letterSpacing: "0.18em", fontFamily: "var(--mono)", marginBottom: 12 }}>DATE &amp; TIME</p>
              <div className="resp-grid-2" style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>

                {/* ── Custom Calendar Picker ── */}
                <div style={{ position: "relative" }}>
                  <label style={labelStyle}>📅 Date</label>
                  {/* Trigger button */}
                  <button data-picker onClick={() => setShowCal(v => !v)} style={{
                    ...inputStyle, width: "100%", textAlign: "left", cursor: "pointer",
                    border: missingFields.includes("date") ? "1.5px solid #ff3a30" : showCal ? `1.5px solid var(--amber)` : inputStyle.border,
                    boxShadow: showCal ? "0 0 0 1px rgba(76,175,106,0.15)" : missingFields.includes("date") ? "0 0 0 1px rgba(220,38,38,0.15)" : "none",
                    display: "flex", alignItems: "center", justifyContent: "space-between", fontFamily: "inherit", background: inputStyle.background
                  }}>
                    <span style={{ color: form.date ? "#000" : "var(--text-3)" }}>
                      {form.date ? new Date(form.date + "T12:00:00").toLocaleDateString("en-US", { weekday: "short", month: "short", day: "numeric" }) : "Select date"}
                    </span>
                    <span style={{ fontSize: 12, color: "var(--text-3)" }}>{showCal ? "▲" : "▼"}</span>
                  </button>

                  {/* Calendar popup */}
                  {showCal && (() => {
                    const today = new Date(); today.setHours(0,0,0,0);
                    const todayStr = today.toISOString().split("T")[0];
                    const selectedDate = form.date ? new Date(form.date + "T12:00:00") : null;
                    const viewYear = calViewMonth.year;
                    const viewMonth = calViewMonth.month; // 0-indexed
                    const firstDay = new Date(viewYear, viewMonth, 1).getDay();
                    const daysInMonth = new Date(viewYear, viewMonth + 1, 0).getDate();
                    const monthNames = ["January","February","March","April","May","June","July","August","September","October","November","December"];
                    const cells = [];
                    for (let i = 0; i < firstDay; i++) cells.push(null);
                    for (let d = 1; d <= daysInMonth; d++) cells.push(d);
                    while (cells.length % 7 !== 0) cells.push(null);

                    return (
                      <div data-picker style={{
                        position: "absolute", top: "calc(100% + 6px)", left: 0, zIndex: 200,
                        background: "var(--bg-2)", border: "1px solid var(--border-1)", borderRadius: 12,
                        padding: 14, width: 280, boxShadow: "0 8px 32px rgba(0,0,0,0.6)",
                        opacity: 1
                      }}>
                        {/* Month nav */}
                        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 10 }}>
                          <button onClick={() => setCalViewMonth(p => { const d = new Date(p.year, p.month - 1); return { year: d.getFullYear(), month: d.getMonth() }; })} style={{ background: "transparent", border: "none", color: "var(--text-2)", fontSize: 18, cursor: "pointer", padding: "0 6px" }}>‹</button>
                          <span style={{ fontSize: 14, fontWeight: 700, color: "#fff" }}>{monthNames[viewMonth]} {viewYear}</span>
                          <button onClick={() => setCalViewMonth(p => { const d = new Date(p.year, p.month + 1); return { year: d.getFullYear(), month: d.getMonth() }; })} style={{ background: "transparent", border: "none", color: "var(--text-2)", fontSize: 18, cursor: "pointer", padding: "0 6px" }}>›</button>
                        </div>

                        {/* Day headers */}
                        <div style={{ display: "grid", gridTemplateColumns: "repeat(7,1fr)", gap: 2, marginBottom: 4 }}>
                          {["S","M","T","W","T","F","S"].map((d,i) => (
                            <div key={i} style={{ textAlign: "center", fontSize: 11, color: "#7a8498", fontWeight: 700, padding: "2px 0" }}>{d}</div>
                          ))}
                        </div>

                        {/* Day cells */}
                        <div style={{ display: "grid", gridTemplateColumns: "repeat(7,1fr)", gap: 2 }}>
                          {cells.map((day, i) => {
                            if (!day) return <div key={i} />;
                            const dateStr = `${viewYear}-${String(viewMonth+1).padStart(2,"0")}-${String(day).padStart(2,"0")}`;
                            const isPast = dateStr < todayStr;
                            const isToday = dateStr === todayStr;
                            const isSelected = dateStr === form.date;
                            return (
                              <button key={i} onClick={() => { if (!isPast) { setForm(p => ({...p, date: dateStr})); setShowCal(false); } }} style={{
                                padding: "7px 0", borderRadius: 6, border: "none", fontSize: 13, fontFamily: "inherit",
                                background: isSelected ? "var(--green)" : isToday ? "rgba(255,107,53,0.15)" : "transparent",
                                color: isPast ? "var(--border-0)" : isSelected ? "#fff" : isToday ? "var(--green)" : "#ccc",
                                cursor: isPast ? "not-allowed" : "pointer",
                                fontWeight: isSelected || isToday ? 700 : 400,
                                opacity: isPast ? 0.4 : 1
                              }}>{day}</button>
                            );
                          })}
                        </div>

                        {/* Today / Tomorrow shortcuts */}
                        <div style={{ display: "flex", gap: 6, marginTop: 10, borderTop: "1px solid #222", paddingTop: 10 }}>
                          {["Today","Tomorrow"].map((label, offset) => {
                            const d = new Date(); d.setDate(d.getDate() + offset);
                            const ds = d.toISOString().split("T")[0];
                            return (
                              <button key={label} onClick={() => { setForm(p => ({...p, date: ds})); setShowCal(false); }} style={{
                                flex: 1, padding: "6px 0", borderRadius: 6, border: "1px solid var(--border-1)",
                                background: form.date === ds ? "rgba(220,38,38,0.06)" : "transparent",
                                color: "#000", fontSize: 13, cursor: "pointer", fontFamily: "inherit", fontWeight: 600
                              }}>{label}</button>
                            );
                          })}
                        </div>
                      </div>
                    );
                  })()}
                </div>

                {/* ── Quick Time Picker ── */}
                <div style={{ position: "relative" }}>
                  <label style={{...labelStyle, color: missingFields.includes("timeSlot") ? "var(--red)" : labelStyle.color}}>
                    ⏰ Time{missingFields.includes("timeSlot") && <span style={{ color: "var(--red)" }}> *</span>}
                  </label>
                  <button data-picker onClick={() => setShowTimePicker(v => !v)} style={{
                    ...inputStyle, width: "100%", textAlign: "left", cursor: "pointer",
                    border: missingFields.includes("timeSlot") ? "1.5px solid #ff3a30" : showTimePicker ? "1.5px solid #ff6b35" : inputStyle.border,
                    boxShadow: showTimePicker ? "0 0 0 1px rgba(255,107,53,0.2)" : missingFields.includes("timeSlot") ? "0 0 0 1px rgba(220,38,38,0.15)" : "none",
                    display: "flex", alignItems: "center", justifyContent: "space-between", fontFamily: "inherit", background: inputStyle.background
                  }}>
                    <span style={{ color: form.timeSlot ? "var(--text-1)" : "#7a8498" }}>{form.timeSlot || "Select time"}</span>
                    <span style={{ fontSize: 12, color: "#8892a8" }}>{showTimePicker ? "▲" : "▼"}</span>
                  </button>

                  {showTimePicker && (
                    <TimePickerDropdown
                      selected={form.timeSlot}
                      onSelect={(t) => {
                        const [time, period] = t.split(" ");
                        const [h, m] = time.split(":").map(Number);
                        let h24 = period === "PM" && h !== 12 ? h + 12 : period === "AM" && h === 12 ? 0 : h;
                        const customTime = `${String(h24).padStart(2,"0")}:${String(m).padStart(2,"0")}`;
                        setForm(p => ({...p, timeSlot: t, customTime}));
                        setShowTimePicker(false);
                      }}
                      allSlots={[...AM_SLOTS, ...PM_SLOTS]}
                    />
                  )}
                </div>

              </div>
            </div>{/* end Date/Time section */}

            {/* Customer Info */}
            <div style={{ background: "var(--bg-1)", border: "1px solid #1e2028", borderRadius: 14, padding: 18, marginBottom: 14 }}>
              <p style={{ fontSize: 14, fontWeight: 700, color: "var(--green)", marginBottom: 14, letterSpacing: "0.1em" }}>CUSTOMER INFO</p>
              <div className="resp-grid-2" style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
                <Field label="Customer Name" value={form.customerName} onChange={v => setForm(p=>({...p,customerName:v}))} full highlight={missingFields.includes("customerName")} />
                <Field label="Phone Number" value={form.phone} onChange={v => setForm(p=>({...p,phone:v}))} type="tel" highlight={missingFields.includes("phone")} />
                <AddressField label="Pickup Address" value={form.pickupAddress} onChange={v => { const norm = normalizeLocation(v); const doNorm = normalizeLocation(form.dropoffAddress); const airport = ["JFK","LGA","EWR"].includes(norm) || ["JFK","LGA","EWR"].includes(doNorm); setForm(p=>({...p,pickupAddress:v,...(!airport && {airline:"",flightNumber:""})})); }} highlight={missingFields.includes("pickupAddress")} mapsReady={mapsReady} speechLang={speechLang} />
                <AddressField label="Dropoff Address" value={form.dropoffAddress} onChange={v => { const norm = normalizeLocation(v); const puNorm = normalizeLocation(form.pickupAddress); const airport = ["JFK","LGA","EWR"].includes(norm) || ["JFK","LGA","EWR"].includes(puNorm); setForm(p=>({...p,dropoffAddress:v,...(!airport && {airline:"",flightNumber:""})})); }} highlight={missingFields.includes("dropoffAddress")} mapsReady={mapsReady} speechLang={speechLang} />
                {/* Airline & Flight — only required/active for airport trips */}
                <div>
                  <label style={{...labelStyle, color: !isAirportTrip ? "#3a3d46" : missingFields.includes("airline") ? "var(--red)" : labelStyle.color}}>
                    Airline{isArrivalTrip && <span style={{ color: "var(--red)" }}> *</span>}
                    {!isAirportTrip && <span style={{ color: "#3a3d46", fontWeight: 400, marginLeft: 6 }}>(arrival only)</span>}
                    {isDepartureTrip && !isArrivalTrip && <span style={{ color: "var(--text-3)", fontWeight: 400, marginLeft: 6 }}>(not required)</span>}
                  </label>
                  <input
                    type="text" value={form.airline}
                    onChange={e => { if (isAirportTrip) setForm(p=>({...p,airline:e.target.value})); }}
                    disabled={!isAirportTrip}
                    placeholder={isArrivalTrip ? "e.g. Korean Air" : isDepartureTrip ? "(departure — optional)" : "—"}
                    style={{
                      ...inputStyle,
                      opacity: isAirportTrip ? 1 : 0.25,
                      cursor: isAirportTrip ? "text" : "not-allowed",
                      border: isArrivalTrip && missingFields.includes("airline") ? "1.5px solid #ff3a30" : inputStyle.border,
                      boxShadow: isAirportTrip && missingFields.includes("airline") ? "0 0 0 1px rgba(220,38,38,0.15)" : "none",
                    }}
                  />
                </div>
                <div>
                  <label style={{...labelStyle, color: !isAirportTrip ? "#3a3d46" : missingFields.includes("flightNumber") ? "var(--red)" : labelStyle.color}}>
                    Flight #{isArrivalTrip && <span style={{ color: "var(--red)" }}> *</span>}
                    {!isAirportTrip && <span style={{ color: "#3a3d46", fontWeight: 400, marginLeft: 6 }}>(arrival only)</span>}
                    {isDepartureTrip && !isArrivalTrip && <span style={{ color: "var(--text-3)", fontWeight: 400, marginLeft: 6 }}>(not required)</span>}
                  </label>
                  <input
                    type="text" value={form.flightNumber}
                    onChange={e => { if (isAirportTrip) setForm(p=>({...p,flightNumber:e.target.value.toUpperCase()})); }} maxLength={10}
                    disabled={!isAirportTrip}
                    placeholder={isAirportTrip ? "e.g. KE081" : "—"}
                    style={{
                      ...inputStyle,
                      opacity: isAirportTrip ? 1 : 0.25,
                      cursor: isAirportTrip ? "text" : "not-allowed",
                      border: isArrivalTrip && missingFields.includes("flightNumber") ? "1.5px solid #ff3a30" : inputStyle.border,
                      boxShadow: isAirportTrip && missingFields.includes("flightNumber") ? "0 0 0 1px rgba(220,38,38,0.15)" : "none",
                    }}
                  />
                </div>
                {/* Passengers stepper */}
                <div>
                  <label style={labelStyle}>Passengers</label>
                  <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                    <button className="pax-step-btn" onClick={() => setForm(p=>({...p,passengers:String(Math.max(1,parseInt(p.passengers||1)-1))}))}
                      style={{ width: 44, height: 44, borderRadius: 8, border: "1px solid var(--border-1)", background: "var(--bg-2)", color: "var(--text-2)", fontSize: 20, cursor: "pointer", display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0, boxShadow: "0 1px 0 rgba(76,175,106,0.1)" }}>−</button>
                    <span style={{ flex: 1, textAlign: "center", fontSize: 20, fontWeight: 700, color: "var(--amber)", fontFamily: "var(--mono)", letterSpacing: "0.04em" }}>{form.passengers}</span>
                    <button className="pax-step-btn" onClick={() => setForm(p=>({...p,passengers:String(Math.min(12,parseInt(p.passengers||1)+1))}))}
                      style={{ width: 44, height: 44, borderRadius: 8, border: "1px solid var(--border-1)", background: "var(--bg-2)", color: "var(--amber)", fontSize: 20, cursor: "pointer", display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0, boxShadow: "0 1px 0 rgba(76,175,106,0.1)" }}>+</button>
                  </div>
                </div>
                {/* Luggage stepper */}
                <div>
                  <label style={labelStyle}>Luggage</label>
                  <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                    <button className="pax-step-btn" onClick={() => setForm(p=>({...p,luggage:String(Math.max(0,parseInt(p.luggage||0)-1))}))}
                      style={{ width: 44, height: 44, borderRadius: 8, border: "1px solid var(--border-1)", background: "var(--bg-2)", color: "var(--text-2)", fontSize: 20, cursor: "pointer", display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0, boxShadow: "0 1px 0 rgba(76,175,106,0.1)" }}>−</button>
                    <span style={{ flex: 1, textAlign: "center", fontSize: 20, fontWeight: 700, color: "var(--amber)", fontFamily: "var(--mono)", letterSpacing: "0.04em" }}>{form.luggage}</span>
                    <button className="pax-step-btn" onClick={() => setForm(p=>({...p,luggage:String(Math.min(12,parseInt(p.luggage||0)+1))}))}
                      style={{ width: 44, height: 44, borderRadius: 8, border: "1px solid var(--border-1)", background: "var(--bg-2)", color: "var(--amber)", fontSize: 20, cursor: "pointer", display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0, boxShadow: "0 1px 0 rgba(76,175,106,0.1)" }}>+</button>
                  </div>
                </div>
              </div>
              {/* Trip Type — two big buttons */}
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8, marginTop: 12 }}>
                {[["one-way","One Way →"],["round-trip","Round Trip ⇄"]].map(([t, label]) => (
                  <button key={t} className="trip-type-btn" onClick={() => setForm(p=>({...p,tripType:t}))} style={{
                    padding: "14px 0", borderRadius: 10, border: form.tripType === t ? "2px solid var(--amber)" : "1px solid var(--border-1)",
                    background: form.tripType === t ? "rgba(76,175,106,0.08)" : "var(--bg-2)",
                    color: form.tripType === t ? "var(--amber)" : "var(--text-2)",
                    fontSize: 14, fontWeight: 700, cursor: "pointer", fontFamily: "var(--sans)",
                    transition: "all 0.15s"
                  }}>{label}</button>
                ))}
              </div>
              <div className="resp-grid-2" style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10, marginTop: 10 }}>
                <Field label="Payment ($)" value={form.paymentAmount} onChange={v => { setForm(p=>({...p,paymentAmount:v})); setPaymentManuallyEdited(true); }} type="number" highlight={missingFields.includes("paymentAmount")} />
                {/* Auto-fare indicator */}
                {autoFareLabel && (
                  <div style={{ marginTop: 6, display: "flex", alignItems: "center", gap: 8 }}>
                    <span style={{ fontSize: 11, fontFamily: "var(--mono)", color: paymentManuallyEdited ? "var(--text-3)" : "var(--green)", letterSpacing: "0.06em" }}>
                      {paymentManuallyEdited ? "✎ " + autoFareLabel.replace("Auto:", "Override:") : "⚡ " + autoFareLabel}
                    </span>
                    {paymentManuallyEdited && (
                      <button onClick={() => { setPaymentManuallyEdited(false); }}
                        style={{ fontSize: 10, fontFamily: "var(--mono)", color: "var(--green)", background: "transparent", border: "none", cursor: "pointer", letterSpacing: "0.08em", padding: 0 }}>
                        RESET
                      </button>
                    )}
                  </div>
                )}
              </div>
            </div>

            {/* ── Flight Status & AI-Powered Fare ── */}
            <div style={{ background: "linear-gradient(135deg, #0f1118, #131620)", border: "1px solid #1a1d28", borderRadius: 14, padding: 18, marginBottom: 14 }}>
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 14 }}>
                <p style={{ fontSize: 14, fontWeight: 700, color: "var(--green)", letterSpacing: "0.1em" }}>✈ FLIGHT STATUS & FARE ASSIST</p>
                {isStandaloneMode() && !aiLoading && !aiError && (
                <div style={{ fontSize: 12, color: "var(--text-2)", background: "rgba(217,119,6,0.05)", padding: "6px 10px", borderRadius: 6, border: "1px solid #3a3a1a" }}>
                  <span>Website mode — AI flight lookup unavailable. </span>
                  <span style={{ color: "var(--green)", fontSize: 11, fontFamily: "var(--mono)", letterSpacing: "0.06em" }}>✈ Live flight data via AviationStack</span>
                </div>
              )}
              {aiLoading && <span style={{ fontSize: 12, color: "var(--amber)", animation: "pulse 1s infinite" }}>⏳ Searching... ({aiTimer}s)</span>}
              </div>

              {/* Action Buttons */}
              <div style={{ display: "flex", gap: 6, marginBottom: 14 }}>
                <button
                  onClick={lookupFlightOnly}
                  disabled={aiLoading || (!form.flightNumber && !form.airline)}
                  style={{
                    flex: 1, padding: "10px 8px", borderRadius: 8, border: "none", fontSize: 14, fontWeight: 700,
                    background: (!form.flightNumber && !form.airline) ? "var(--bg-2)" : "var(--amber)",
                    color: (!form.flightNumber && !form.airline) ? "var(--text-3)" : "#0a0a0a",
                    cursor: (!form.flightNumber && !form.airline || aiLoading) ? "default" : "pointer", fontFamily: "var(--mono)", letterSpacing: "0.06em",
                    opacity: aiLoading ? 0.5 : 1
                  }}
                >
                  {aiLoading ? "⏳ CHECKING..." : "✈ CHECK FLIGHT"}
                </button>
                <button
                  onClick={runAIAssistHandler}
                  disabled={aiLoading || ((!form.flightNumber && !form.airline) && (!form.pickupAddress || !form.dropoffAddress))}
                  style={{
                    flex: 2, padding: "10px 8px", borderRadius: 8, border: "none", fontSize: 14, fontWeight: 700,
                    background: aiLoading ? "var(--bg-2)" : "var(--green)",
                    color: aiLoading ? "var(--text-3)" : "#0a0a0a",
                    cursor: aiLoading ? "default" : "pointer", fontFamily: "var(--mono)", letterSpacing: "0.06em",
                    boxShadow: aiLoading ? "none" : "0 2px 12px rgba(76,175,106,0.2)",
                    opacity: aiLoading ? 0.5 : 1
                  }}
                >
                  {aiLoading ? `⏳ CHECKING... (${aiTimer}s)` : "✈ CHECK FLIGHT + FARE"}
                </button>
              </div>

              {/* AI Summary */}
              {aiSummary && (
                <div style={{ padding: "8px 12px", background: "rgba(59,158,255,0.06)", border: "1px solid #1a2a4a", borderRadius: 8, marginBottom: 12 }}>
                  <p style={{ fontSize: 14, color: "var(--green)" }}>{aiSummary}</p>
                </div>
              )}

              {/* Error */}
              {aiError && (
                <div style={{ padding: "8px 12px", background: "rgba(220,38,38,0.04)", border: "1px solid #3a1a1a", borderRadius: 8, marginBottom: 12 }}>
                  <p style={{ fontSize: 13, color: "var(--red)" }}>⚠ {aiError}</p>
                </div>
              )}

              {/* Flight Data Card */}
              {flightData && !flightData.error && flightData.status !== "error" && flightData.status !== "unavailable" && (
                <div style={{ background: "var(--bg-1)", border: "1px solid var(--border-1)", borderRadius: 10, padding: 14, marginBottom: 10 }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 10 }}>
                    <span style={{ fontSize: 18 }}>✈</span>
                    <div>
                      <p style={{ fontSize: 16, fontWeight: 700, color: "var(--text-1)" }}>
                        {flightData.flight_number || form.flightNumber || "Flight"}
                        {flightData.airline && <span style={{ fontWeight: 400, color: "var(--text-2)", fontSize: 14 }}> · {flightData.airline}</span>}
                      </p>
                    </div>
                    {/* Status badge */}
                    <span style={{
                      marginLeft: "auto", padding: "3px 10px", borderRadius: 6, fontSize: 12, fontWeight: 700,
                      background: flightData.status === "scheduled" || flightData.status === "landed" || flightData.status === "on-time" ? "rgba(5,150,105,0.1)" :
                        flightData.delay_minutes > 0 ? "rgba(217,119,6,0.1)" :
                        flightData.status === "cancelled" ? "rgba(220,38,38,0.1)" : "rgba(150,150,150,0.1)",
                      color: flightData.status === "scheduled" || flightData.status === "landed" || flightData.status === "on-time" ? "var(--green)" :
                        flightData.delay_minutes > 0 ? "var(--amber)" :
                        flightData.status === "cancelled" ? "var(--red)" : "var(--text-2)",
                      border: `1px solid ${flightData.status === "scheduled" || flightData.status === "landed" ? "rgba(5,150,105,0.2)" : flightData.delay_minutes > 0 ? "rgba(217,119,6,0.2)" : "var(--border-0)"}`,
                      fontFamily: "var(--mono)", letterSpacing: "0.08em", textTransform: "uppercase"
                    }}>
                      {flightData.status || "Unknown"}
                      {Number(flightData.delay_minutes) > 0 && ` +${flightData.delay_minutes}m`}
                    </span>
                  </div>

                  {/* Message from AviationStack */}
                  {flightData.message && (
                    <div style={{ background: "rgba(240,165,0,0.06)", border: "1px solid var(--amber-border)", borderRadius: 8, padding: "8px 12px", marginBottom: 10, textAlign: "center" }}>
                      <p style={{ fontSize: 14, fontWeight: 700, color: "var(--amber)", fontFamily: "var(--mono)" }}>
                        ✈ {flightData.message}
                      </p>
                    </div>
                  )}

                  <div style={{ display: "grid", gridTemplateColumns: "1fr auto 1fr", gap: 8, alignItems: "center", marginBottom: 8 }}>
                    <div style={{ textAlign: "center" }}>
                      <p style={{ fontSize: 18, fontWeight: 700, color: "var(--green)", fontFamily: "var(--mono)" }}>{flightData.origin_code || flightData.departure || "---"}</p>
                      <p style={{ fontSize: 11, color: "var(--text-2)" }}>Origin</p>
                    </div>
                    <div style={{ fontSize: 16, color: "var(--text-3)" }}>→</div>
                    <div style={{ textAlign: "center" }}>
                      <p style={{ fontSize: 18, fontWeight: 700, color: "var(--green)", fontFamily: "var(--mono)" }}>{flightData.destination_code || flightData.arrival || "---"}</p>
                      <p style={{ fontSize: 11, color: "var(--text-2)" }}>Arrival</p>
                      {(flightData.arrivalTime || flightData.actual_arrival || flightData.scheduled_arrival) && (
                        <p style={{ fontSize: 14, fontWeight: 700, color: flightData.delay_minutes > 0 ? "var(--amber)" : "var(--text-1)", marginTop: 3, fontFamily: "var(--mono)" }}>
                          {flightData.arrivalTime || flightData.actual_arrival || flightData.scheduled_arrival}
                        </p>
                      )}
                    </div>
                  </div>

                  {/* Auto-fill arrival hint */}
                  {(flightData.arrivalTime || flightData.actual_arrival) && (
                    <button onClick={() => {
                      const t = flightData.arrivalTime || flightData.actual_arrival;
                      setForm(p => ({ ...p, flightArrival: t }));
                    }} style={{ width: "100%", padding: "6px", borderRadius: 6, border: "1px solid var(--border-0)", background: "transparent", color: "var(--green)", fontSize: 12, cursor: "pointer", fontFamily: "var(--mono)", letterSpacing: "0.06em" }}>
                      ⚡ USE {flightData.arrivalTime || flightData.actual_arrival} AS ARRIVAL TIME
                    </button>
                  )}
                </div>
              )}

              {/* Fare Data Card */}
              {fareData && fareData.found && (
                <div style={{ background: "var(--bg-1)", border: "1px solid #1a3a1a", borderRadius: 10, padding: 14 }}>
                  <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 8 }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                      <span style={{ fontSize: 16 }}>💰</span>
                      <p style={{ fontSize: 14, fontWeight: 600, color: "#fff" }}>{fareData.route || "Fare"}</p>
                    </div>
                    <p style={{ fontSize: 22, fontWeight: 800, color: "#4ade80" }}>${fareData.total}</p>
                  </div>
                  <div style={{ display: "flex", gap: 10, flexWrap: "wrap", fontSize: 13 }}>
                    <span style={{ color: "var(--text-2)" }}>Base: <span style={{color:"var(--text-2)"}}>${fareData.base_fare}</span></span>
                    {fareData.toll > 0 && <span style={{ color: "var(--text-2)" }}>Toll: <span style={{color:"var(--amber)"}}>${fareData.toll}</span></span>}
                    {fareData.surcharges && fareData.surcharges.length > 0 && fareData.surcharges.map((s, i) => (
                      <span key={i} style={{ color: "#a86c32" }}>{s}</span>
                    ))}
                  </div>
                </div>
              )}

              {!flightData && !fareData && !aiLoading && !aiError && (
                <p style={{ fontSize: 13, color: "#909aaa", textAlign: "center", padding: 8 }}>
                  Enter a flight # or pickup/dropoff above, then press a lookup button.
                  Both run in parallel when available.
                </p>
              )}
            </div>

            {/* Fleet Assignment — driver picker */}
            <div style={{ background: "var(--bg-1)", border: "1px solid #1e2028", borderRadius: 14, padding: 18, marginBottom: 14 }}>
              <p style={{ fontSize: 14, fontWeight: 700, color: "var(--green)", marginBottom: 4, letterSpacing: "0.08em" }}>🚖 Fleet Assignment</p>

              {/* Active filters display */}
              {(() => {
                const pickup  = normalizeLocation(form.pickupAddress);
                const dropoff = normalizeLocation(form.dropoffAddress);
                const needsPickup  = ["JFK","LGA","EWR"].includes(pickup);
                const needsDropoff = ["JFK","LGA","EWR"].includes(dropoff);
                const filters = [];
                if (form.date)    filters.push(`📅 ${new Date(form.date + "T12:00:00").toLocaleDateString("en-US",{weekday:"short",month:"short",day:"numeric"})}`);
                if (form.timeSlot) filters.push(`⏰ ${form.timeSlot}`);
                if (needsPickup)  filters.push(`✈ Airport pickup (${pickup})`);
                if (needsDropoff) filters.push(`✈ Airport dropoff (${dropoff})`);
                return filters.length > 0 ? (
                  <div style={{ display: "flex", flexWrap: "wrap", gap: 5, marginBottom: 12 }}>
                    {filters.map((f,i) => (
                      <span key={i} style={{ fontSize: 12, padding: "3px 10px", borderRadius: 20, background: "rgba(255,107,53,0.08)", border: "1px solid #3a2010", color: "#ff8c35" }}>{f}</span>
                    ))}
                  </div>
                ) : <p style={{ fontSize: 12, color: "#7a8498", marginBottom: 12 }}>Fill in date, time, and addresses above to filter drivers automatically</p>;
              })()}

              <div className="resp-grid-3" style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 6 }}>
                {DRIVERS.map(driver => {
                  const pickup  = normalizeLocation(form.pickupAddress);
                  const dropoff = normalizeLocation(form.dropoffAddress);
                  const needsPickup  = ["JFK","LGA","EWR"].includes(pickup);
                  const needsDropoff = ["JFK","LGA","EWR"].includes(dropoff);

                  // Reason for each grey-out (evaluated independently)
                  const shift       = form.date ? getDriverShift(driver, form.date) : { available: true };
                  const offDate     = !shift.available;
                  const offTime     = !offDate && form.timeSlot
                                        ? (driverTimeMatch[driver.id] && !driverTimeMatch[driver.id].available)
                                        : false;
                  const noAirportPU = needsPickup  && !driver.airportPickup;
                  const noAirportDO = needsDropoff && !driver.airportDropoff;

                  const alreadyBooked = bookedDrivers.has(driver.id);
      const isUnavailable = offDate || offTime || noAirportPU || noAirportDO || alreadyBooked;
                  const isSelected    = form.driverNumber === driver.id;

                  // Reason label shown inside the button
                  const fmt12 = (t) => {
                    if (!t) return "";
                    let [h, m] = t.split(":").map(Number);
                    const p = h >= 12 ? "PM" : "AM";
                    if (h === 0) h = 12; else if (h > 12) h -= 12;
                    return `${h}${m ? ":"+String(m).padStart(2,"0") : ""}${p}`;
                  };
                  const reasonLabel = offDate     ? "Off today"
                    : noAirportPU && noAirportDO  ? "No airport"
                    : noAirportPU                 ? `No PU at ${pickup}`
                    : noAirportDO                 ? `No DO at ${dropoff}`
                    : offTime                     ? "Off shift"
                    : shift.start                 ? `${fmt12(shift.start)}–${fmt12(shift.end)}`
                    : "On duty";

                  // Border/bg colour by state
                  const borderColor = isSelected    ? "var(--green)"
                    : isUnavailable                 ? "var(--bg-1)"
                    : "1e2028";
                  const bgColor     = isSelected    ? "rgba(220,38,38,0.08)"
                    : isUnavailable                 ? "var(--bg-0)"
                    : "var(--bg-1)";
                  const textColor   = isSelected    ? "var(--green)"
                    : isUnavailable                 ? "var(--text-1)"
                    : "#ccc";
                  const subColor    = isSelected    ? "#ff8c35"
                    : offDate || noAirportPU || noAirportDO ? "rgba(220,38,38,0.2)"
                    : offTime                       ? "#5a3a1a"
                    : "#4a6a4a";

                  return (
                    <button key={driver.id}
                      onClick={() => { if (!isUnavailable) setForm(p => ({...p, driverNumber: driver.id})); }}
                      title={isUnavailable ? reasonLabel : `Driver #${driver.id} — ${reasonLabel}`}
                      style={{
                        padding: "10px 6px", borderRadius: 8, textAlign: "center",
                        border: isSelected ? `2px solid ${borderColor}` : `1px solid ${borderColor === "1e2028" ? "var(--border-0)" : borderColor}`,
                        background: bgColor, color: textColor,
                        cursor: isUnavailable ? "not-allowed" : "pointer",
                        fontFamily: "inherit", fontWeight: isSelected ? 700 : 400,
                        opacity: isUnavailable ? 0.32 : 1,
                        transition: "all 0.15s ease"
                      }}>
                      <div style={{ fontSize: 13, fontWeight: 700, letterSpacing: "0.02em" }}>
                        #{driver.id}
                      </div>
                      {driver.name && <div style={{ fontSize: 10, color: subColor, marginTop: 1, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{driver.name}</div>}
                      <div style={{ fontSize: 10, marginTop: 2, color: subColor, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
                        {reasonLabel}
                      </div>
                      {/* Airport capability badges */}
                      {!isUnavailable && (
                        <div style={{ display: "flex", justifyContent: "center", gap: 3, marginTop: 4 }}>
                          {driver.airportPickup  && <span style={{ fontSize: 9, padding: "1px 4px", borderRadius: 3, background: "rgba(76,175,106,0.08)", color: "var(--green)", border: "1px solid #1a2a4a" }}>PU</span>}
                          {driver.airportDropoff && <span style={{ fontSize: 9, padding: "1px 4px", borderRadius: 3, background: "rgba(76,175,106,0.08)", color: "var(--green)", border: "1px solid #1a2a4a" }}>DO</span>}
                        </div>
                      )}
                    </button>
                  );
                })}
              </div>

              {/* Legend */}
              <div style={{ display: "flex", flexWrap: "wrap", gap: 12, marginTop: 12 }}>
                <span style={{ fontSize: 11, color: "#7a8498" }}><span style={{ color: "#ccc" }}>■</span> Available</span>
                <span style={{ fontSize: 11, color: "#7a8498" }}><span style={{ color: "var(--text-1)" }}>■</span> Off today / shift</span>
                <span style={{ fontSize: 11, color: "#7a8498" }}><span style={{ color: "var(--green)" }}>PU</span> Airport pickup &nbsp;<span style={{ color: "var(--green)" }}>DO</span> Airport dropoff</span>
              </div>

              {/* Selected driver summary */}
              {form.driverNumber && (() => {
                const d = DRIVERS.find(x => x.id === form.driverNumber);
                const timeMismatch = form.timeSlot && driverTimeMatch[form.driverNumber] && !driverTimeMatch[form.driverNumber].available;
                const pickup  = normalizeLocation(form.pickupAddress);
                const dropoff = normalizeLocation(form.dropoffAddress);
                const airportWarning = (["JFK","LGA","EWR"].includes(pickup) && !d.airportPickup)
                                    || (["JFK","LGA","EWR"].includes(dropoff) && !d.airportDropoff);
                const hasWarning = timeMismatch || airportWarning;
                return (
                  <div style={{ marginTop: 10, padding: "10px 14px", background: hasWarning ? "rgba(220,38,38,0.06)" : "rgba(80,200,80,0.04)", border: `1px solid ${hasWarning ? "rgba(220,38,38,0.2)" : "rgba(5,150,105,0.2)"}`, borderRadius: 8 }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                      <span style={{ fontSize: 20 }}>{hasWarning ? "⚠️" : "✅"}</span>
                      <div style={{ flex: 1 }}>
                        <span style={{ fontSize: 14, fontWeight: 700, color: hasWarning ? "var(--red)" : "var(--green)" }}>Driver #{form.driverNumber}</span>
                        {d && d.notes && <span style={{ fontSize: 12, color: "var(--text-2)", marginLeft: 8 }}>{d.notes}</span>}
                        {timeMismatch && (
                          <p style={{ fontSize: 12, color: "var(--red)", marginTop: 2 }}>
                            ⏰ Unavailable at {form.timeSlot} — {driverTimeMatch[form.driverNumber].reason === "day-off" ? "off this day" : "outside shift hours"}
                          </p>
                        )}
                        {["JFK","LGA","EWR"].includes(pickup) && !d.airportPickup && (
                          <p style={{ fontSize: 12, color: "var(--red)", marginTop: 2 }}>✈ Does not do airport pickups ({pickup})</p>
                        )}
                        {["JFK","LGA","EWR"].includes(dropoff) && !d.airportDropoff && (
                          <p style={{ fontSize: 12, color: "var(--red)", marginTop: 2 }}>✈ Does not do airport dropoffs ({dropoff})</p>
                        )}
                      </div>
                      <button onClick={() => setForm(p => ({...p, driverNumber: ""}))} style={{ background: "transparent", border: "none", color: "#8892a8", fontSize: 18, cursor: "pointer", padding: "0 4px", flexShrink: 0 }}>✕</button>
                    </div>
                  </div>
                );
              })()}
            </div>

            {/* Form validation error / warning */}
            {formError && (() => {
              const isWarning = formError.startsWith("__OK__:");
              const isRequired = formError.startsWith("__FIELDS__:");
              let requiredList = [], optionalList = [];
              try {
                if (isRequired) {
                  const parts = formError.slice(11).split("|");
                  requiredList = JSON.parse(parts[0] || "[]");
                  optionalList = JSON.parse(parts[1] || "[]");
                } else if (isWarning) {
                  optionalList = JSON.parse(formError.slice(6));
                }
              } catch {}
              return (
                <div role="alert" aria-live="assertive" style={{ padding: "14px 16px", borderRadius: 12, marginBottom: 14, background: isWarning ? "rgba(217,119,6,0.05)" : "rgba(220,38,38,0.04)", border: `1px solid ${isWarning ? "rgba(217,119,6,0.2)" : "rgba(220,38,38,0.2)"}` }}>
                  <div style={{ display: "flex", alignItems: "flex-start", gap: 10, marginBottom: requiredList.length + optionalList.length > 0 ? 10 : 0 }}>
                    <span style={{ fontSize: 20, flexShrink: 0 }}>{isWarning ? "💡" : "⚠️"}</span>
                    <div style={{ flex: 1 }}>
                      <p style={{ fontSize: 15, fontWeight: 700, color: isWarning ? "var(--amber)" : "var(--red)" }}>
                        {isWarning ? "Optional fields empty — tap Confirm again to submit anyway" : `${requiredList.length} required field${requiredList.length !== 1 ? "s" : ""} missing`}
                      </p>
                      <p style={{ fontSize: 12, color: isWarning ? "var(--amber)" : "var(--red)", opacity: 0.8, marginTop: 3, fontFamily: "var(--sans)" }}>
                        {isWarning ? "선택 항목이 비어 있습니다 — 다시 확인을 눌러 제출하세요" : `필수 항목 ${requiredList.length}개가 누락되었습니다`}
                      </p>
                    </div>
                    <button onClick={() => { setFormError(""); setMissingFields([]); }} style={{ background: "transparent", border: "none", color: "var(--text-2)", fontSize: 16, cursor: "pointer", flexShrink: 0 }}>✕</button>
                  </div>
                  {requiredList.length > 0 && (
                    <div style={{ marginBottom: 8 }}>
                      <p style={{ fontSize: 12, color: "var(--red)", fontWeight: 600, marginBottom: 6 }}>Required:</p>
                      <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                        {requiredList.map(f => (
                          <span key={f} style={{ padding: "4px 10px", borderRadius: 6, background: "rgba(220,38,38,0.08)", border: "1px solid #3a1a1a", color: "var(--red)", fontSize: 13, fontWeight: 600 }}>✗ {f}</span>
                        ))}
                      </div>
                    </div>
                  )}
                  {optionalList.length > 0 && (
                    <div>
                      <p style={{ fontSize: 12, color: "var(--amber)", fontWeight: 600, marginBottom: 6 }}>{isRequired ? "Also empty (optional):" : "Empty fields:"}</p>
                      <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                        {optionalList.map(f => (
                          <span key={f} style={{ padding: "4px 10px", borderRadius: 6, background: "rgba(217,119,6,0.06)", border: "1px solid #3a3a1a", color: "var(--amber)", fontSize: 13 }}>○ {f}</span>
                        ))}
                      </div>
                    </div>
                  )}
                  {isRequired && <p style={{ fontSize: 14, color: "var(--text-2)", fontWeight: 500, marginTop: 8 }}>Fill in the red-highlighted fields above and try again. <span style={{ fontFamily: "var(--sans)", opacity: 0.8 }}>위의 빨간색 항목을 입력하고 다시 시도하세요.</span></p>}
                </div>
              );
            })()}

            <button onClick={handleSubmit} disabled={isSubmitting} className="confirm-btn" aria-label={isSubmitting ? "Saving booking" : editingBooking ? "Update booking" : "Confirm booking"} style={{ width: "100%", padding: 16, borderRadius: 12, border: "none", background: isSubmitting ? "var(--bg-2)" : "var(--amber)", color: isSubmitting ? "var(--text-3)" : "#0a0a0a", fontSize: 14, fontWeight: 700, cursor: isSubmitting ? "not-allowed" : "pointer", fontFamily: "var(--mono)", letterSpacing: "0.14em", boxShadow: isSubmitting ? "none" : "0 4px 16px rgba(240,165,0,0.25)", opacity: isSubmitting ? 0.6 : 1, transition: "all 0.2s" }}>
              {isSubmitting ? "⏳ SAVING..." : editingBooking ? "UPDATE BOOKING ✓" : "CONFIRM BOOKING ✓"}
            </button>
          </div>)}
          </div>
        </div>
        )}

        {/* ══════════════ CONFIRMATION MODAL ══════════════ */}
        {showConfirm && (
          <div role="dialog" aria-label="Booking confirmed"
            onClick={() => setShowConfirm(null)}
            style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.85)", zIndex: 200,
              display: "flex", alignItems: "center", justifyContent: "center", padding: 16,
              backdropFilter: "blur(6px)", WebkitBackdropFilter: "blur(6px)" }}>

            {/* ── Ticket card ── */}
            <div onClick={e => e.stopPropagation()} style={{
              width: "100%", maxWidth: 400, position: "relative",
              animation: "confirmSlideUp 0.35s cubic-bezier(0.34,1.56,0.64,1) forwards"
            }}>
              <style>{`
                @keyframes confirmSlideUp {
                  from { opacity:0; transform:translateY(24px) scale(0.97); }
                  to   { opacity:1; transform:translateY(0) scale(1); }
                }
                @keyframes confirmFadeRow {
                  from { opacity:0; transform:translateX(-8px); }
                  to   { opacity:1; transform:translateX(0); }
                }
                .confirm-row { animation: confirmFadeRow 0.3s ease forwards; opacity:0; }
              `}</style>

              {/* ── Header stub (top of ticket) ── */}
              <div style={{
                background: "linear-gradient(135deg, #1a1008 0%, #2a1d0a 50%, #1a1008 100%)",
                border: "1px solid #a07830",
                borderBottom: "none",
                borderRadius: "18px 18px 0 0",
                padding: "22px 24px 20px",
                position: "relative",
                overflow: "hidden"
              }}>
                {/* Gold shimmer overlay */}
                <div style={{ position:"absolute", inset:0, background:"linear-gradient(105deg, transparent 30%, rgba(200,160,60,0.06) 50%, transparent 70%)", pointerEvents:"none" }} />

                <div style={{ display:"flex", alignItems:"flex-start", justifyContent:"space-between" }}>
                  <div>
                    <p style={{ fontSize:10, fontWeight:700, color:"#a07830", letterSpacing:"0.2em", margin:"0 0 4px", textTransform:"uppercase" }}>Dispatch HQ · NYC</p>
                    <p style={{ fontSize:26, fontWeight:800, color:"#f0c060", margin:"0 0 2px", fontFamily:"Georgia, 'Times New Roman', serif", letterSpacing:"-0.02em" }}>
                      Confirmed
                    </p>
                    <p style={{ fontSize:12, color:"#7a5a20", margin:0 }}>예약이 완료되었습니다</p>
                  </div>
                  {/* Reference number */}
                  <div style={{ textAlign:"right" }}>
                    <p style={{ fontSize:10, color:"#7a5a20", margin:"0 0 2px", letterSpacing:"0.15em" }}>REF</p>
                    <p style={{ fontSize:20, fontWeight:800, color:"#f0c060", margin:0, fontFamily:"'Courier New', monospace", letterSpacing:"0.08em" }}>
                      #{showConfirm.id ? showConfirm.id.slice(-6).toUpperCase() : "------"}
                    </p>
                  </div>
                </div>

                {/* Driver badge */}
                <div style={{ display:"inline-flex", alignItems:"center", gap:8, marginTop:14,
                  background:"rgba(240,192,96,0.1)", border:"1px solid rgba(160,120,48,0.4)",
                  borderRadius:8, padding:"6px 12px" }}>
                  <span style={{ fontSize:16 }}>🚖</span>
                  <span style={{ fontSize:13, fontWeight:700, color:"#f0c060" }}>
                    Driver #{showConfirm.driverNumber || "—"}
                  </span>
                </div>
              </div>

              {/* ── Perforated edge ── */}
              <div style={{ position:"relative", height:16, overflow:"hidden",
                background:"linear-gradient(135deg, #1a1008, #2a1d0a)",
                borderLeft:"1px solid #a07830", borderRight:"1px solid #a07830" }}>
                {/* Left notch */}
                <div style={{ position:"absolute", left:-10, top:"50%", transform:"translateY(-50%)",
                  width:20, height:20, borderRadius:"50%", background:"rgba(0,0,0,0.85)" }} />
                {/* Dotted perforation */}
                <div style={{ position:"absolute", left:16, right:16, top:"50%", transform:"translateY(-50%)",
                  borderTop:"2px dashed rgba(160,120,48,0.3)" }} />
                {/* Right notch */}
                <div style={{ position:"absolute", right:-10, top:"50%", transform:"translateY(-50%)",
                  width:20, height:20, borderRadius:"50%", background:"rgba(0,0,0,0.85)" }} />
              </div>

              {/* ── Body (booking details) ── */}
              <div style={{
                background: "var(--border-0)",
                border: "1px solid #a07830",
                borderTop: "none",
                borderRadius: "0 0 18px 18px",
                padding: "20px 24px 24px"
              }}>
                {/* Key trip info — large */}
                <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:12, marginBottom:18 }}>
                  {[
                    ["📅", "Date", showConfirm.date ? new Date(showConfirm.date+"T12:00:00").toLocaleDateString("en-US",{weekday:"short",month:"short",day:"numeric"}) : "—"],
                    ["⏰", "Time", showConfirm.timeSlot || "—"],
                    ["👤", "Customer", showConfirm.customerName || "—"],
                    ["📞", "Phone", showConfirm.phone || "—"],
                  ].map(([icon, label, val], i) => (
                    <div key={label} className="confirm-row" style={{ animationDelay: `${0.05 + i*0.06}s` }}>
                      <p style={{ fontSize:10, color:"#7a5a20", margin:"0 0 2px", letterSpacing:"0.12em", textTransform:"uppercase" }}>{icon} {label}</p>
                      <p style={{ fontSize:14, fontWeight:600, color:"#e8d4a0", margin:0, overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>{val}</p>
                    </div>
                  ))}
                </div>

                {/* Route */}
                <div className="confirm-row" style={{ animationDelay:"0.3s", background:"rgba(240,192,96,0.04)", border:"1px solid rgba(160,120,48,0.2)", borderRadius:10, padding:"12px 14px", marginBottom:14 }}>
                  <div style={{ display:"flex", alignItems:"flex-start", gap:10 }}>
                    <div style={{ display:"flex", flexDirection:"column", alignItems:"center", gap:4, paddingTop:2 }}>
                      <div style={{ width:8, height:8, borderRadius:"50%", background:"#f0c060", border:"2px solid #a07830" }} />
                      <div style={{ width:1, height:20, background:"rgba(160,120,48,0.4)" }} />
                      <div style={{ width:8, height:8, borderRadius:2, background:"#f0c060" }} />
                    </div>
                    <div style={{ flex:1, overflow:"hidden" }}>
                      <p style={{ fontSize:11, color:"#7a5a20", margin:"0 0 4px", letterSpacing:"0.1em" }}>PICKUP</p>
                      <p style={{ fontSize:13, color:"#e8d4a0", margin:"0 0 10px", overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>{showConfirm.pickupAddress || "—"}</p>
                      <p style={{ fontSize:11, color:"#7a5a20", margin:"0 0 4px", letterSpacing:"0.1em" }}>DROPOFF</p>
                      <p style={{ fontSize:13, color:"#e8d4a0", margin:0, overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>{showConfirm.dropoffAddress || "—"}</p>
                    </div>
                  </div>
                </div>

                {/* Flight info (only if airport trip) */}
                {showConfirm.airline && (
                  <div className="confirm-row" style={{ animationDelay:"0.38s", display:"flex", gap:8, marginBottom:14 }}>
                    <div style={{ flex:1, background:"rgba(59,158,255,0.06)", border:"1px solid rgba(59,158,255,0.2)", borderRadius:8, padding:"8px 12px" }}>
                      <p style={{ fontSize:10, color:"#3b6aaa", margin:"0 0 2px", letterSpacing:"0.12em" }}>✈️ AIRLINE</p>
                      <p style={{ fontSize:13, fontWeight:600, color:"var(--green)", margin:0 }}>{showConfirm.airline}</p>
                    </div>
                    <div style={{ flex:1, background:"rgba(59,158,255,0.06)", border:"1px solid rgba(59,158,255,0.2)", borderRadius:8, padding:"8px 12px" }}>
                      <p style={{ fontSize:10, color:"#3b6aaa", margin:"0 0 2px", letterSpacing:"0.12em" }}>FLIGHT</p>
                      <p style={{ fontSize:13, fontWeight:600, color:"var(--green)", margin:0, fontFamily:"monospace" }}>{showConfirm.flightNumber}</p>
                    </div>
                    {showConfirm.flightStatus && (
                      <div style={{ flex:1, background:"rgba(5,150,105,0.05)", border:"1px solid rgba(80,200,80,0.2)", borderRadius:8, padding:"8px 12px" }}>
                        <p style={{ fontSize:10, color:"#3a8a3a", margin:"0 0 2px", letterSpacing:"0.12em" }}>STATUS</p>
                        <p style={{ fontSize:12, fontWeight:700, color: showConfirm.flightStatus==="delayed"?"var(--amber)":showConfirm.flightStatus==="cancelled"?"var(--red)":"var(--green)", margin:0, textTransform:"uppercase" }}>{showConfirm.flightStatus}</p>
                      </div>
                    )}
                  </div>
                )}

                {/* Payment — large gold amount */}
                <div className="confirm-row" style={{ animationDelay:"0.44s", display:"flex", alignItems:"center", justifyContent:"space-between",
                  background:"linear-gradient(135deg, rgba(240,192,96,0.08), rgba(160,120,48,0.04))",
                  border:"1px solid rgba(160,120,48,0.3)", borderRadius:10, padding:"12px 16px", marginBottom:18 }}>
                  <div>
                    <p style={{ fontSize:10, color:"#7a5a20", margin:"0 0 2px", letterSpacing:"0.15em" }}>FARE · {showConfirm.tripType==="round-trip"?"ROUND TRIP":"ONE WAY"}</p>
                    {showConfirm.fareRoute && <p style={{ fontSize:11, color:"#9a8040", margin:"2px 0 0" }}>{showConfirm.fareRoute}</p>}
                  </div>
                  <p style={{ fontSize:30, fontWeight:800, color:"#f0c060", margin:0, fontFamily:"Georgia, serif", letterSpacing:"-0.02em" }}>
                    ${showConfirm.paymentAmount || "—"}
                  </p>
                </div>

                {/* Actions */}
                <div className="confirm-row" style={{ animationDelay:"0.5s", display:"flex", gap:8 }}>
                  <button onClick={() => setShowConfirm(null)}
                    style={{ flex:1, padding:"11px 0", borderRadius:10, border:"1px solid rgba(160,120,48,0.3)",
                      background:"transparent", color:"#7a5a20", fontSize:14, fontWeight:600,
                      cursor:"pointer", fontFamily:"inherit", transition:"all 0.2s" }}>
                    Close
                  </button>
                  <button onClick={() => { setShowConfirm(null); setView("dashboard"); }}
                    style={{ flex:2, padding:"11px 0", borderRadius:10, border:"none",
                      background:"linear-gradient(135deg, #c08020, #e0a030)",
                      color:"var(--border-0)", fontSize:14, fontWeight:800,
                      cursor:"pointer", fontFamily:"inherit", letterSpacing:"0.04em",
                      boxShadow:"0 4px 20px rgba(200,150,30,0.3)", transition:"all 0.2s" }}>
                    View Dashboard →
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* ══════════════ DELETE CONFIRMATION MODAL ══════════════ */}
        {deleteConfirmId && (
          <div role="alertdialog" aria-label="Delete booking confirmation" style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.6)", zIndex: 200, display: "flex", alignItems: "center", justifyContent: "center", padding: 16 }} onClick={() => setDeleteConfirmId(null)}>
            <div className="card-enter" onClick={e => e.stopPropagation()} style={{ background: "var(--bg-2)", border: "1px solid #3a1a1a", borderRadius: 14, padding: 24, maxWidth: 340, width: "100%", textAlign: "center" }}>
              <div style={{ fontSize: 32, marginBottom: 12 }}>🗑️</div>
              <p style={{ fontSize: 16, fontWeight: 700, color: "#fff", marginBottom: 6 }}>Delete Booking?</p>
              <p style={{ fontSize: 14, color: "var(--text-2)", fontWeight: 500, marginBottom: 18 }}>This action cannot be undone.</p>
              <div style={{ display: "flex", gap: 8 }}>
                <button onClick={() => setDeleteConfirmId(null)} style={{ flex: 1, padding: 12, borderRadius: 8, border: "1px solid var(--border-1)", background: "transparent", color: "var(--text-2)", fontSize: 14, fontWeight: 600, cursor: "pointer", fontFamily: "inherit" }}>Cancel</button>
                <button onClick={confirmDelete} style={{ flex: 1, padding: 12, borderRadius: 8, border: "none", background: "linear-gradient(135deg, #ff3a30, #cc2020)", color: "#fff", fontSize: 14, fontWeight: 700, cursor: "pointer", fontFamily: "inherit" }}>Delete</button>
              </div>
            </div>
          </div>
        )}

        {/* ══════════════ MIC PERMISSION PROMPT ══════════════ */}
        {showMicPrompt && (
          <div style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.65)", zIndex: 300, display: "flex", alignItems: "center", justifyContent: "center", padding: 20 }} onClick={() => setShowMicPrompt(false)}>
            <div className="card-enter" onClick={e => e.stopPropagation()} style={{
              background: "linear-gradient(180deg, #1e2030 0%, #161820 100%)",
              border: "1px solid #2a2d3a", borderRadius: 18, padding: 28, maxWidth: 340, width: "100%",
              textAlign: "center", boxShadow: "0 20px 60px rgba(0,0,0,0.5)"
            }}>
              <div style={{
                width: 64, height: 64, borderRadius: 16, margin: "0 auto 16px",
                background: "linear-gradient(135deg, #ff3a30, #ff6b35)",
                display: "flex", alignItems: "center", justifyContent: "center", fontSize: 30
              }}>🎤</div>
              <h3 style={{ fontSize: 17, fontWeight: 700, color: "#fff", marginBottom: 8 }}>Allow Microphone Access?</h3>
              <p style={{ fontSize: 14, color: "#a8b0c0", lineHeight: 1.5, marginBottom: 6 }}>
                Dispatch HQ needs your microphone to transcribe booking details by voice.
              </p>
              <p style={{ fontSize: 13, color: "var(--text-2)", marginBottom: 20 }}>
                Your device will ask you to allow microphone access. Tap "Allow" when prompted.
              </p>
              <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                <button onClick={requestMicPermission} style={{
                  width: "100%", padding: 14, borderRadius: 12, border: "none",
                  background: "linear-gradient(135deg, #ff3a30, #ff6b35)",
                  color: "#fff", fontSize: 16, fontWeight: 700, cursor: "pointer",
                  fontFamily: "inherit", letterSpacing: "0.03em",
                  boxShadow: "0 4px 16px rgba(255,58,48,0.3)"
                }}>
                  Allow Microphone
                </button>
                <button onClick={() => { setShowMicPrompt(false); setVoiceError("Mic skipped. Type your booking info in the text box and tap AI Smart Fill."); }} style={{
                  width: "100%", padding: 12, borderRadius: 12,
                  border: "1px solid var(--border-1)", background: "transparent",
                  color: "var(--text-2)", fontSize: 15, fontWeight: 600, cursor: "pointer",
                  fontFamily: "inherit"
                }}>
                  Not Now \u2014 I'll Type Instead
                </button>
              </div>
            </div>
          </div>
        )}

        {/* ══════════════ DASHBOARD ══════════════ */}
        {view === "dashboard" && (
          <div className="card-enter">
            <h2 style={{ fontSize: 20, fontWeight: 700, color: "#fff", marginBottom: 16 }}>📊 Bookings Dashboard</h2>

            {/* Revenue & Stats */}
            {(() => {
              const now = new Date();
              const weekStart = new Date(now); weekStart.setDate(now.getDate() - now.getDay()); weekStart.setHours(0,0,0,0);
              const monthStart = new Date(now.getFullYear(), now.getMonth(), 1);
              const active = bookings.filter(b => !b.deleted);
              const fares = active.map(b => parseFloat(b.paymentAmount)||0);
              const weekFares = active.filter(b => new Date(b.date+"T12:00:00") >= weekStart).map(b => parseFloat(b.paymentAmount)||0);
              const monthFares = active.filter(b => new Date(b.date+"T12:00:00") >= monthStart).map(b => parseFloat(b.paymentAmount)||0);
              const totalFare = fares.reduce((a,v)=>a+v,0);
              const weekTotal = weekFares.reduce((a,v)=>a+v,0);
              const monthTotal = monthFares.reduce((a,v)=>a+v,0);
              const avgFare = fares.length ? (totalFare/fares.length).toFixed(0) : 0;
              const airportCount = active.filter(b => b.fareRoute && b.fareRoute.includes("→")).length;
              const driverCounts = {};
              active.forEach(b => { if (b.driverNumber) driverCounts[b.driverNumber] = (driverCounts[b.driverNumber]||0)+1; });
              const topDriver = Object.entries(driverCounts).sort((a,b)=>b[1]-a[1])[0];
              const SC = {background:"var(--bg-1)",border:"1px solid #1e2028",borderRadius:10,padding:"12px 14px"};
              return (
                <div style={{ marginBottom: 18 }}>
                  <p style={{ fontSize: 12, fontWeight: 700, color: "#7a8498", letterSpacing: "0.1em", marginBottom: 10 }}>STATS</p>
                  <div className="resp-grid-3" style={{ display:"grid",gridTemplateColumns:"repeat(3,1fr)",gap:8,marginBottom:8 }}>
                    <div style={SC}><div style={{fontSize:18,marginBottom:4}}>📋</div><div style={{fontSize:20,fontWeight:800,color:"#fff"}}>{active.length}</div><div style={{fontSize:11,color:"#7a8498"}}>Total Trips</div><div style={{fontSize:12,color:"var(--text-2)",marginTop:4}}>Avg ${avgFare}</div></div>
                    <div style={SC}><div style={{fontSize:18,marginBottom:4}}>💰</div><div style={{fontSize:20,fontWeight:800,color:"var(--green)"}}>${weekTotal.toLocaleString()}</div><div style={{fontSize:11,color:"#7a8498"}}>This Week</div><div style={{fontSize:12,color:"var(--text-2)",marginTop:4}}>{weekFares.length} trips</div></div>
                    <div style={SC}><div style={{fontSize:18,marginBottom:4}}>📅</div><div style={{fontSize:20,fontWeight:800,color:"var(--green)"}}>${monthTotal.toLocaleString()}</div><div style={{fontSize:11,color:"#7a8498"}}>This Month</div><div style={{fontSize:12,color:"var(--text-2)",marginTop:4}}>{monthFares.length} trips</div></div>
                  </div>
                  <div className="resp-grid-3" style={{ display:"grid",gridTemplateColumns:"repeat(3,1fr)",gap:8,marginBottom:16 }}>
                    <div style={SC}><div style={{fontSize:18,marginBottom:4}}>✈️</div><div style={{fontSize:20,fontWeight:800,color:"var(--amber)"}}>{airportCount}</div><div style={{fontSize:11,color:"#7a8498"}}>Airport Trips</div><div style={{fontSize:12,color:"var(--text-2)",marginTop:4}}>{active.length?Math.round(airportCount/active.length*100):0}% of total</div></div>
                    <div style={SC}><div style={{fontSize:18,marginBottom:4}}>🚗</div><div style={{fontSize:20,fontWeight:800,color:"var(--green)"}}>{topDriver?`#${topDriver[0]}`:"—"}</div><div style={{fontSize:11,color:"#7a8498"}}>Top Driver</div><div style={{fontSize:12,color:"var(--text-2)",marginTop:4}}>{topDriver?`${topDriver[1]} trips`:"No trips"}</div></div>
                    <div style={SC}><div style={{fontSize:18,marginBottom:4}}>💵</div><div style={{fontSize:20,fontWeight:800,color:"var(--red)"}}>${totalFare.toLocaleString()}</div><div style={{fontSize:11,color:"#7a8498"}}>All-Time Revenue</div><div style={{fontSize:12,color:"var(--text-2)",marginTop:4}}>{fares.length} paid trips</div></div>
                  </div>
                </div>
              );
            })()}

            {/* Driver Performance */}
            {bookings.filter(b=>!b.deleted&&b.driverNumber).length > 0 && (() => {
              const driverStats = {};
              bookings.filter(b=>!b.deleted&&b.driverNumber).forEach(b => {
                if (!driverStats[b.driverNumber]) driverStats[b.driverNumber] = { trips:0, revenue:0, airport:0 };
                driverStats[b.driverNumber].trips++;
                driverStats[b.driverNumber].revenue += parseFloat(b.paymentAmount)||0;
                const pu = (b.pickupAddress||"").toUpperCase(); const do_ = (b.dropoffAddress||"").toUpperCase();
                if (/JFK|LGA|EWR/.test(pu+do_)) driverStats[b.driverNumber].airport++;
              });
              const sorted = Object.entries(driverStats).sort((a,b)=>b[1].trips-a[1].trips);
              return (
                <div style={{ marginBottom: 18 }}>
                  <p style={{ fontSize: 12, fontWeight: 700, color: "#7a8498", letterSpacing: "0.1em", marginBottom: 10 }}>DRIVER PERFORMANCE</p>
                  <div style={{ background: "var(--bg-1)", border: "1px solid #1e2028", borderRadius: 10, overflow: "hidden" }}>
                    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr 1fr", padding: "6px 14px", borderBottom: "1px solid #12141a" }}>
                      {["Driver","Trips","Revenue","Airport"].map(h => <span key={h} style={{ fontSize: 13, fontWeight: 700, color: "#7a8498", letterSpacing: "0.08em" }}>{h}</span>)}
                    </div>
                    {sorted.map(([id, s]) => (
                      <div key={id} style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr 1fr", padding: "8px 14px", borderBottom: "1px solid #0a0b0f", alignItems: "center" }}>
                        <span style={{ fontSize: 14, fontWeight: 700, color: "var(--green)" }}>#{id}</span>
                        <span style={{ fontSize: 14, color: "var(--text-1)" }}>{s.trips}</span>
                        <span style={{ fontSize: 14, color: "var(--green)" }}>${s.revenue.toLocaleString()}</span>
                        <span style={{ fontSize: 13, color: "var(--amber)" }}>{s.airport} ✈</span>
                      </div>
                    ))}
                  </div>
                </div>
              );
            })()}

            {/* Search */}
            <input aria-label="Search bookings by name, phone, driver, airline, flight, or date" placeholder="🔍 Search name, phone, driver, airline, flight, date..." value={searchQuery} onChange={e => handleSearchChange(e.target.value)} style={{...inputStyle, marginBottom: 12}} />

            {/* Filters */}
            <div style={{ background: "var(--bg-1)", border: "1px solid #1e2028", borderRadius: 12, padding: 14, marginBottom: 18 }}>
              <p style={{ fontSize: 13, fontWeight: 700, color: "var(--text-2)", letterSpacing: "0.1em", marginBottom: 10 }}>FILTERS</p>
              <div className="resp-grid-3" style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 8 }}>
                <div>
                  <label style={{...labelStyle, fontSize: 12}}>From</label>
                  <input type="date" value={filters.dateFrom} onChange={e => setFilters(p=>({...p,dateFrom:e.target.value}))} style={{...inputStyle, fontSize: 13, padding: 8}} />
                </div>
                <div>
                  <label style={{...labelStyle, fontSize: 12}}>To</label>
                  <input type="date" value={filters.dateTo} onChange={e => setFilters(p=>({...p,dateTo:e.target.value}))} style={{...inputStyle, fontSize: 13, padding: 8}} />
                </div>
                <div>
                  <label style={{...labelStyle, fontSize: 12}}>Driver</label>
                  <select value={filters.driverNumber} onChange={e => setFilters(p=>({...p,driverNumber:e.target.value}))} style={{...inputStyle, fontSize: 13, padding: 8}}>
                    <option value="">All</option>
                    {DRIVERS.map(d => <option key={d.id} value={d.id}>#{d.id}</option>)}
                  </select>
                </div>
                <div>
                  <label style={{...labelStyle, fontSize: 12}}>Trip</label>
                  <select value={filters.tripType} onChange={e => setFilters(p=>({...p,tripType:e.target.value}))} style={{...inputStyle, fontSize: 13, padding: 8}}>
                    <option value="">All</option>
                    <option value="one-way">One-Way</option>
                    <option value="round-trip">Round-Trip</option>
                  </select>
                </div>
                <div>
                  <label style={{...labelStyle, fontSize: 12}}>Shift</label>
                  <select value={filters.shift} onChange={e => setFilters(p=>({...p,shift:e.target.value}))} style={{...inputStyle, fontSize: 13, padding: 8}}>
                    <option value="">All</option>
                    <option value="morning">Morning (5am–4pm)</option>
                    <option value="allday">All-Day</option>
                    <option value="night">Night (5pm–12am)</option>
                  </select>
                </div>
                <div>
                  <label style={{...labelStyle, fontSize: 12}}>Day Type</label>
                  <select value={filters.dayType} onChange={e => setFilters(p=>({...p,dayType:e.target.value}))} style={{...inputStyle, fontSize: 13, padding: 8}}>
                    <option value="">All</option>
                    <option value="weekday">Weekday</option>
                    <option value="weekend">Weekend</option>
                  </select>
                </div>
              </div>
              <button onClick={() => setFilters({ dateFrom: "", dateTo: "", driverNumber: "", tripType: "", shift: "", dayType: "" })} style={{ marginTop: 8, padding: "4px 12px", borderRadius: 6, border: "1px solid var(--border-1)", background: "transparent", color: "var(--text-2)", fontSize: 13, cursor: "pointer", fontFamily: "inherit" }}>Clear Filters</button>
            </div>

            {/* Bookings count */}
            <p style={{ fontSize: 14, color: "#a8b0c0", marginBottom: 14 }}>{filteredBookings.length} booking{filteredBookings.length !== 1 ? "s" : ""} found</p>

            {/* Weekday Section */}
            <BookingSection title="📅 Weekdays (Mon–Fri)" bookings={groupedBookings.weekday} onEdit={editBooking} onDelete={deleteBooking} />

            {/* Weekend Section */}
            <BookingSection title="🌴 Weekends (Sat–Sun)" bookings={groupedBookings.weekend} onEdit={editBooking} onDelete={deleteBooking} />

            {filteredBookings.length > dashPage && (
              <div style={{ textAlign: "center", padding: "16px 0" }}>
                <button onClick={() => setDashPage(p => p + 50)} style={{ padding: "9px 24px", borderRadius: 8, border: "1px solid var(--border-1)", background: "transparent", color: "var(--text-2)", fontSize: 14, cursor: "pointer", fontFamily: "inherit" }}>
                  Load more ({filteredBookings.length - dashPage} remaining)
                </button>
              </div>
            )}

            {filteredBookings.length === 0 && (
              <div style={{ textAlign: "center", padding: 48, color: "#909aaa" }}>
                <p style={{ fontSize: 36 }}>📭</p>
                <p style={{ fontSize: 15, marginTop: 8 }}>No bookings found</p>
              </div>
            )}
          </div>
        )}

        {/* ══════════════ DRIVERS ══════════════ */}
        {view === "drivers" && (
          <div className="card-enter">
            <h2 style={{ fontSize: 20, fontWeight: 700, color: "var(--text-1)", marginBottom: 16 }}>Driver Database</h2>

            {/* Driver Management — Add Custom Drivers */}
            {(() => {
              const saveCustom = (arr) => { setCustomDrivers(arr); try { localStorage.setItem("dispatch-hq-custom-drivers", JSON.stringify(arr)); } catch {} };
              const addDriver = () => {
                setDFormErr("");
                const id = String(parseInt(dForm.id)||0).padStart(3,"0");
                if (id === "000") { setDFormErr("Enter a valid driver number"); return; }
                if ([...DRIVERS,...customDrivers].some(d=>d.id===id)) { setDFormErr("Driver #"+id+" already exists"); return; }
                const d = { id, shiftStart:dForm.shiftStart, shiftEnd:dForm.shiftEnd,
                  daysOff:dForm.daysOff.split(",").map(s=>s.trim()).filter(Boolean),
                  monthlyOff:dForm.monthlyOff.split(",").map(s=>parseInt(s)).filter(n=>n>0&&n<=31),
                  specialShifts:[], airportPickup:dForm.airportPickup, airportDropoff:dForm.airportDropoff, notes:dForm.notes.trim(), custom:true };
                saveCustom([...customDrivers, d]);
                setShowAddDriver(false);
                setDForm({ id:"", shiftStart:"06:00", shiftEnd:"18:00", daysOff:"", monthlyOff:"", airportPickup:false, airportDropoff:false, notes:"" });
              };
              return (
                <div style={{ marginBottom: 16 }}>
                  <div style={{ display:"flex", alignItems:"center", justifyContent:"space-between", marginBottom: 12 }}>
                    <p style={{ fontSize:13, color:"var(--text-2)" }}>{DRIVERS.length + customDrivers.length} registered drivers</p>
                    <button onClick={()=>setShowAddDriver(v=>!v)} style={{ padding:"7px 14px", borderRadius:8, border:"1px solid #ff3a30", background:showAddDriver?"rgba(76,175,106,0.08)":"transparent", color:"var(--green)", fontSize:13, fontWeight:700, cursor:"pointer", fontFamily:"inherit" }}>{showAddDriver?"✕ Cancel":"+ Add Driver"}</button>
                  </div>
                  {showAddDriver && (
                    <div style={{ background:"var(--bg-1)", border:"1px solid var(--border-1)", borderRadius:12, padding:16, marginBottom:14 }}>
                      <p style={{ fontSize:14, fontWeight:700, color:"var(--green)", marginBottom:12 }}>New Driver</p>
                      {dFormErr && <p style={{ color:"var(--red)", fontSize:13, marginBottom:8 }}>{dFormErr}</p>}
                      <div className="resp-grid-2" style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:8, marginBottom:10 }}>
                        <div><label style={labelStyle}>Driver #</label><input type="number" min="1" max="99" value={dForm.id} onChange={e=>setDForm(p=>({...p,id:e.target.value}))} style={inputStyle} placeholder="e.g. 25" /></div>
                        <div><label style={labelStyle}>Notes</label><input type="text" value={dForm.notes} onChange={e=>setDForm(p=>({...p,notes:e.target.value}))} style={inputStyle} placeholder="Full time, PM shift..." /></div>
                        <div><label style={labelStyle}>Shift Start</label><input type="time" value={dForm.shiftStart} onChange={e=>setDForm(p=>({...p,shiftStart:e.target.value}))} style={inputStyle} /></div>
                        <div><label style={labelStyle}>Shift End</label><input type="time" value={dForm.shiftEnd} onChange={e=>setDForm(p=>({...p,shiftEnd:e.target.value}))} style={inputStyle} /></div>
                        <div><label style={labelStyle}>Days Off (comma-separated)</label><input type="text" value={dForm.daysOff} onChange={e=>setDForm(p=>({...p,daysOff:e.target.value}))} style={inputStyle} placeholder="Sunday, Thursday" /></div>
                        <div><label style={labelStyle}>Monthly Off Dates</label><input type="text" value={dForm.monthlyOff} onChange={e=>setDForm(p=>({...p,monthlyOff:e.target.value}))} style={inputStyle} placeholder="9, 19, 29" /></div>
                      </div>
                      <div style={{ display:"flex", gap:20, marginBottom:12 }}>
                        <label style={{ display:"flex", alignItems:"center", gap:8, fontSize:13, color:"var(--text-2)", cursor:"pointer" }}><input type="checkbox" checked={dForm.airportPickup} onChange={e=>setDForm(p=>({...p,airportPickup:e.target.checked}))} /> Airport Pickup</label>
                        <label style={{ display:"flex", alignItems:"center", gap:8, fontSize:13, color:"var(--text-2)", cursor:"pointer" }}><input type="checkbox" checked={dForm.airportDropoff} onChange={e=>setDForm(p=>({...p,airportDropoff:e.target.checked}))} /> Airport Dropoff</label>
                      </div>
                      <button onClick={addDriver} style={{ padding:"9px 20px", borderRadius:8, border:"none", background:"linear-gradient(135deg,#1a5a2a,#1a7a3a)", color:"#fff", fontSize:14, fontWeight:700, cursor:"pointer", fontFamily:"inherit" }}>Save Driver</button>
                    </div>
                  )}
                  {customDrivers.length > 0 && (
                    <div style={{ padding:"8px 12px", background:"rgba(255,200,50,0.04)", border:"1px solid #2a2010", borderRadius:8, marginBottom:12, fontSize:12, color:"#886a30", display:"flex", alignItems:"center", justifyContent:"space-between" }}>
                      <span>⚠️ {customDrivers.length} custom driver(s) — stored locally. Add to DRIVERS array in source to make permanent.</span>
                      <button onClick={()=>saveCustom([])} style={{ background:"transparent", border:"none", color:"var(--red)", fontSize:12, cursor:"pointer", fontFamily:"inherit", marginLeft:12 }}>Remove all</button>
                    </div>
                  )}
                </div>
              );
            })()}

            <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
              {DRIVERS.map(d => {
                const shift = getShiftLabel(d);
                return (
                  <div key={d.id} style={{ background: "var(--bg-1)", border: "1px solid #1e2028", borderRadius: 12, padding: 14 }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 6 }}>
                      <span style={{ fontSize: 20, fontWeight: 800, color: "var(--green)", fontFamily: "inherit" }}>#{d.id}</span>
                      {d.name && <span style={{ fontSize: 14, fontWeight: 700, color: "#fff" }}>{d.name}</span>}
                      <Badge label={shift} ok={true} neutral />
                      {d.airportPickup && <Badge label="✈ PU" ok={true} />}
                      {d.airportDropoff && <Badge label="✈ DO" ok={true} />}
                      {!d.airportPickup && !d.airportDropoff && <Badge label="No Airport" ok={false} />}
                    </div>
                    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 4, fontSize: 13 }}>
                      {d.carType && <span style={{ color: "var(--text-2)" }}>🚗 {d.carType}</span>}
                      {d.phone && <span style={{ color: "var(--text-2)" }}>📞 {d.phone}</span>}
                      <span style={{ color: "var(--text-2)" }}>Shift: <span style={{ color: "var(--text-2)" }}>{formatShiftDisplay(d.shiftStart, d.shiftEnd)}</span></span>
                      <span style={{ color: "var(--text-2)" }}>Days Off: <span style={{ color: d.daysOff.length ? "var(--red)" : "var(--green)" }}>{d.daysOff.length ? d.daysOff.join(", ") : "None"}</span></span>
                    </div>
                    {d.monthlyOff && <p style={{ fontSize: 14, color: "var(--text-2)", fontWeight: 500, marginTop: 4 }}>Monthly off: {d.monthlyOff.join(", ")}th</p>}
                    {d.specialShifts && <p style={{ fontSize: 13, color: "#ca8", marginTop: 4 }}>Special: {d.specialShifts.map(s => `${s.day} ${formatShiftDisplay(s.start, s.end)}`).join(", ")}</p>}
                    {d.notes && <p style={{ fontSize: 13, color: "#f96", marginTop: 4 }}>📌 {d.notes}</p>}
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* ══════════════ SYNC SETTINGS ══════════════ */}
        {view === "sync" && (
          <div className="card-enter">
            <h2 style={{ fontSize: 20, fontWeight: 700, color: "#fff", marginBottom: 6 }}>🔐 Cloud Backup</h2>
            <p style={{ fontSize: 14, color: "var(--text-2)", fontWeight: 500, marginBottom: 8 }}>
              Back up bookings to Google Sheets so they're safe and accessible from any device.
            </p>
            <p style={{ fontSize: 13, color: "#a8b0c0", marginBottom: 20 }}>
              All data is encrypted before leaving your device — only you can read it with your passphrase.
            </p>

            {/* Status Banner */}
            {syncMessage && (
              <div style={{
                padding: "10px 14px", borderRadius: 10, marginBottom: 16,
                background: syncStatus === "success" ? "rgba(80,200,80,0.08)" : syncStatus === "error" ? "rgba(220,38,38,0.06)" : "rgba(217,119,6,0.06)",
                border: `1px solid ${syncStatus === "success" ? "rgba(5,150,105,0.2)" : syncStatus === "error" ? "rgba(220,38,38,0.2)" : "rgba(217,119,6,0.2)"}`,
                display: "flex", alignItems: "center", gap: 10
              }}>
                <span style={{ fontSize: 16 }}>{syncStatus === "success" ? "✅" : syncStatus === "error" ? "❌" : "⏳"}</span>
                <span style={{ fontSize: 14, color: syncStatus === "success" ? "var(--green)" : syncStatus === "error" ? "var(--red)" : "var(--amber)" }}>{syncMessage}</span>
              </div>
            )}

            {/* Maps API Key */}
            <div style={{ background: "var(--bg-1)", border: "1px solid #1e2028", borderRadius: 14, padding: 18, marginBottom: 14 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 10 }}>
                <p style={{ fontSize: 14, fontWeight: 700, color: "var(--green)", letterSpacing: "0.1em" }}>📍 GOOGLE MAPS AUTOCOMPLETE</p>
                {mapsReady && <span style={{ fontSize: 12, padding: "2px 8px", borderRadius: 10, background: "rgba(5,150,105,0.08)", color: "var(--green)", border: "1px solid #1a3a1a" }}>Active</span>}
              </div>
              <p style={{ fontSize: 12, color: "var(--text-2)", marginBottom: 10, lineHeight: 1.5 }}>
                Optional. Adds smart address suggestions to the Pickup and Dropoff fields as you type. 
                Requires a Google Maps Platform API key with the <strong style={{ color: "#ccc" }}>Places API</strong> enabled.
              </p>
              <label style={labelStyle}>API Key</label>
              <div style={{ display: "flex", gap: 8 }}>
                <input
                  type="password"
                  value={mapsApiKey}
                  onChange={e => setMapsApiKey(e.target.value)}
                  placeholder="AIzaSy..."
                  style={{ ...inputStyle, flex: 1 }}
                />
                <button onClick={() => {
                  const key = mapsApiKey.trim();
                  if (!key) { saveMapsKey(""); setMapsReady(false); return; }
                  saveMapsKey(key);
                  mapsLoadState = "idle"; // reset so it reloads with new key
                  ensureMapsLoaded(key, ok => {
                    setMapsReady(ok);
                    if (!ok) { setAdminSyncMsg("❌ Could not load Google Maps. Check your API key and make sure the Places API is enabled in Google Cloud Console."); setAdminSyncStatus("error"); }
                  });
                }} style={{ padding: "0 16px", borderRadius: 8, border: "none", background: "var(--border-0)", color: "var(--text-2)", fontSize: 14, cursor: "pointer", fontFamily: "inherit", fontWeight: 600, whiteSpace: "nowrap" }}>
                  {mapsReady ? "Update" : "Activate"}
                </button>
              </div>
              {mapsApiKey && !mapsReady && (
                <p style={{ fontSize: 12, color: "#886a30", marginTop: 6 }}>⚠️ Key saved but Maps not loaded yet. Tap Activate.</p>
              )}
              <p style={{ fontSize: 11, color: "#7a8498", marginTop: 8 }}>
                Get a free key at console.cloud.google.com → APIs & Services → Enable "Places API" → Credentials → Create API Key.
                Free tier: 28,500 requests/month.
              </p>
            </div>

            {/* Connection Setup */}
            <div style={{ background: "var(--bg-1)", border: "1px solid #1e2028", borderRadius: 14, padding: 18, marginBottom: 14 }}>
              {/* Auto-sync toggle */}
              <div style={{ background: "var(--bg-1)", border: "1px solid #1e2028", borderRadius: 10, padding: "12px 14px", marginBottom: 14, display: "flex", alignItems: "center", gap: 12, flexWrap: "wrap" }}>
                <div style={{ flex: 1 }}>
                  <p style={{ fontSize: 14, fontWeight: 700, color: "var(--text-1)", margin: "0 0 2px" }}>⚡ Auto-Sync</p>
                  <p style={{ fontSize: 12, color: "#8892a8", margin: 0 }}>Automatically push bookings every {autoSyncInterval} minutes{!passphrase ? " (unlock first)" : ""}</p>
                </div>
                <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <select value={autoSyncInterval} onChange={e => { const v = parseInt(e.target.value); setAutoSyncInterval(v); try { localStorage.setItem("dispatch-hq-autosync-interval", String(v)); } catch {} }} disabled={!passphrase} style={{ ...inputStyle, width: 100, padding: "6px 10px", fontSize: 13, opacity: passphrase ? 1 : 0.4 }}>
                    {[5,10,15,30,60].map(m => <option key={m} value={m}>{m} min</option>)}
                  </select>
                  <button onClick={() => { const next = !autoSyncEnabled; setAutoSyncEnabled(next); try { localStorage.setItem("dispatch-hq-autosync", String(next)); } catch {}; }} disabled={!passphrase} style={{ padding: "7px 14px", borderRadius: 8, border: "none", background: autoSyncEnabled ? "linear-gradient(135deg,#1a5a2a,#1a7a3a)" : "var(--border-0)", color: autoSyncEnabled ? "#fff" : "#8892a8", fontSize: 13, fontWeight: 700, cursor: passphrase ? "pointer" : "not-allowed", fontFamily: "inherit", opacity: passphrase ? 1 : 0.4 }}>{autoSyncEnabled ? "ON" : "OFF"}</button>
                </div>
              </div>

              <p style={{ fontSize: 14, fontWeight: 700, color: "var(--green)", marginBottom: 14, letterSpacing: "0.1em" }}>1. GOOGLE SHEETS ENDPOINT</p>
              <label style={labelStyle}>Web App URL</label>
              <p style={{ fontSize: 12, color: "var(--text-2)", marginBottom: 6 }}>Paste the Google Apps Script URL from your setup. See the Setup Guide for step-by-step instructions.</p>
              <input
                type="url" placeholder="https://script.google.com/macros/s/.../exec"
                value={syncEndpointInput}
                onChange={e => setSyncEndpointInput(e.target.value.slice(0, 300))}
                style={{...inputStyle, marginBottom: 10, fontSize: 14}}
              />
              <button onClick={testConnection} disabled={syncStatus === "syncing"} style={{
                padding: "8px 16px", borderRadius: 8, border: "1px solid var(--border-1)", background: "var(--bg-2)",
                color: "var(--text-2)", fontSize: 14, fontWeight: 600, cursor: "pointer", fontFamily: "inherit"
              }}>
                {syncStatus === "syncing" ? "⏳ Testing..." : "🔌 Test Connection"}
              </button>
            </div>

            {/* Encryption Setup */}
            <div style={{ background: "var(--bg-1)", border: "1px solid #1e2028", borderRadius: 14, padding: 18, marginBottom: 14 }}>
              <p style={{ fontSize: 14, fontWeight: 700, color: "var(--green)", marginBottom: 14, letterSpacing: "0.1em" }}>2. ENCRYPTION PASSPHRASE</p>
              <p style={{ fontSize: 13, color: "#a8b0c0", marginBottom: 10 }}>
                This passphrase encrypts all customer data. If lost, your remote data cannot be recovered.
              </p>
              <label style={labelStyle}>{syncConfigured ? "Enter Passphrase to Unlock" : "Set New Passphrase (8+ chars)"}</label>
              <div style={{ display: "flex", gap: 8 }}>
                <input
                  type="password" placeholder="Enter encryption passphrase..."
                  value={passphraseInput}
                  onChange={e => setPassphraseInput(e.target.value.slice(0, 128))}
                  style={{...inputStyle, flex: 1, fontSize: 14}}
                />
                {syncConfigured ? (
                  <button onClick={unlockWithPassphrase} disabled={!passphraseInput} style={{
                    padding: "8px 18px", borderRadius: 8, border: "none", flexShrink: 0,
                    background: passphraseInput ? "linear-gradient(135deg, #2a6a2a, #3a8a3a)" : "var(--border-0)",
                    color: passphraseInput ? "#fff" : "var(--text-2)", fontSize: 14, fontWeight: 700, cursor: passphraseInput ? "pointer" : "default", fontFamily: "inherit"
                  }}>🔓 Unlock</button>
                ) : (
                  <button onClick={saveSyncSettings} disabled={!passphraseInput || passphraseInput.length < 8} style={{
                    padding: "8px 18px", borderRadius: 8, border: "none", flexShrink: 0,
                    background: passphraseInput.length >= 8 ? "linear-gradient(135deg, #ff3a30, #ff6b35)" : "var(--border-0)",
                    color: passphraseInput.length >= 8 ? "#fff" : "var(--text-2)", fontSize: 14, fontWeight: 700, cursor: passphraseInput.length >= 8 ? "pointer" : "default", fontFamily: "inherit"
                  }}>🔐 Save & Encrypt</button>
                )}
              </div>
              {passphrase && (
                <div style={{ marginTop: 8, display: "flex", alignItems: "center", gap: 6 }}>
                  <span style={{ width: 8, height: 8, borderRadius: "50%", background: "var(--green)", display: "inline-block" }} />
                  <span style={{ fontSize: 13, color: "var(--green)" }}>Passphrase active — encryption ready</span>
                </div>
              )}
            </div>

            {/* Sync Controls */}
            {syncConfigured && passphrase && (
              <div style={{ background: "var(--bg-1)", border: "1px solid #1e2028", borderRadius: 14, padding: 18, marginBottom: 14 }}>
                <p style={{ fontSize: 14, fontWeight: 700, color: "var(--green)", marginBottom: 14, letterSpacing: "0.1em" }}>3. SYNC CONTROLS</p>
                <div style={{ display: "flex", gap: 8, marginBottom: 12 }}>
                  <button onClick={syncNow} disabled={syncStatus === "syncing"} style={{
                    flex: 1, padding: "14px", borderRadius: 10, border: "none",
                    background: "linear-gradient(135deg, #ff3a30, #ff6b35)",
                    color: "#fff", fontSize: 15, fontWeight: 700, cursor: "pointer", fontFamily: "inherit",
                    boxShadow: "0 4px 16px rgba(255,58,48,0.3)", opacity: syncStatus === "syncing" ? 0.6 : 1
                  }}>
                    {syncStatus === "syncing" ? "⏳ Syncing..." : "⬆️ Push to Google Sheets"}
                  </button>
                  <button onClick={pullFromRemote} disabled={syncStatus === "syncing"} style={{
                    flex: 1, padding: "14px", borderRadius: 10, border: "none",
                    background: "linear-gradient(135deg, #2255aa, #3377cc)",
                    color: "#fff", fontSize: 15, fontWeight: 700, cursor: "pointer", fontFamily: "inherit",
                    boxShadow: "0 4px 16px rgba(34,85,170,0.3)", opacity: syncStatus === "syncing" ? 0.6 : 1
                  }}>
                    {syncStatus === "syncing" ? "⏳ Pulling..." : "⬇️ Pull from Google Sheets"}
                  </button>
                </div>
                {syncConfig.lastSync && (
                  <p style={{ fontSize: 13, color: "#a8b0c0", textAlign: "center" }}>
                    Last synced: {new Date(syncConfig.lastSync).toLocaleString()}
                  </p>
                )}
              </div>
            )}

            {/* Encryption Info Panel */}
            <div style={{ background: "var(--bg-1)", border: "1px solid #1e2028", borderRadius: 14, padding: 18 }}>
              <p style={{ fontSize: 14, fontWeight: 700, color: "#a8b0c0", marginBottom: 12, letterSpacing: "0.1em" }}>SECURITY DETAILS</p>
              <div style={{ display: "grid", gridTemplateColumns: "auto 1fr", gap: "8px 16px", fontSize: 14 }}>
                {[
                  ["Cipher", "AES-256-GCM (authenticated)"],
                  ["Key Derivation", "PBKDF2 · SHA-256 · 310K iterations"],
                  ["IV", "12-byte random per record"],
                  ["Salt", "16-byte random per session"],
                  ["Passphrase Storage", "Never stored — SHA-256 hash for verification only"],
                  ["Data at Rest", "Encrypted in Google Sheets"],
                  ["Data in Transit", "HTTPS + client-side encryption"],
                  ["Local Bookings", bookings.length + " records"],
                  ["Endpoint", syncConfig.endpointUrl ? "✅ Configured" : "❌ Not configured"],
                  ["Encryption Key", passphrase ? "🔓 Active" : "🔒 Locked"],
                ].map(([k, v]) => (
                  <React.Fragment key={k}>
                    <span style={{ color: "#a8b0c0", fontWeight: 500 }}>{k}</span>
                    <span style={{ color: "var(--text-2)", fontFamily: "var(--mono)", fontSize: 13 }}>{v}</span>
                  </React.Fragment>
                ))}
              </div>
            </div>

            {/* Reset option */}
            <div style={{ marginTop: 14, textAlign: "center" }}>
              {syncResetConfirm ? (
                <div style={{ display: "inline-flex", gap: 6, alignItems: "center" }}>
                  <span style={{ fontSize: 13, color: "var(--red)" }}>Reset config? Local bookings will be kept.</span>
                  <button onClick={() => {
                    localStorage.removeItem(SYNC_CONFIG_KEY);
                    setSyncConfig({ endpointUrl: "", passphraseHash: "", lastSync: "" });
                    setSyncEndpointInput(""); setPassphraseInput(""); setPassphrase("");
                    setSyncConfigured(false); setSyncStatus("idle"); setSyncMessage("Config reset");
                    setSyncResetConfirm(false);
                  }} style={{ padding: "4px 12px", borderRadius: 5, border: "1px solid #3a1a1a", background: "rgba(220,38,38,0.06)", color: "var(--red)", fontSize: 13, cursor: "pointer", fontFamily: "inherit", fontWeight: 700 }}>Yes, Reset</button>
                  <button onClick={() => setSyncResetConfirm(false)} style={{ padding: "4px 12px", borderRadius: 5, border: "1px solid var(--border-1)", background: "transparent", color: "var(--text-2)", fontSize: 13, cursor: "pointer", fontFamily: "inherit" }}>Cancel</button>
                </div>
              ) : (
                <button onClick={() => setSyncResetConfirm(true)} style={{ padding: "6px 14px", borderRadius: 6, border: "1px solid #2a1a1a", background: "transparent", color: "#664", fontSize: 13, cursor: "pointer", fontFamily: "inherit" }}>
                  Reset Sync Configuration
                </button>
              )}
            </div>
          </div>
        )}

        {/* ══════════════ BACKUP & RECOVERY ══════════════ */}
        {view === "backup" && (
          <div className="card-enter">
            <h2 style={{ fontSize: 20, fontWeight: 700, color: "#fff", marginBottom: 6 }}>💾 Backup & Recovery</h2>
            <p style={{ fontSize: 14, color: "var(--text-2)", fontWeight: 500, marginBottom: 20 }}>
              Auto-backups run every 10 minutes. Manual backups and file exports keep your data safe.
            </p>

            {/* Status Banner */}
            {backupMsg && (
              <div style={{ padding: "10px 14px", borderRadius: 10, marginBottom: 16, background: backupMsgType === "success" ? "rgba(80,200,80,0.08)" : backupMsgType === "error" ? "rgba(220,38,38,0.06)" : "rgba(59,158,255,0.06)", border: `1px solid ${backupMsgType === "success" ? "rgba(5,150,105,0.2)" : backupMsgType === "error" ? "rgba(220,38,38,0.2)" : "rgba(76,175,106,0.15)"}`, display: "flex", alignItems: "center", gap: 10 }}>
                <span style={{ fontSize: 16 }}>{backupMsgType === "success" ? "✅" : backupMsgType === "error" ? "❌" : "💡"}</span>
                <span style={{ fontSize: 14, color: backupMsgType === "success" ? "var(--green)" : backupMsgType === "error" ? "var(--red)" : "var(--green)", flex: 1 }}>{backupMsg}</span>
                <button onClick={() => setBackupMsg("")} style={{ background: "transparent", border: "none", color: "#a8b0c0", fontSize: 14, cursor: "pointer" }}>✕</button>
              </div>
            )}

            {/* Storage Info Bar */}
            <div style={{ background: "var(--bg-1)", border: "1px solid #1e2028", borderRadius: 12, padding: 14, marginBottom: 14 }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
                <span style={{ fontSize: 14, fontWeight: 700, color: "var(--green)", letterSpacing: "0.08em" }}>STORAGE</span>
                <span style={{ fontSize: 13, color: "var(--text-2)" }}>{storageInfo.capacityPercent}% of 5MB used</span>
              </div>
              <div style={{ height: 6, borderRadius: 3, background: "var(--border-0)", overflow: "hidden", marginBottom: 8 }}>
                <div style={{ height: "100%", borderRadius: 3, width: `${Math.min(storageInfo.capacityPercent, 100)}%`, background: storageInfo.capacityPercent > 80 ? "var(--green)" : storageInfo.capacityPercent > 50 ? "var(--amber)" : "#4ade80", transition: "width 0.3s" }} />
              </div>
              <div style={{ display: "flex", gap: 16, fontSize: 13, color: "var(--text-2)" }}>
                <span>📝 Bookings: <span style={{ color: "var(--text-2)" }}>{storageInfo.bookingKB}KB</span></span>
                <span>💾 Backups: <span style={{ color: "var(--text-2)" }}>{storageInfo.backupKB}KB ({storageInfo.backupCount})</span></span>
                <span>📊 Total: <span style={{ color: "var(--text-2)" }}>{storageInfo.totalKB}KB</span></span>
              </div>
            </div>

            {/* Action Buttons */}
            <div style={{ display: "flex", gap: 8, marginBottom: 14 }}>
              <button onClick={handleManualBackup} style={{ flex: 1, padding: "12px", borderRadius: 10, border: "none", background: "linear-gradient(135deg, #2a6a2a, #3a8a3a)", color: "#fff", fontSize: 14, fontWeight: 700, cursor: "pointer", fontFamily: "inherit" }}>
                💾 Back Up Now
              </button>
              <button onClick={handleExport} style={{ flex: 1, padding: "12px", borderRadius: 10, border: "none", background: "linear-gradient(135deg, #2255aa, #3377cc)", color: "#fff", fontSize: 14, fontWeight: 700, cursor: "pointer", fontFamily: "inherit" }}>
                📤 Export to File
              </button>
              <button onClick={() => fileInputRef.current?.click()} style={{ flex: 1, padding: "12px", borderRadius: 10, border: "1px solid var(--border-1)", background: "transparent", color: "var(--text-2)", fontSize: 14, fontWeight: 700, cursor: "pointer", fontFamily: "inherit" }}>
                📥 Import File
              </button>
              <input ref={fileInputRef} type="file" accept=".json" onChange={handleImport} style={{ display: "none" }} />
            </div>

            {/* Current Data Summary */}
            <div style={{ background: "var(--bg-1)", border: "1px solid #1e2028", borderRadius: 12, padding: 14, marginBottom: 14 }}>
              <p style={{ fontSize: 14, fontWeight: 700, color: "var(--green)", letterSpacing: "0.08em", marginBottom: 10 }}>CURRENT DATA</p>
              <div className="resp-grid-3" style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 8, textAlign: "center" }}>
                <div style={{ background: "var(--bg-1)", borderRadius: 8, padding: "10px 8px" }}>
                  <p style={{ fontSize: 22, fontWeight: 800, color: "#fff" }}>{bookings.length}</p>
                  <p style={{ fontSize: 12, color: "var(--text-2)" }}>Bookings</p>
                </div>
                <div style={{ background: "var(--bg-1)", borderRadius: 8, padding: "10px 8px" }}>
                  <p style={{ fontSize: 22, fontWeight: 800, color: "#4ade80" }}>{snapshots.length}</p>
                  <p style={{ fontSize: 12, color: "var(--text-2)" }}>Snapshots</p>
                </div>
                <div style={{ background: "var(--bg-1)", borderRadius: 8, padding: "10px 8px" }}>
                  <p style={{ fontSize: 22, fontWeight: 800, color: "var(--green)" }}>{backupLog.length}</p>
                  <p style={{ fontSize: 12, color: "var(--text-2)" }}>Log Entries</p>
                </div>
              </div>
            </div>

            {/* Available Snapshots */}
            <div style={{ background: "var(--bg-1)", border: "1px solid #1e2028", borderRadius: 12, padding: 14, marginBottom: 14 }}>
              <p style={{ fontSize: 14, fontWeight: 700, color: "var(--green)", letterSpacing: "0.08em", marginBottom: 10 }}>SAVED SNAPSHOTS</p>
              {snapshots.length === 0 ? (
                <p style={{ fontSize: 14, color: "var(--text-2)", fontWeight: 500, textAlign: "center", padding: 16 }}>No snapshots yet. Tap "Back Up Now" or wait for auto-backup.</p>
              ) : (
                <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                  {snapshots.map(snap => (
                    <div key={snap.key} style={{ background: "var(--bg-1)", border: "1px solid #1e2028", borderRadius: 8, padding: "10px 12px", borderLeft: `3px solid ${snap.type === "manual" ? "#4ade80" : "var(--green)"}` }}>
                      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 4 }}>
                        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                          <span style={{ fontSize: 13, fontWeight: 700, color: snap.type === "manual" ? "#4ade80" : "var(--green)", textTransform: "uppercase", background: snap.type === "manual" ? "rgba(74,222,128,0.1)" : "rgba(76,175,106,0.08)", padding: "2px 6px", borderRadius: 4 }}>{snap.type === "manual" ? "💾 Manual" : "⏰ Auto"}</span>
                          <span style={{ fontSize: 14, color: "var(--text-2)", fontWeight: 500 }}>{snap.count} bookings</span>
                          <span style={{ fontSize: 12, color: "var(--text-2)" }}>{snap.sizeKB}KB</span>
                        </div>
                        <div style={{ display: "flex", gap: 4 }}>
                          {restoreConfirmKey === snap.key ? (
                            <>
                              <button onClick={() => handleRestore(snap.key)} style={{ padding: "3px 8px", borderRadius: 4, border: "none", background: "var(--green)", color: "#fff", fontSize: 12, fontWeight: 700, cursor: "pointer", fontFamily: "inherit" }}>Restore</button>
                              <button onClick={() => setRestoreConfirmKey(null)} style={{ padding: "3px 8px", borderRadius: 4, border: "1px solid var(--border-1)", background: "transparent", color: "var(--text-2)", fontSize: 12, cursor: "pointer", fontFamily: "inherit" }}>Cancel</button>
                            </>
                          ) : (
                            <>
                              <button onClick={() => setRestoreConfirmKey(snap.key)} style={{ padding: "3px 8px", borderRadius: 4, border: "1px solid #1a3a1a", background: "transparent", color: "var(--green)", fontSize: 12, cursor: "pointer", fontFamily: "inherit" }}>↩ Restore</button>
                              <button onClick={() => handleDeleteSnapshot(snap.key)} style={{ padding: "3px 8px", borderRadius: 4, border: "1px solid #3a1a1a", background: "transparent", color: "#844", fontSize: 12, cursor: "pointer", fontFamily: "inherit" }}>✕</button>
                            </>
                          )}
                        </div>
                      </div>
                      <p style={{ fontSize: 12, color: "#a8b0c0" }}>{new Date(snap.timestamp).toLocaleString()}</p>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Backup Log */}
            <div style={{ background: "var(--bg-1)", border: "1px solid #1e2028", borderRadius: 12, padding: 14 }}>
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 10 }}>
                <p style={{ fontSize: 14, fontWeight: 700, color: "var(--green)", letterSpacing: "0.08em" }}>BACKUP LOG</p>
                <div style={{ display: "flex", gap: 4 }}>
                  <button onClick={() => setShowBackupLog(!showBackupLog)} style={{ padding: "3px 10px", borderRadius: 4, border: "1px solid var(--border-1)", background: "transparent", color: "var(--text-2)", fontSize: 12, cursor: "pointer", fontFamily: "inherit" }}>{showBackupLog ? "Hide" : "Show"} ({backupLog.length})</button>
                  {backupLog.length > 0 && <button onClick={() => { BackupService.clearLog(); refreshBackupState(); }} style={{ padding: "3px 8px", borderRadius: 4, border: "1px solid #3a1a1a", background: "transparent", color: "#664", fontSize: 12, cursor: "pointer", fontFamily: "inherit" }}>Clear</button>}
                </div>
              </div>
              {showBackupLog && (
                <div style={{ maxHeight: 300, overflowY: "auto" }}>
                  {backupLog.length === 0 ? (
                    <p style={{ fontSize: 14, color: "var(--text-2)", fontWeight: 500, textAlign: "center", padding: 12 }}>No log entries yet</p>
                  ) : (
                    backupLog.map((entry, i) => (
                      <div key={i} style={{ display: "flex", alignItems: "flex-start", gap: 8, padding: "6px 0", borderBottom: "1px solid #1a1c22" }}>
                        <span style={{ fontSize: 14, flexShrink: 0 }}>
                          {entry.action === "auto" ? "⏰" : entry.action === "manual" ? "💾" : entry.action === "export" ? "📤" : entry.action === "import" ? "📥" : entry.action === "restore" ? "↩️" : entry.action === "delete" ? "🗑" : "📋"}
                        </span>
                        <div style={{ flex: 1 }}>
                          <p style={{ fontSize: 14, color: "var(--text-2)", fontWeight: 500 }}>{entry.message}</p>
                          <p style={{ fontSize: 11, color: "var(--text-2)" }}>{new Date(entry.timestamp).toLocaleString()}{entry.count > 0 ? ` · ${entry.count} bookings` : ""}</p>
                        </div>
                      </div>
                    ))
                  )}
                </div>
              )}
            </div>
          </div>
        )}
      </main>
    </div>
  );
}

// ── Subcomponents ──

const labelStyle = { display: "block", fontSize: 10, fontWeight: 500, color: "var(--green)", letterSpacing: "0.16em", textTransform: "uppercase", marginBottom: 5, fontFamily: "var(--mono)", lineHeight: 1.2 };
const inputStyle = { width: "100%", padding: "11px 13px", borderRadius: 6, border: "1px solid var(--border-1)", background: "#fff", color: "#1a0a00", fontSize: 15, fontWeight: 600, fontFamily: "var(--sans)", outline: "none", transition: "border-color 0.15s, box-shadow 0.15s", lineHeight: 1.4 };

// ────────────────────────────────────────────────────────
// LOGIN PAGE
// ────────────────────────────────────────────────────────
function LoginPage({ endpointUrl: initialEndpointUrl, onLogin, onSaveEndpoint }) {
  const { useState: ust, useCallback: ucb, useRef: ur, useEffect: ue } = React;
  const [tab, setTab] = ust("signin");
  const [username, setUsername] = ust("");
  const [password, setPassword] = ust("");
  const [displayName, setDisplayName] = ust("");
  const [email, setEmail] = ust("");
  const [loading, setLoading] = ust(false);
  const [error, setError] = ust("");
  const [success, setSuccess] = ust("");
  const [showPass, setShowPass] = ust(false);
  const [endpointUrl, setEndpointUrl] = ust(initialEndpointUrl || "https://script.google.com/macros/s/AKfycbzRFmi7dn8yy_u6m0YCz7YCHt-_-PNm6VHOVdOMixf_vMBq0SF3lWg1sEQhwWI2J8I-/exec");
  const [showUrlField, setShowUrlField] = ust(false);
  const [faceIdAvail, setFaceIdAvail] = ust(false);
  const [faceIdUser, setFaceIdUser] = ust("");
  const [faceIdLoading, setFaceIdLoading] = ust(false);
  const [faceIdError, setFaceIdError] = ust("");
  const FACEID_KEY = "dispatch-hq-faceid-cred";
  const FACEID_USER_KEY = "dispatch-hq-faceid-user";
  const FACEID_SESSION_KEY = "dispatch-hq-faceid-session";

  // Check if WebAuthn + platform authenticator (Face ID) is available
  ue(() => {
    const saved = localStorage.getItem(FACEID_USER_KEY);
    if (saved) setFaceIdUser(saved);
    if (window.PublicKeyCredential) {
      window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()
        .then(ok => {
          setFaceIdAvail(ok);
          // Auto-trigger Face ID if credential exists
          if (ok && saved && localStorage.getItem(FACEID_KEY)) {
            setTimeout(() => handleFaceId(), 600);
          }
        })
        .catch(() => setFaceIdAvail(false));
    }
  }, []);

  // Client-side pre-hash (SHA-256 via Web Crypto) before sending
  async function clientHash(password) {
    const enc = new TextEncoder();
    const buf = await crypto.subtle.digest("SHA-256", enc.encode(password + "dispatch-hq-client-salt"));
    return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2,"0")).join("");
  }

  // Register Face ID after successful password login
  async function registerFaceId(userData) {
    if (!faceIdAvail) return;
    try {
      const uid = crypto.getRandomValues(new Uint8Array(16));
      const cred = await navigator.credentials.create({
        publicKey: {
          challenge: crypto.getRandomValues(new Uint8Array(32)),
          rp: { name: "Dispatch HQ", id: location.hostname },
          user: {
            id: uid,
            name: userData.username,
            displayName: userData.displayName || userData.username
          },
          pubKeyCredParams: [{ alg: -7, type: "public-key" }, { alg: -257, type: "public-key" }],
          authenticatorSelection: {
            authenticatorAttachment: "platform",
            userVerification: "required",
            requireResidentKey: true
          },
          timeout: 60000,
          attestation: "none"
        }
      });
      // Store credential ID and saved session for Face ID re-auth
      const credId = btoa(String.fromCharCode(...new Uint8Array(cred.rawId)));
      localStorage.setItem(FACEID_KEY, credId);
      localStorage.setItem(FACEID_USER_KEY, userData.username);
      localStorage.setItem(FACEID_SESSION_KEY, JSON.stringify(userData));
    } catch(e) {
      // User cancelled or Face ID failed — skip silently
    }
  }

  // Sign in with Face ID
  async function handleFaceId() {
    setFaceIdLoading(true); setFaceIdError("");
    try {
      const credIdStr = localStorage.getItem(FACEID_KEY);
      if (!credIdStr) { setFaceIdError("Face ID not set up. Sign in with password first."); return; }
      const credIdBytes = Uint8Array.from(atob(credIdStr), c => c.charCodeAt(0));
      const assertion = await navigator.credentials.get({
        publicKey: {
          challenge: crypto.getRandomValues(new Uint8Array(32)),
          rpId: location.hostname,
          allowCredentials: [{ type: "public-key", id: credIdBytes }],
          userVerification: "required",
          timeout: 60000
        }
      });
      if (assertion) {
        // Face ID passed — restore saved session OR re-auth with server
        const saved = localStorage.getItem(FACEID_SESSION_KEY);
        if (saved) {
          const sess = JSON.parse(saved);
          // Re-validate session is still active with server
          const url = endpointUrl.trim();
          try {
            const resp = await fetch(`${url}?action=validateSession&sessionToken=${sess.token}`, { signal: AbortSignal.timeout(5000) });
            const data = await resp.json();
            if (data.valid) {
              onLogin(sess);
              return;
            }
          } catch {}
          // If server check fails, still allow via Face ID (offline mode)
          onLogin(sess);
        } else {
          setFaceIdError("Session expired. Sign in with password to re-enable Face ID.");
        }
      }
    } catch(e) {
      if (e.name === "NotAllowedError") {
        setFaceIdError("Face ID cancelled. Use password to sign in.");
      } else {
        setFaceIdError("Face ID failed. Use password instead.");
      }
    } finally { setFaceIdLoading(false); }
  }

  async function handleSignIn(e) {
    e.preventDefault();
    if (!username.trim() || !password) { setError("Please enter your username and password."); return; }
    const url = endpointUrl.trim();
    if (!url) { setError("Enter your Google Sheets URL below first."); setShowUrlField(true); return; }
    if (!url.startsWith("https://script.google.com/")) { setError("URL must start with https://script.google.com/"); return; }
    if (onSaveEndpoint) onSaveEndpoint(url);
    setLoading(true); setError(""); setSuccess("");
    try {
      const hash = await clientHash(password);
      const resp = await fetch(url, {
        method: "POST", headers: { "Content-Type": "text/plain;charset=utf-8" },
        body: JSON.stringify({ action: "login", username: username.trim().toLowerCase(), passwordHash: hash })
      });
      const data = await resp.json();
      if (!data.success) { setError(data.error || "Sign in failed."); return; }
      const userData = { username: username.trim().toLowerCase(), role: data.role, displayName: data.displayName, token: data.token, expiresAt: data.expiresAt };
      // Register Face ID after successful login (required)
      if (faceIdAvail) await registerFaceId(userData);
      onLogin(userData);
    } catch(err) {
      setError("Could not reach server. Check your internet connection.");
    } finally { setLoading(false); }
  }

  async function handleSignUp(e) {
    e.preventDefault();
    if (!username.trim()) { setError("Username is required."); return; }
    if (!/^[a-z0-9_]{3,30}$/.test(username.trim().toLowerCase())) { setError("Username: 3-30 characters, letters/numbers/underscores only."); return; }
    if (!displayName.trim()) { setError("Display name is required."); return; }
    if (!password || password.length < 8) { setError("Password must be at least 8 characters."); return; }
    if (!endpointUrl) { setError("App not connected to Google Sheets. Ask your admin."); return; }
    setLoading(true); setError(""); setSuccess("");
    try {
      const hash = await clientHash(password);
      const resp = await fetch(endpointUrl, {
        method: "POST", headers: { "Content-Type": "text/plain;charset=utf-8" },
        body: JSON.stringify({ action: "register", username: username.trim().toLowerCase(), passwordHash: hash, displayName: displayName.trim(), email: email.trim() })
      });
      const data = await resp.json();
      if (!data.success) { setError(data.error || "Registration failed."); return; }
      setSuccess("Account created! Your request is pending admin approval. You'll be able to sign in once approved.");
      setUsername(""); setPassword(""); setDisplayName(""); setEmail("");
    } catch(err) {
      setError("Could not reach server. Check your internet connection.");
    } finally { setLoading(false); }
  }

  const inp = { background: "#fff", border: "1px solid var(--border-1)", borderRadius: 6, color: "#1a0a00", fontSize: 15, fontWeight: 600, padding: "10px 12px", width: "100%", outline: "none", fontFamily: "var(--sans)", boxSizing: "border-box", transition: "border-color 0.15s, box-shadow 0.15s", lineHeight: 1.4 };
  const btn = { width: "100%", padding: "13px", borderRadius: 10, border: "none", fontSize: 17, fontWeight: 700, cursor: "pointer", fontFamily: "var(--sans)", transition: "all 0.2s", letterSpacing: "0.03em" };
  const lbl = { display: "block", fontSize: 10, fontWeight: 500, color: "var(--green)", letterSpacing: "0.16em", textTransform: "uppercase", marginBottom: 6, fontFamily: "var(--mono)", lineHeight: 1.2 };

  return (
    <div style={{ minHeight: "100vh", background: "var(--bg-0)", display: "flex", alignItems: "center", justifyContent: "center", padding: 20, position: "relative", overflow: "hidden", minHeight: "100vh" }}>
      {/* Grid texture */}
      <div style={{ position: "absolute", inset: 0, backgroundImage: "linear-gradient(rgba(61,159,255,0.018) 1px, transparent 1px), linear-gradient(90deg, rgba(61,159,255,0.018) 1px, transparent 1px)", backgroundSize: "40px 40px", pointerEvents: "none" }} />
      {/* Glow orbs */}
      <div style={{ position: "absolute", top: "10%", left: "8%", width: 400, height: 400, borderRadius: "50%", background: "radial-gradient(circle, rgba(42,125,225,0.06) 0%, transparent 70%)", pointerEvents: "none" }} />
      <div style={{ position: "absolute", bottom: "10%", right: "5%", width: 500, height: 500, borderRadius: "50%", background: "radial-gradient(circle, rgba(42,125,225,0.04) 0%, transparent 70%)", pointerEvents: "none" }} />

      <div style={{ width: "100%", maxWidth: 420, position: "relative", zIndex: 1, animation: "fadeUp 0.4s ease forwards" }}>
        {/* Logo */}
        <div style={{ textAlign: "center", marginBottom: 36 }}>
          <div style={{ width: 64, height: 64, borderRadius: 18, background: "linear-gradient(135deg, #ff3a20, #ff5c2b)", display: "inline-flex", alignItems: "center", justifyContent: "center", fontSize: 30, marginBottom: 16, boxShadow: "0 0 40px rgba(76,175,106,0.25)" }}>🚖</div>
          <h1 style={{ color: "var(--text-1)", fontSize: 28, fontWeight: 800, margin: 0, letterSpacing: "0.16em", fontFamily: "var(--sans)" }}>DISPATCH HQ</h1>
          <p style={{ color: "var(--text-3)", fontSize: 11, marginTop: 6, letterSpacing: "0.08em", fontFamily: "var(--mono)", color: "var(--text-3)" }}>택시 배차 관리 시스템</p>
        </div>

        {/* Card */}
        <div style={{ background: "var(--bg-1)", border: "1px solid var(--border-1)", borderRadius: 12, padding: 28, boxShadow: "var(--shadow-lg)" }}>
          {/* Tabs */}
          <div style={{ display: "flex", background: "var(--bg-1)", borderRadius: 8, padding: 3, marginBottom: 24, border: "1px solid var(--border-0)" }}>
            {[["signin","Sign In"],["signup","Sign Up"]].map(([t, label]) => (
              <button key={t} onClick={() => { setTab(t); setError(""); setSuccess(""); }} style={{
                flex: 1, padding: "10px 0", borderRadius: 8, border: "none", fontSize: 14, fontWeight: 600, cursor: "pointer", fontFamily: "var(--sans)", transition: "all 0.2s", letterSpacing: "0.01em",
                background: tab === t ? "var(--amber)" : "transparent",
                color: tab === t ? "#0a0a0a" : "var(--text-3)",
                boxShadow: tab === t ? "0 2px 8px rgba(240,165,0,0.2)" : "none"
              }}>{label}</button>
            ))}
          </div>

          {/* Error / Success */}
          {error && <div style={{ padding: "10px 14px", borderRadius: 8, background: "rgba(220,38,38,0.05)", border: "1px solid rgba(220,38,38,0.2)", color: "var(--red)", fontSize: 13, marginBottom: 18, lineHeight: 1.5, fontFamily: "var(--sans)" }}>{error}</div>}
          {success && <div style={{ padding: "10px 14px", borderRadius: 8, background: "rgba(5,150,105,0.05)", border: "1px solid rgba(5,150,105,0.2)", color: "var(--green)", fontSize: 13, marginBottom: 18, lineHeight: 1.5, fontFamily: "var(--sans)" }}>{success}</div>}

          {tab === "signin" ? (
            <form onSubmit={handleSignIn}>
              {/* Face ID — shown when credential exists */}
              {faceIdAvail && faceIdUser && (
                <div style={{ marginBottom: 20 }}>
                  <button type="button" onClick={handleFaceId} disabled={faceIdLoading} style={{ width: "100%", padding: "16px", borderRadius: 10, border: "2px solid var(--amber)", background: faceIdLoading ? "var(--bg-2)" : "rgba(240,165,0,0.06)", color: faceIdLoading ? "var(--text-3)" : "var(--amber)", fontSize: 16, fontWeight: 700, cursor: faceIdLoading ? "not-allowed" : "pointer", fontFamily: "var(--display)", letterSpacing: "0.1em", transition: "all 0.2s", display: "flex", alignItems: "center", justifyContent: "center", gap: 10 }}>
                    <span style={{ fontSize: 26 }}>🔐</span>
                    <span>{faceIdLoading ? "VERIFYING..." : "SIGN IN WITH FACE ID"}</span>
                  </button>
                  {faceIdError && <p style={{ fontSize: 12, color: "var(--red)", marginTop: 8, textAlign: "center", fontFamily: "var(--mono)" }}>{faceIdError}</p>}
                  <div style={{ display: "flex", alignItems: "center", gap: 10, margin: "16px 0 4px" }}>
                    <div style={{ flex: 1, height: 1, background: "var(--border-0)" }} />
                    <span style={{ fontSize: 10, color: "var(--text-3)", fontFamily: "var(--mono)", letterSpacing: "0.12em" }}>OR USE PASSWORD</span>
                    <div style={{ flex: 1, height: 1, background: "var(--border-0)" }} />
                  </div>
                </div>
              )}
              {/* Google Sheets URL */}
              {showUrlField ? (
                <div style={{ marginBottom: 16 }}>
                  <label style={lbl}>Google Sheets URL</label>
                  <input style={{...inp, fontSize: 12}} type="url" value={endpointUrl} onChange={e => setEndpointUrl(e.target.value)} placeholder="https://script.google.com/macros/s/.../exec" autoComplete="off" />
                  <p style={{ fontSize: 13, color: "var(--text-3)", marginTop: 4, fontFamily: "var(--mono)" }}>Your Apps Script deployment URL. {endpointUrl && <span onClick={() => setShowUrlField(false)} style={{ color: "var(--green)", cursor: "pointer" }}>Hide</span>}</p>
                </div>
              ) : (
                <div style={{ marginBottom: 16, display: "flex", alignItems: "center", justifyContent: "space-between", padding: "8px 0" }}>
                  <span style={{ fontSize: 12, color: "var(--green)", display: "flex", alignItems: "center", gap: 6, fontFamily: "var(--mono)" }}>
                    <span style={{ width: 6, height: 6, borderRadius: "50%", background: "var(--green)", display: "inline-block", animation: "pulse-dot 2s infinite" }} />
                    Server connected
                  </span>
                  <button type="button" onClick={() => setShowUrlField(true)} style={{ background: "transparent", border: "none", color: "var(--text-3)", fontSize: 11, cursor: "pointer", fontFamily: "var(--mono)", letterSpacing: "0.08em" }}>CHANGE URL</button>
                </div>
              )}
              <div style={{ marginBottom: 14 }}>
                <label style={lbl}>Username</label>
                <input style={inp} type="text" value={username} onChange={e => setUsername(e.target.value)} placeholder="your_username" autoComplete="username" autoCapitalize="none" />
              </div>
              <div style={{ marginBottom: 22, position: "relative" }}>
                <label style={lbl}>Password</label>
                <input style={inp} type={showPass ? "text" : "password"} value={password} onChange={e => setPassword(e.target.value)} placeholder="••••••••" autoComplete="current-password" />
                <button type="button" onClick={() => setShowPass(v => !v)} style={{ position: "absolute", right: 12, top: 28, background: "transparent", border: "none", color: "var(--text-3)", cursor: "pointer", fontSize: 14 }}>{showPass ? "👁" : "👁️"}</button>
              </div>
              <button type="submit" disabled={loading} style={{ ...btn, background: loading ? "var(--bg-2)" : "var(--amber)", color: loading ? "var(--text-3)" : "#0a0a0a", boxShadow: loading ? "none" : "0 0 20px rgba(240,165,0,0.25)", fontFamily: "var(--display)", letterSpacing: "0.1em" }}>
                {loading ? "SIGNING IN..." : "SIGN IN →"}
              </button>
              {faceIdAvail && !faceIdUser && (
                <p style={{ textAlign: "center", fontSize: 11, color: "var(--text-3)", marginTop: 10, fontFamily: "var(--mono)", letterSpacing: "0.06em" }}>🔒 Face ID will activate after your first sign in</p>
              )}
              <p style={{ textAlign: "center", fontSize: 12, color: "var(--text-3)", marginTop: 16, marginBottom: 0, fontFamily: "var(--sans)" }}>No account? <button type="button" onClick={() => setTab("signup")} style={{ background: "none", border: "none", color: "var(--green)", cursor: "pointer", fontFamily: "var(--sans)", fontSize: 12, fontWeight: 600, textDecoration: "underline" }}>Request Access</button></p>
            </form>
          ) : (
            <form onSubmit={handleSignUp}>
              <div style={{ marginBottom: 14 }}>
                <label style={lbl}>Display Name</label>
                <input style={inp} type="text" value={displayName} onChange={e => setDisplayName(e.target.value)} placeholder="Your Full Name" autoComplete="name" />
              </div>
              <div style={{ marginBottom: 14 }}>
                <label style={lbl}>Username</label>
                <input style={inp} type="text" value={username} onChange={e => setUsername(e.target.value.toLowerCase().replace(/[^a-z0-9_]/g,""))} placeholder="letters_numbers_only" autoComplete="username" autoCapitalize="none" />
                <p style={{ fontSize: 9, color: "var(--text-3)", fontFamily: "var(--mono)", letterSpacing: "0.08em", marginTop: 4, fontFamily: "var(--mono)" }}>3–30 chars · letters, numbers, underscore only</p>
              </div>
              <div style={{ marginBottom: 14 }}>
                <label style={lbl}>Email (optional)</label>
                <input style={inp} type="email" value={email} onChange={e => setEmail(e.target.value)} placeholder="your@email.com" autoComplete="email" />
              </div>
              <div style={{ marginBottom: 22, position: "relative" }}>
                <label style={lbl}>Password</label>
                <input style={inp} type={showPass ? "text" : "password"} value={password} onChange={e => setPassword(e.target.value)} placeholder="Min 8 characters" autoComplete="new-password" />
                <button type="button" onClick={() => setShowPass(v => !v)} style={{ position: "absolute", right: 12, top: 28, background: "transparent", border: "none", color: "var(--text-3)", cursor: "pointer", fontSize: 14 }}>{showPass ? "👁" : "👁️"}</button>
              </div>
              <button type="submit" disabled={loading} style={{ ...btn, background: loading ? "var(--bg-2)" : "rgba(34,197,94,0.15)", color: loading ? "var(--text-3)" : "var(--green)", border: "1px solid rgba(34,197,94,0.25)", boxShadow: "none" }}>
                {loading ? "Sending request…" : "Request Access"}
              </button>
              <p style={{ textAlign: "center", fontSize: 13, color: "var(--text-3)", marginTop: 14, lineHeight: 1.6, marginBottom: 0, fontFamily: "var(--mono)" }}>Account requires admin approval before sign in.</p>
            </form>
          )}
        </div>

        <p style={{ textAlign: "center", fontSize: 10, color: "var(--border-1)", marginTop: 20, fontFamily: "var(--mono)", letterSpacing: "0.1em" }}>DISPATCH HQ · SECURED WITH AES-256</p>
      </div>
    </div>
  );
}

// ────────────────────────────────────────────────────────
// ADMIN DASHBOARD
// ────────────────────────────────────────────────────────
function AdminDashboard({ currentUser, endpointUrl, onSignOut }) {
  const { useState: ust, useEffect: uef, useCallback: ucb } = React;
  const [users, setUsers] = ust([]);
  const [stats, setStats] = ust({ activeSessions: 0, totalBookings: 0 });
  const [loading, setLoading] = ust(true);
  const [actionMsg, setActionMsg] = ust("");
  const [filterStatus, setFilterStatus] = ust("all");
  const [confirmAction, setConfirmAction] = ust(null); // { action, username, label }

  const fetchUsers = ucb(async () => {
    if (!endpointUrl) return;
    try {
      const resp = await fetch(endpointUrl + "?action=adminGetUsers&token=" + encodeURIComponent(loadSyncConfig().authToken || "") + "&sessionToken=" + encodeURIComponent(currentUser.token), { method: "GET", redirect: "follow" });
      const data = await resp.json();
      if (data.success) { setUsers(data.users || []); setStats({ activeSessions: data.activeSessions || 0, totalBookings: data.totalBookings || 0 }); }
    } catch(e) {}
    finally { setLoading(false); }
  }, [endpointUrl, currentUser.token]);

  uef(() => { fetchUsers(); }, [fetchUsers]);

  const doAction = async (action, targetUsername, newPassword) => {
    setConfirmAction(null);
    setActionMsg("");
    try {
      const body = { action, targetUsername, sessionToken: currentUser.token };
      if (newPassword) body.newPasswordHash = await (async () => {
        const enc = new TextEncoder();
        const buf = await crypto.subtle.digest("SHA-256", enc.encode(newPassword + "dispatch-hq-client-salt"));
        return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2,"0")).join("");
      })();
      const resp = await fetch(endpointUrl, {
        method: "POST", headers: { "Content-Type": "text/plain;charset=utf-8" },
        body: JSON.stringify(body)
      });
      const data = await resp.json();
      setActionMsg(data.success ? "✅ Done — " + (data.message || action) : "❌ " + (data.error || "Failed"));
      if (data.success) fetchUsers();
    } catch(e) { setActionMsg("❌ Network error"); }
  };

  const statusColors = { active: "var(--green)", pending: "var(--amber)", rejected: "var(--red)", disabled: "var(--text-2)" };
  const filtered = filterStatus === "all" ? users : users.filter(u => u.status === filterStatus);
  const pendingCount = users.filter(u => u.status === "pending").length;

  const cardStyle = { background: "var(--bg-1)", border: "1px solid #1e2028", borderRadius: 12, padding: "14px 18px" };

  return (
    <div style={{ minHeight: "100vh", background: "var(--bg-0)", color: "var(--text-1)", fontFamily: "var(--sans)" }}>
      {/* Header */}
      <div className="safe-header" style={{ background: "rgba(9,21,8,0.97)", borderBottom: "1px solid var(--border-0)", paddingLeft: 16, paddingRight: 16, paddingTop: "max(env(safe-area-inset-top), 44px)", paddingBottom: 0, display: "flex", alignItems: "flex-end", gap: 12, minHeight: "calc(54px + max(env(safe-area-inset-top), 44px))", position: "sticky", top: 0, zIndex: 100, boxShadow: "0 1px 0 rgba(76,175,106,0.1)", boxSizing: "border-box" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10, paddingBottom: 10, flex: 1 }}>
          <div style={{ width: 28, height: 28, borderRadius: 7, background: "linear-gradient(135deg, #8a6000, var(--amber))", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 13 }}>🚖</div>
          <div>
            <p style={{ fontSize: 15, fontWeight: 700, color: "var(--amber)", margin: 0, letterSpacing: "0.1em", fontFamily: "var(--display)" }}>DISPATCH HQ</p>
            <p style={{ fontSize: 10, color: "var(--green)", margin: 0, fontWeight: 500, fontFamily: "var(--mono)", letterSpacing: "0.12em" }}>ADMIN DASHBOARD</p>
          </div>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 10, paddingBottom: 10 }}>
          <span style={{ fontSize: 12, color: "var(--text-3)", fontFamily: "var(--mono)" }}>👤 {currentUser.displayName}</span>
          <button onClick={onSignOut} style={{ padding: "6px 12px", borderRadius: 6, border: "1px solid var(--border-0)", background: "transparent", color: "var(--text-2)", fontSize: 12, fontWeight: 600, cursor: "pointer", fontFamily: "var(--mono)", letterSpacing: "0.08em" }}>EXIT</button>
        </div>
      </div>

      {/* Bottom nav for admin on mobile */}
      <nav role="navigation" aria-label="Admin navigation" className="bottom-nav">
        <button onClick={onSignOut} className="bottom-nav-btn" aria-label="Sign out" style={{ flex: 1 }}>
          <span>EXIT</span>
        </button>
        <div className="bottom-nav-btn" style={{ flex: 3, display: "flex", alignItems: "center", justifyContent: "center", color: "var(--amber)", fontSize: 11, fontFamily: "var(--mono)", letterSpacing: "0.1em", fontWeight: 700, borderTop: "none" }}>
          ADMIN PANEL
        </div>
        <div className="bottom-nav-btn" style={{ flex: 1 }} />
      </nav>

      <div className="safe-main" style={{ maxWidth: 900, margin: "0 auto", padding: "20px 16px" }}>
        {/* Stats row */}
        <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 10, marginBottom: 24 }}>
          {[
            ["👥", "Total Users", users.length, "#fff"],
            ["⏳", "Pending Approval", pendingCount, pendingCount > 0 ? "var(--amber)" : "#fff"],
            ["✅", "Active Users", users.filter(u => u.status==="active").length, "var(--green)"],
            ["📋", "Total Bookings", stats.totalBookings, "var(--green)"],
          ].map(([icon, label, val, col]) => (
            <div key={label} style={cardStyle}>
              <p style={{ fontSize: 20, margin: "0 0 4px" }}>{icon}</p>
              <p style={{ fontSize: 22, fontWeight: 800, color: col, margin: "0 0 2px" }}>{val}</p>
              <p style={{ fontSize: 12, color: "#7a8498", margin: 0 }}>{label}</p>
            </div>
          ))}
        </div>

        {/* Action feedback */}
        {actionMsg && <div style={{ padding: "10px 14px", borderRadius: 8, background: actionMsg.startsWith("✅") ? "rgba(5,150,105,0.05)" : "rgba(220,38,38,0.04)", border: `1px solid ${actionMsg.startsWith("✅") ? "rgba(5,150,105,0.2)" : "rgba(220,38,38,0.2)"}`, color: actionMsg.startsWith("✅") ? "var(--green)" : "var(--red)", fontSize: 14, marginBottom: 16 }}>{actionMsg}</div>}

        {/* Confirm dialog */}
        {confirmAction && (
          <div style={{ position: "fixed", inset: 0, background: "rgba(15,23,42,0.5)", zIndex: 500, display: "flex", alignItems: "center", justifyContent: "center" }}>
            <div style={{ background: "var(--bg-2)", border: "1px solid var(--border-1)", borderRadius: 16, padding: 24, maxWidth: 340, width: "90%" }}>
              <p style={{ fontSize: 16, fontWeight: 700, color: "#fff", marginBottom: 8 }}>Confirm Action</p>
              <p style={{ fontSize: 14, color: "var(--text-2)", fontWeight: 500, marginBottom: confirmAction.isReset ? 12 : 20 }}>{confirmAction.label} <strong style={{ color: "#fff" }}>{confirmAction.username}</strong>?</p>
              {confirmAction.isReset && (
                <div style={{ marginBottom: 16 }}>
                  <label style={{ display: "block", fontSize: 12, fontWeight: 700, color: "var(--text-2)", marginBottom: 6, letterSpacing: "0.08em" }}>NEW PASSWORD</label>
                  <input
                    type="text"
                    value={confirmAction.newPassword || ""}
                    onChange={e => setConfirmAction(prev => ({ ...prev, newPassword: e.target.value }))}
                    placeholder="Enter new password for dispatcher"
                    style={{ width: "100%", padding: "10px 12px", borderRadius: 8, border: "1px solid var(--border-1)", background: "var(--bg-1)", color: "var(--text-1)", fontSize: 14, fontFamily: "inherit", outline: "none", boxSizing: "border-box" }}
                  />
                  <p style={{ fontSize: 11, color: "#7a8498", marginTop: 4 }}>Share this with the dispatcher verbally or over the phone.</p>
                </div>
              )}
              <div style={{ display: "flex", gap: 10 }}>
                <button onClick={() => setConfirmAction(null)} style={{ flex: 1, padding: "10px", borderRadius: 8, border: "1px solid var(--border-1)", background: "transparent", color: "var(--text-2)", fontSize: 14, cursor: "pointer", fontFamily: "inherit" }}>Cancel</button>
                <button
                  onClick={() => {
                    if (confirmAction.isReset && !confirmAction.newPassword?.trim()) {
                      setActionMsg("❌ Please enter a new password");
                      setConfirmAction(null);
                      return;
                    }
                    doAction(confirmAction.action, confirmAction.username, confirmAction.newPassword);
                  }}
                  style={{ flex: 1, padding: "10px", borderRadius: 8, border: "none", background: confirmAction.isReset ? "rgba(76,175,106,0.12)" : "var(--green)", color: "#fff", fontSize: 14, fontWeight: 700, cursor: "pointer", fontFamily: "inherit" }}>
                  {confirmAction.isReset ? "🔑 Reset" : "Confirm"}
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Bookings section */}
        <div style={{ ...cardStyle, padding: 0, overflow: "hidden", marginBottom: 14 }}>
          <div style={{ padding: "14px 18px", borderBottom: "1px solid #1e2028", display: "flex", alignItems: "center", gap: 10 }}>
            <span style={{ fontSize: 20 }}>📋</span>
            <div style={{ flex: 1 }}>
              <p style={{ fontSize: 14, fontWeight: 700, color: "var(--green)", margin: "0 0 2px", letterSpacing: "0.08em" }}>BOOKING DATA</p>
              <p style={{ fontSize: 12, color: "#7a8498", margin: 0 }}>{stats.totalBookings} records in cloud (AES-256 encrypted)</p>
            </div>
          </div>
          <div style={{ padding: "12px 18px" }}>
            <p style={{ fontSize: 13, color: "var(--text-2)", margin: "0 0 10px", lineHeight: 1.6 }}>
              Booking data is encrypted client-side before syncing. Only dispatcher devices holding the decryption passphrase can read it — the cloud storage and this admin panel cannot decrypt it.
            </p>
            <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
              <div style={{ padding: "8px 14px", borderRadius: 8, background: "var(--bg-0)", border: "1px solid #1e2028", fontSize: 14, color: "var(--text-2)", fontWeight: 500 }}>
                📊 To view bookings → sign in as a dispatcher → Dashboard tab
              </div>
              <div style={{ padding: "8px 14px", borderRadius: 8, background: "var(--bg-0)", border: "1px solid #1e2028", fontSize: 14, color: "var(--text-2)", fontWeight: 500 }}>
                💾 To export → dispatcher → Backup tab → Export JSON
              </div>
            </div>
          </div>
        </div>

        {/* Users table */}
        <div style={{ ...cardStyle, padding: 0, overflow: "hidden" }}>
          <div style={{ padding: "14px 18px", borderBottom: "1px solid #1e2028", display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
            <p style={{ fontSize: 14, fontWeight: 700, color: "var(--green)", margin: 0, letterSpacing: "0.08em", flex: 1 }}>DISPATCHER ACCOUNTS</p>
            <div style={{ display: "flex", gap: 4 }}>
              {["all","pending","active","disabled"].map(s => (
                <button key={s} onClick={() => setFilterStatus(s)} style={{ padding: "5px 10px", borderRadius: 6, border: filterStatus === s ? "1px solid #ff3a30" : "1px solid #1e2028", background: filterStatus === s ? "rgba(220,38,38,0.06)" : "transparent", color: filterStatus === s ? "var(--green)" : "#7a8498", fontSize: 12, cursor: "pointer", fontFamily: "inherit", fontWeight: 600, textTransform: "capitalize" }}>{s}{s==="pending" && pendingCount > 0 ? ` (${pendingCount})` : ""}</button>
              ))}
            </div>
            <button onClick={fetchUsers} style={{ padding: "5px 12px", borderRadius: 6, border: "1px solid #1e2028", background: "transparent", color: "#8892a8", fontSize: 12, cursor: "pointer", fontFamily: "inherit" }}>↻ Refresh</button>
          </div>

          {loading ? (
            <div style={{ padding: 40, textAlign: "center", color: "#7a8498" }}>Loading users…</div>
          ) : filtered.length === 0 ? (
            <div style={{ padding: 40, textAlign: "center", color: "#7a8498" }}>{filterStatus === "pending" ? "No pending registrations" : "No users found"}</div>
          ) : (
            filtered.map(user => (
              <div key={user.id} style={{ padding: "14px 18px", borderBottom: "1px solid #12141a", display: "flex", alignItems: "center", gap: 12, flexWrap: "wrap" }}>
                <div style={{ flex: 1, minWidth: 180 }}>
                  <p style={{ fontSize: 14, fontWeight: 700, color: "var(--text-1)", margin: "0 0 2px" }}>{user.displayName}</p>
                  <p style={{ fontSize: 12, color: "#8892a8", margin: 0 }}>@{user.username}{user.email ? " · " + user.email : ""}</p>
                  <p style={{ fontSize: 11, color: "var(--text-3)", margin: "2px 0 0" }}>Registered {new Date(user.createdAt).toLocaleDateString()}</p>
                </div>
                <span style={{ fontSize: 12, padding: "3px 10px", borderRadius: 10, background: `rgba(${user.status==="active"?"80,200,80":user.status==="pending"?"255,200,50":user.status==="disabled"?"128,128,128":"255,80,80"},0.1)`, color: statusColors[user.status] || "var(--text-2)", fontWeight: 700, border: `1px solid ${statusColors[user.status] || "var(--text-1)"}22`, textTransform: "capitalize" }}>{user.status}</span>
                <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                  {user.status === "pending" && <>
                    <button onClick={() => setConfirmAction({ action: "approveUser", username: user.username, label: "Approve account for" })} style={{ padding: "6px 12px", borderRadius: 6, border: "1px solid #1a3a1a", background: "rgba(5,150,105,0.08)", color: "var(--green)", fontSize: 13, fontWeight: 700, cursor: "pointer", fontFamily: "inherit" }}>✓ Approve</button>
                    <button onClick={() => setConfirmAction({ action: "rejectUser", username: user.username, label: "Reject account for" })} style={{ padding: "6px 12px", borderRadius: 6, border: "1px solid #3a1a1a", background: "rgba(220,38,38,0.04)", color: "var(--red)", fontSize: 13, fontWeight: 700, cursor: "pointer", fontFamily: "inherit" }}>✗ Reject</button>
                  </>}
                  {user.status === "active" && <button onClick={() => setConfirmAction({ action: "disableUser", username: user.username, label: "Disable account for" })} style={{ padding: "6px 12px", borderRadius: 6, border: "1px solid var(--border-1)", background: "transparent", color: "var(--text-2)", fontSize: 13, cursor: "pointer", fontFamily: "inherit" }}>Disable</button>}
                  {user.status === "active" && <button onClick={() => setConfirmAction({ action: "resetPassword", username: user.username, label: "Reset password for", isReset: true })} style={{ padding: "6px 12px", borderRadius: 6, border: "1px solid #2a3a4a", background: "rgba(59,158,255,0.06)", color: "var(--green)", fontSize: 13, cursor: "pointer", fontFamily: "inherit" }}>🔑 Reset PW</button>}
                  {user.status === "disabled" && <button onClick={() => setConfirmAction({ action: "enableUser", username: user.username, label: "Re-enable account for" })} style={{ padding: "6px 12px", borderRadius: 6, border: "1px solid #1a3a1a", background: "transparent", color: "var(--green)", fontSize: 13, cursor: "pointer", fontFamily: "inherit" }}>Enable</button>}
                  {user.status !== "active" && <button onClick={() => setConfirmAction({ action: "deleteUser", username: user.username, label: "Permanently delete account for" })} style={{ padding: "6px 12px", borderRadius: 6, border: "1px solid #3a1a1a", background: "transparent", color: "var(--red)", fontSize: 13, cursor: "pointer", fontFamily: "inherit" }}>Delete</button>}
                </div>
              </div>
            ))
          )}
        </div>

        <div style={{ marginTop: 20, padding: "14px 18px", background: "var(--bg-1)", border: "1px solid #1a1c22", borderRadius: 12 }}>
          <p style={{ fontSize: 13, color: "#7a8498", margin: 0, lineHeight: 1.6 }}>
            <strong style={{ color: "var(--text-2)" }}>Admin credentials:</strong> To change your admin password, run <code style={{ background: "var(--bg-2)", padding: "1px 6px", borderRadius: 4, color: "var(--amber)" }}>Logger.log(hashPassword('newpassword'))</code> in the Apps Script editor, then update <code style={{ background: "var(--bg-2)", padding: "1px 6px", borderRadius: 4, color: "var(--amber)" }}>ADMIN_PASSWORD_HASH</code> and redeploy.
          </p>
        </div>

        {/* ── Sync & Settings ── */}
        {(() => {
          const [adminSyncUrl, setAdminSyncUrl] = React.useState(() => {
            try { const cfg = JSON.parse(localStorage.getItem("dispatch-hq-sync-config") || "{}"); return cfg.endpointUrl || ""; } catch { return ""; }
          });
          const [adminAuthToken, setAdminAuthToken] = React.useState(() => {
            try { const cfg = JSON.parse(localStorage.getItem("dispatch-hq-sync-config") || "{}"); return cfg.authToken || "kX9mP2vQ8nL5wR3jF7tY4cH6dA1sE0bN"; } catch { return "kX9mP2vQ8nL5wR3jF7tY4cH6dA1sE0bN"; }
          });
          const [adminPassphrase, setAdminPassphrase] = React.useState("");
          const [adminSyncMsg, setAdminSyncMsg] = React.useState("");
          const [adminSyncStatus, setAdminSyncStatus] = React.useState("idle");
          const [adminMapsKey, setAdminMapsKey] = React.useState(() => {
            try { return localStorage.getItem("dispatch-hq-maps-key") || ""; } catch { return ""; }
          });
          const [showAdminPass, setShowAdminPass] = React.useState(false);

          const saveAdminSync = () => {
            if (!adminSyncUrl.trim()) { setAdminSyncMsg("Enter the Google Sheets URL"); return; }
            if (!adminSyncUrl.startsWith("https://script.google.com/")) { setAdminSyncMsg("URL must start with https://script.google.com/"); return; }
            try {
              const existing = JSON.parse(localStorage.getItem("dispatch-hq-sync-config") || "{}");
              const updated = { ...existing, endpointUrl: adminSyncUrl.trim(), authToken: adminAuthToken.trim() };
              localStorage.setItem("dispatch-hq-sync-config", JSON.stringify(updated));
              setAdminSyncMsg("✅ Saved. Reload the app to apply.");
              setAdminSyncStatus("success");
            } catch { setAdminSyncMsg("❌ Failed to save"); setAdminSyncStatus("error"); }
          };

          const testAdminConnection = async () => {
            if (!adminSyncUrl.trim()) { setAdminSyncMsg("Enter the URL first"); return; }
            setAdminSyncStatus("testing"); setAdminSyncMsg("Testing connection...");
            try {
              const resp = await fetch(adminSyncUrl.trim() + "?action=ping&token=" + encodeURIComponent(adminAuthToken.trim()), { method: "GET", redirect: "follow" });
              const data = await resp.json();
              if (data.success) {
                setAdminSyncMsg("✅ Connected — " + (data.sheetName || "Sheet") + " · " + (data.recordCount || 0) + " records");
                setAdminSyncStatus("success");
              } else {
                setAdminSyncMsg("❌ " + (data.error || "Server error"));
                setAdminSyncStatus("error");
              }
            } catch (e) { setAdminSyncMsg("❌ Could not reach server — " + e.message); setAdminSyncStatus("error"); }
          };

          const saveAdminMapsKey = () => {
            try {
              if (adminMapsKey.trim()) localStorage.setItem("dispatch-hq-maps-key", adminMapsKey.trim());
              else localStorage.removeItem("dispatch-hq-maps-key");
              setAdminSyncMsg("✅ Maps API key saved. Reload the app to activate address autocomplete.");
              setAdminSyncStatus("success");
            } catch { setAdminSyncMsg("❌ Failed to save Maps key"); }
          };

          const iStyle = { width:"100%", padding:"10px 12px", borderRadius:8, border:"1px solid #1e2028", background:"var(--bg-1)", color:"var(--text-1)", fontSize:14, fontFamily:"inherit", outline:"revert", boxSizing:"border-box" };
          const lStyle = { display:"block", fontSize:12, fontWeight:700, color:"var(--text-2)", marginBottom:6, textTransform:"uppercase", letterSpacing:"0.06em" };

          return (
            <div style={{ marginTop: 20 }}>
              <p style={{ fontSize: 14, fontWeight: 700, color: "var(--green)", letterSpacing: "0.1em", marginBottom: 14 }}>⚙️ SETTINGS</p>

              {/* Google Sheets Sync */}
              <div style={{ background: "var(--bg-1)", border: "1px solid #1e2028", borderRadius: 12, padding: 18, marginBottom: 12 }}>
                <p style={{ fontSize: 13, fontWeight: 700, color: "#ccc", marginBottom: 14 }}>🔗 Google Sheets Connection</p>

                {adminSyncMsg && (
                  <div style={{ padding: "8px 12px", borderRadius: 8, background: adminSyncStatus === "success" ? "rgba(5,150,105,0.05)" : "rgba(220,38,38,0.04)", border: `1px solid ${adminSyncStatus === "success" ? "rgba(5,150,105,0.2)" : "rgba(220,38,38,0.2)"}`, color: adminSyncStatus === "success" ? "var(--green)" : "var(--red)", fontSize: 13, marginBottom: 12 }}>{adminSyncMsg}</div>
                )}

                <div style={{ marginBottom: 12 }}>
                  <label style={lStyle}>Web App URL</label>
                  <input type="url" value={adminSyncUrl} onChange={e => setAdminSyncUrl(e.target.value)} placeholder="https://script.google.com/macros/s/.../exec" style={iStyle} />
                </div>
                <div style={{ marginBottom: 14 }}>
                  <label style={lStyle}>Auth Token</label>
                  <input type="text" value={adminAuthToken} onChange={e => setAdminAuthToken(e.target.value)} placeholder="Your AUTH_TOKEN from Apps Script" style={iStyle} />
                </div>
                <div style={{ display: "flex", gap: 8 }}>
                  <button onClick={testAdminConnection} style={{ flex: 1, padding: "9px", borderRadius: 8, border: "1px solid var(--border-1)", background: "transparent", color: "var(--text-2)", fontSize: 14, cursor: "pointer", fontFamily: "inherit", fontWeight: 600 }}>Test Connection</button>
                  <button onClick={saveAdminSync} style={{ flex: 1, padding: "9px", borderRadius: 8, border: "none", background: "linear-gradient(135deg,#1a5a2a,#1a7a3a)", color: "#fff", fontSize: 14, cursor: "pointer", fontFamily: "inherit", fontWeight: 700 }}>Save</button>
                </div>
              </div>

              {/* Google Maps API Key */}
              <div style={{ background: "var(--bg-1)", border: "1px solid #1e2028", borderRadius: 12, padding: 18, marginBottom: 12 }}>
                <p style={{ fontSize: 13, fontWeight: 700, color: "#ccc", marginBottom: 14 }}>📍 Google Maps Autocomplete</p>
                <div style={{ marginBottom: 12 }}>
                  <label style={lStyle}>API Key</label>
                  <div style={{ display: "flex", gap: 8 }}>
                    <input type={showAdminPass ? "text" : "password"} value={adminMapsKey} onChange={e => setAdminMapsKey(e.target.value)} placeholder="AIzaSy..." style={{ ...iStyle, flex: 1 }} />
                    <button onClick={() => setShowAdminPass(v => !v)} style={{ padding: "0 12px", borderRadius: 8, border: "1px solid #1e2028", background: "transparent", color: "#8892a8", cursor: "pointer", fontSize: 14 }}>{showAdminPass ? "👁" : "👁️"}</button>
                  </div>
                  <p style={{ fontSize: 11, color: "#7a8498", marginTop: 4 }}>Enables address autocomplete on booking form. Get a free key at console.cloud.google.com</p>
                </div>
                <button onClick={saveAdminMapsKey} style={{ padding: "9px 18px", borderRadius: 8, border: "none", background: "var(--border-0)", color: "var(--text-2)", fontSize: 14, cursor: "pointer", fontFamily: "inherit", fontWeight: 600 }}>Save Maps Key</button>
              </div>
            </div>
          );
        })()}

      </div>
    </div>
  );
}

// ────────────────────────────────────────────────────────
// WHISPER SERVICE — On-device HIPAA-compliant speech recognition
// Uses OpenAI Whisper (tiny) via @xenova/transformers.
// Audio is processed ENTIRELY in the browser — nothing sent to any server.
// No Google, Apple, or Microsoft speech APIs used.
// ────────────────────────────────────────────────────────
// ── Bilingual number normalizer (English + Korean → digits) ──
// Applied after transcription to convert spoken numbers to digit form
// which Whisper sometimes returns as words, especially for address house numbers.
function normalizeSpokenNumbers(text) {
  if (!text) return "";
  let t = text.trim();

  // ── Korean digit-by-digit sequences ──
  const KOR_DIGIT = { "영":0,"공":0,"일":1,"이":2,"삼":3,"사":4,"오":5,"육":6,"칠":7,"팔":8,"구":9 };
  t = t.replace(/[영공일이삼사오육칠팔구]{2,}/g, (m) => {
    const digits = Array.from(m).map(c => KOR_DIGIT[c]);
    return digits.every(d => d !== undefined) ? digits.join("") : m;
  });

  // ── Korean large-unit numbers ──
  t = t.replace(/([일이삼사오육칠팔구]?)(천)([일이삼사오육칠팔구]?)(백)?([일이삼사오육칠팔구십]?)/g, (m, k천, 천w, k백, 백w, k십) => {
    if (!천w) return m;
    const thou = (KOR_DIGIT[k천] || 1) * 1000;
    const hund = 백w ? (KOR_DIGIT[k백] || 1) * 100 : 0;
    const tens = k십 ? (KOR_DIGIT[k십] || 0) * 10 : 0;
    const result = thou + hund + tens;
    return result > 0 ? String(result) : m;
  });
  t = t.replace(/([일이삼사오육칠팔구]?)(백)([일이삼사오육칠팔구]?)(십)?([일이삼사오육칠팔구]?)/g, (m, k백, 백w, k십a, 십w, k일) => {
    if (!백w) return m;
    const hund = (KOR_DIGIT[k백] || 1) * 100;
    const tens = 십w ? (KOR_DIGIT[k십a] || 1) * 10 : 0;
    const ones = KOR_DIGIT[k일] !== undefined ? KOR_DIGIT[k일] : 0;
    const result = hund + tens + ones;
    return result > 0 ? String(result) : m;
  });

  // ── English digit-word helpers ──
  const ENG_DIGIT = { zero:0,oh:0,one:1,two:2,three:3,four:4,five:5,six:6,seven:7,eight:8,nine:9 };
  const ENG_TENS  = { twenty:20,thirty:30,forty:40,fifty:50,sixty:60,seventy:70,eighty:80,ninety:90 };
  const ENG_TEENS = { ten:10,eleven:11,twelve:12,thirteen:13,fourteen:14,fifteen:15,sixteen:16,seventeen:17,eighteen:18,nineteen:19 };

  // ── ADDRESS NUMBER PATTERNS (most important for street addresses) ──

  // Pattern 1: "thirty two forty four" → 3244  (two compound numbers side by side)
  // This is how people SAY house numbers — in pairs
  t = t.replace(/\b(twenty|thirty|forty|fifty|sixty|seventy|eighty|ninety)(?:[- ](one|two|three|four|five|six|seven|eight|nine))?\s+(twenty|thirty|forty|fifty|sixty|seventy|eighty|ninety)(?:[- ](one|two|three|four|five|six|seven|eight|nine))?\b/gi, (m, t1, o1, t2, o2) => {
    const n1 = ENG_TENS[t1.toLowerCase()] + (o1 ? ENG_DIGIT[o1.toLowerCase()] : 0);
    const n2 = ENG_TENS[t2.toLowerCase()] + (o2 ? ENG_DIGIT[o2.toLowerCase()] : 0);
    return String(n1) + String(n2);
  });

  // Pattern 2: "thirty two forty" → 3240 (tens + tens)
  t = t.replace(/\b(twenty|thirty|forty|fifty|sixty|seventy|eighty|ninety)\s+(twenty|thirty|forty|fifty|sixty|seventy|eighty|ninety)\b/gi, (m, t1, t2) => {
    return String(ENG_TENS[t1.toLowerCase()]) + String(ENG_TENS[t2.toLowerCase()]);
  });

  // Pattern 3: "two oh eight" → 208, "one one three" → 113 (digit words with "oh" for zero)
  // Handles ZIP codes and street numbers with zeros
  t = t.replace(/\b(zero|oh|one|two|three|four|five|six|seven|eight|nine)(\s+(zero|oh|one|two|three|four|five|six|seven|eight|nine)){2,5}\b/gi, (m) => {
    const parts = m.toLowerCase().split(/\s+/);
    if (parts.every(p => ENG_DIGIT[p] !== undefined)) {
      return parts.map(p => ENG_DIGIT[p]).join("");
    }
    return m;
  });

  // Pattern 4: ZIP codes — 5 digit-words spoken individually "one one three six one" → "11361"
  // Must come BEFORE compound number patterns to take priority
  t = t.replace(/\b(zero|oh|one|two|three|four|five|six|seven|eight|nine)\s+(zero|oh|one|two|three|four|five|six|seven|eight|nine)\s+(zero|oh|one|two|three|four|five|six|seven|eight|nine)\s+(zero|oh|one|two|three|four|five|six|seven|eight|nine)\s+(zero|oh|one|two|three|four|five|six|seven|eight|nine)\b/gi, (m, a, b, c, d, e) => {
    return [a,b,c,d,e].map(w => ENG_DIGIT[w.toLowerCase()]).join("");
  });

  // Pattern: "two oh eighth" / "two zero eighth" → "208th"
  // Handles NYC-style ordinal streets spoken as digit + "oh/zero" + ordinal
  const ORDINAL_SUFFIX = { first:"1st",second:"2nd",third:"3rd",fourth:"4th",fifth:"5th",sixth:"6th",seventh:"7th",eighth:"8th",ninth:"9th",tenth:"10th",eleventh:"11th",twelfth:"12th",thirteenth:"13th",fourteenth:"14th",fifteenth:"15th",sixteenth:"16th",seventeenth:"17th",eighteenth:"18th",nineteenth:"19th",twentieth:"20th",thirtieth:"30th",fortieth:"40th",fiftieth:"50th",sixtieth:"60th",seventieth:"70th",eightieth:"80th",ninetieth:"90th" };
  // e.g. "two oh eighth" → "208th", "one oh fifth" → "105th"
  t = t.replace(/\b(one|two|three|four|five|six|seven|eight|nine)\s+(oh|zero)\s+(first|second|third|fourth|fifth|sixth|seventh|eighth|ninth|tenth|eleventh|twelfth|thirteenth|fourteenth|fifteenth|sixteenth|seventeenth|eighteenth|nineteenth|twentieth)\b/gi, (m, a, _z, ord) => {
    return String(ENG_DIGIT[a.toLowerCase()]) + "0" + (ORDINAL_SUFFIX[ord.toLowerCase()] || ord);
  });
  // e.g. "two oh eight" → "208" (non-ordinal version)  
  // e.g. "one oh five" → "105"
  t = t.replace(/\b(one|two|three|four|five|six|seven|eight|nine)\s+(oh|zero)\s+(one|two|three|four|five|six|seven|eight|nine)\b/gi, (m, a, _z, b) => {
    return String(ENG_DIGIT[a.toLowerCase()]) + "0" + String(ENG_DIGIT[b.toLowerCase()]);
  });

  // Pattern 6: "two hundred eighth street" → "208th St"
  t = t.replace(/\b(one|two|three|four|five|six|seven|eight|nine)\s+hundred\s+(and\s+)?(twenty|thirty|forty|fifty|sixty|seventy|eighty|ninety)(?:[- ](one|two|three|four|five|six|seven|eight|nine))?(st|nd|rd|th)?\b/gi, (m, h, _and, tens, ones, suf) => {
    const n = ENG_DIGIT[h.toLowerCase()] * 100 + ENG_TENS[tens.toLowerCase()] + (ones ? ENG_DIGIT[ones.toLowerCase()] : 0);
    const s = suf || (n % 10 === 1 ? "st" : n % 10 === 2 ? "nd" : n % 10 === 3 ? "rd" : "th");
    return n + s;
  });

  // Pattern 7: standard hundreds + ones
  t = t.replace(/\b(one|two|three|four|five|six|seven|eight|nine)\s+hundred(?:\s+(twenty|thirty|forty|fifty|sixty|seventy|eighty|ninety))?(?:\s+(one|two|three|four|five|six|seven|eight|nine))?\b/gi, (m, h, tens, ones) => {
    const n = (ENG_DIGIT[h.toLowerCase()] * 100) + (tens ? ENG_TENS[tens.toLowerCase()] : 0) + (ones ? ENG_DIGIT[ones.toLowerCase()] : 0);
    return String(n);
  });

  // Pattern 8: teens → numbers
  t = t.replace(/\b(ten|eleven|twelve|thirteen|fourteen|fifteen|sixteen|seventeen|eighteen|nineteen)\b/gi, (m) => String(ENG_TEENS[m.toLowerCase()]));

  // Pattern 9: tens + optional ones
  t = t.replace(/\b(twenty|thirty|forty|fifty|sixty|seventy|eighty|ninety)(?:[- ](one|two|three|four|five|six|seven|eight|nine))?\b/gi, (m, tens, ones) => {
    return String(ENG_TENS[tens.toLowerCase()] + (ones ? ENG_DIGIT[ones.toLowerCase()] : 0));
  });

  // ── Street suffix normalization ──
  t = t.replace(/\b(street|st\.?)\b/gi,    "St");
  t = t.replace(/\b(avenue|ave\.?)\b/gi,   "Ave");
  t = t.replace(/\b(boulevard|blvd\.?)\b/gi, "Blvd");
  t = t.replace(/\b(drive|dr\.?)\b/gi,     "Dr");
  t = t.replace(/\b(road|rd\.?)\b/gi,      "Rd");
  t = t.replace(/\b(place|pl\.?)\b/gi,     "Pl");
  t = t.replace(/\b(court|ct\.?)\b/gi,     "Ct");
  t = t.replace(/\b(lane|ln\.?)\b/gi,      "Ln");
  t = t.replace(/\b(expressway|expy)\b/gi, "Expy");
  t = t.replace(/\b(parkway|pkwy)\b/gi,    "Pkwy");
  t = t.replace(/\b(highway|hwy)\b/gi,     "Hwy");
  t = t.replace(/\b(apartment|apt\.?)\b/gi, "Apt");
  t = t.replace(/\b(unit)\b/gi,            "Unit");
  t = t.replace(/\b(floor|fl\.?)\b/gi,     "Fl");

  // ── State abbreviations ──
  t = t.replace(/\bnew york\b/gi,     "NY");
  t = t.replace(/\bnew jersey\b/gi,   "NJ");
  t = t.replace(/\bconnecticut\b/gi,  "CT");
  t = t.replace(/\bpennsylvania\b/gi, "PA");

  // ── Ordinals ──
  const ORDINALS = { first:"1st",second:"2nd",third:"3rd",fourth:"4th",fifth:"5th",sixth:"6th",seventh:"7th",eighth:"8th",ninth:"9th",tenth:"10th",eleventh:"11th",twelfth:"12th",thirteenth:"13th",fourteenth:"14th",fifteenth:"15th",sixteenth:"16th",seventeenth:"17th",eighteenth:"18th",nineteenth:"19th",twentieth:"20th" };
  t = t.replace(/\b(first|second|third|fourth|fifth|sixth|seventh|eighth|ninth|tenth|eleventh|twelfth|thirteenth|fourteenth|fifteenth|sixteenth|seventeenth|eighteenth|nineteenth|twentieth)\b/gi, (m) => ORDINALS[m.toLowerCase()] || m);

  // ── Ordinal number + "th/st/nd/rd" fixing ──
  // "208 th" → "208th"
  t = t.replace(/(\d+)\s+(st|nd|rd|th)\b/gi, "$1$2");

  // ── Korean floor/unit suffixes ──
  t = t.replace(/(\d+)\s*층/g, "$1F");
  t = t.replace(/(\d+)\s*호/g, "Unit $1");
  t = t.replace(/(\d+)\s*번지/g, "$1");

  // ── Clean up extra spaces ──
  t = t.replace(/\s{2,}/g, " ").trim();

  return t;
}

const WhisperService = (() => {
  let _pipeline = null;
  let _loadPromise = null;
  let _loadProgress = 0;
  const _progressCbs = [];

  function onProgress(p) {
    if (p && p.progress != null) _loadProgress = Math.round(p.progress);
    _progressCbs.forEach(cb => cb(_loadProgress));
  }

  async function load() {
    if (_pipeline) return _pipeline;
    if (_loadPromise) return _loadPromise;
    _loadPromise = (async () => {
      const { pipeline, env } = await import("https://cdn.jsdelivr.net/npm/@xenova/transformers@2.17.2");
      env.allowLocalModels = false;
      // whisper-tiny: multilingual, handles Korean + English simultaneously
      _pipeline = await pipeline("automatic-speech-recognition", "Xenova/whisper-tiny", {
        progress_callback: onProgress
      });
      return _pipeline;
    })();
    return _loadPromise;
  }

  function onLoadProgress(cb) { _progressCbs.push(cb); return () => { const i = _progressCbs.indexOf(cb); if (i >= 0) _progressCbs.splice(i, 1); }; }
  function isLoaded() { return _pipeline != null; }
  function getProgress() { return _loadProgress; }

  async function transcribe(audioBlob) {
    const asr = await load();
    const arrayBuffer = await audioBlob.arrayBuffer();
    let audioBuffer;
    try {
      const ctx = new (window.AudioContext || window.webkitAudioContext)({ sampleRate: 16000 });
      audioBuffer = await ctx.decodeAudioData(arrayBuffer);
      ctx.close();
    } catch(e) {
      const ctx2 = new (window.AudioContext || window.webkitAudioContext)();
      audioBuffer = await ctx2.decodeAudioData(arrayBuffer.slice(0));
      ctx2.close();
    }
    // Resample to 16kHz (Whisper's required input rate)
    let float32 = audioBuffer.getChannelData(0);
    if (audioBuffer.sampleRate !== 16000) {
      const ratio = audioBuffer.sampleRate / 16000;
      const newLen = Math.round(float32.length / ratio);
      const resampled = new Float32Array(newLen);
      for (let i = 0; i < newLen; i++) resampled[i] = float32[Math.round(i * ratio)];
      float32 = resampled;
    }

    const result = await asr(float32, {
      language: null,
      task: "transcribe",
      // Address-specific prompt: teaches Whisper to expect street addresses
      // Numbers spoken as pairs (house numbers) or digit-by-digit (ZIP codes)
      initial_prompt: "Street address: 3244 208th St Bayside NY 11361. 주소: 서울시 강남구. House numbers said as pairs: thirty two forty four = 3244, twenty oh eight = 208. ZIP codes digit by digit: one one three six one = 11361. Streets: St Ave Blvd Dr Rd Pl. Airports: JFK LGA EWR. Cities: Bayside Flushing Manhattan Brooklyn Queens Bronx Newark Fort Lee Hackensack.",
    });

    const raw = (result.text || "").trim().replace(/^[\s.,]+|[\s.,]+$/g, "");
    // Apply bilingual number normalization
    return normalizeSpokenNumbers(raw);
  }

  return { load, transcribe, onLoadProgress, isLoaded, getProgress };
})();

// ────────────────────────────────────────────────────────
// DEVICE PASSPHRASE GATE
// Shown after login, before the booking app loads.
// Prompts for the device passphrase that encrypts local bookings.
// Passphrase held in memory only — never stored.
// ────────────────────────────────────────────────────────
function DevicePassphraseGate({ onUnlocked, isFirstTime }) {
  const { useState: ust } = React;
  const [passphrase, setPassphrase] = ust("");
  const [error, setError]           = ust("");
  const [loading, setLoading]       = ust(false);
  const [showPass, setShowPass]     = ust(false);

  const handleUnlock = async (e) => {
    e.preventDefault();
    if (!passphrase || passphrase.length < 8) {
      setError("Passphrase must be at least 8 characters.");
      return;
    }
    setLoading(true); setError("");
    try {
      const bookings = await loadBookingsEncrypted(passphrase);
      onUnlocked(passphrase, bookings);
    } catch (err) {
      if (err.message === "WRONG_PASSPHRASE") {
        setError("Wrong passphrase — could not decrypt your bookings. Try again.");
      } else {
        setError("Could not unlock: " + err.message);
      }
      setLoading(false);
    }
  };

  const inp = { background: "#fff", border: "1px solid var(--border-1)", borderRadius: 6, color: "#1a0a00", fontSize: 15, fontWeight: 600, padding: "10px 12px", width: "100%", outline: "none", fontFamily: "var(--sans)", boxSizing: "border-box", lineHeight: 1.4 };

  return (
    <div style={{ minHeight: "100vh", background: "var(--bg-0)", display: "flex", alignItems: "center", justifyContent: "center", padding: 20 }}>
      <div style={{ width: "100%", maxWidth: 400 }}>
        <div style={{ textAlign: "center", marginBottom: 28 }}>
          <div style={{ width: 60, height: 60, borderRadius: 16, background: "linear-gradient(135deg, #1a4a8a, #1a6aff)", display: "inline-flex", alignItems: "center", justifyContent: "center", fontSize: 28, marginBottom: 12 }}>🔐</div>
          <h2 style={{ color: "#fff", fontSize: 22, fontWeight: 800, margin: "0 0 4px" }}>Enter Device Passphrase</h2>
          <p style={{ color: "#7a8498", fontSize: 13, margin: 0 }}>
            {isFirstTime
              ? "Create a passphrase to encrypt your bookings on this device. You'll enter it each time you open the app."
              : "Your bookings are encrypted on this device. Enter your passphrase to unlock them."}
          </p>
        </div>

        <div style={{ background: "linear-gradient(145deg, #12141a, #0f1016)", border: "1px solid #1e2028", borderRadius: 18, padding: 24, boxShadow: "0 16px 48px rgba(0,0,0,0.5)" }}>
          {error && (
            <div style={{ padding: "10px 14px", background: "rgba(255,58,48,0.07)", border: "1px solid #3a1a1a", borderRadius: 8, color: "var(--red)", fontSize: 13, marginBottom: 16, lineHeight: 1.5 }}>{error}</div>
          )}

          <form onSubmit={handleUnlock}>
            <div style={{ marginBottom: 20, position: "relative" }}>
              <label style={{ display: "block", fontSize: 12, fontWeight: 700, color: "#8892a8", textTransform: "uppercase", letterSpacing: "0.07em", marginBottom: 6 }}>
                {isFirstTime ? "Create Passphrase" : "Passphrase"}
              </label>
              <input
                type={showPass ? "text" : "password"}
                value={passphrase}
                onChange={e => setPassphrase(e.target.value)}
                placeholder={isFirstTime ? "Min 8 characters — write this down" : "Enter your passphrase"}
                autoFocus style={inp} autoComplete="off"
              />
              <button type="button" onClick={() => setShowPass(v => !v)} style={{ position: "absolute", right: 12, top: 34, background: "transparent", border: "none", color: "#7a8498", cursor: "pointer", fontSize: 15 }}>{showPass ? "👁" : "👁️"}</button>
            </div>

            {isFirstTime && (
              <div style={{ padding: "10px 14px", background: "rgba(59,158,255,0.06)", border: "1px solid #1a2a4a", borderRadius: 8, marginBottom: 16, fontSize: 12, color: "var(--green)", lineHeight: 1.6 }}>
                💡 <strong>Write this passphrase down.</strong> It encrypts all customer data on your device. If forgotten, existing bookings cannot be recovered.
              </div>
            )}

            <button type="submit" disabled={loading} style={{ width: "100%", padding: 14, borderRadius: 10, border: "none", fontSize: 16, fontWeight: 700, cursor: loading ? "default" : "pointer", fontFamily: "inherit", background: loading ? "var(--border-0)" : "linear-gradient(135deg, #1a4a8a, #1a6aff)", color: loading ? "#7a8498" : "#fff", boxShadow: loading ? "none" : "0 4px 16px rgba(26,100,255,0.3)" }}>
              {loading ? "Decrypting…" : isFirstTime ? "Set Passphrase & Continue" : "Unlock →"}
            </button>
          </form>
        </div>

        <p style={{ textAlign: "center", fontSize: 11, color: "var(--border-0)", marginTop: 16 }}>Passphrase held in memory only — never stored or transmitted</p>
      </div>
    </div>
  );
}

function Field({ label, value, onChange, type = "text", full, highlight }) {
  return (
    <div style={full ? { gridColumn: "1 / -1" } : {}}>
      <label style={{...labelStyle, color: highlight ? "var(--red)" : labelStyle.color}}>{label}{highlight && <span style={{ color: "var(--red)" }}> *</span>}</label>
      <input type={type} value={value} onChange={e => onChange(e.target.value)} style={{...inputStyle, border: highlight ? "1.5px solid #ff3a30" : inputStyle.border, boxShadow: highlight ? "0 0 0 1px rgba(220,38,38,0.15)" : "none" }} />
    </div>
  );
}

function AddressField({ label, value, onChange, highlight, mapsReady, speechLang }) {
  const { useState: ust, useEffect: uef, useCallback: ucb, useRef: ur } = React;

  // Google Places autocomplete state
  const [suggestions, setSuggestions] = ust([]);
  const [showSug, setShowSug]         = ust(false);
  const [activeIdx, setActiveIdx]     = ust(-1);
  const svcRef     = ur(null);
  const debounceRef = ur(null);
  const wrapRef    = ur(null);

  // Whisper recording state: "idle" | "recording" | "processing" | "done" | "error" | "loading"
  const [recState, setRecState]       = ust("idle");
  const [whisperMsg, setWhisperMsg]   = ust("");
  const [loadPct, setLoadPct]         = ust(0);
  const mediaRecorderRef = ur(null);
  const audioChunksRef   = ur([]);
  const streamRef        = ur(null);

  // Close autocomplete on outside click
  uef(() => {
    const h = (e) => { if (wrapRef.current && !wrapRef.current.contains(e.target)) setShowSug(false); };
    document.addEventListener("mousedown", h);
    return () => document.removeEventListener("mousedown", h);
  }, []);

  // ── Google Places autocomplete via Netlify proxy ──
  const fetchSuggestions = ucb(async (text) => {
    if (!text || text.length < 2) { setSuggestions([]); return; }
    try {
      const resp = await fetch(`/.netlify/functions/places?input=${encodeURIComponent(text)}`, {
        signal: AbortSignal.timeout(5000)
      });
      const data = await resp.json();
      if (data.predictions && data.predictions.length > 0) {
        setSuggestions(data.predictions);
      } else {
        setSuggestions([]);
      }
    } catch { setSuggestions([]); }
  }, []);

  const handleChange = (v) => {
    onChange(v); setActiveIdx(-1);
    clearTimeout(debounceRef.current);
    if (v.length >= 2) { setShowSug(true); debounceRef.current = setTimeout(() => fetchSuggestions(v), 280); }
    else { setSuggestions([]); setShowSug(false); }
  };
  const selectSuggestion = (desc) => { onChange(desc); setSuggestions([]); setShowSug(false); setActiveIdx(-1); };
  const handleKeyDown = (e) => {
    if (!showSug || !suggestions.length) return;
    if (e.key === "ArrowDown") { e.preventDefault(); setActiveIdx(i => Math.min(i+1, suggestions.length-1)); }
    else if (e.key === "ArrowUp") { e.preventDefault(); setActiveIdx(i => Math.max(i-1, 0)); }
    else if (e.key === "Enter" && activeIdx >= 0) { e.preventDefault(); selectSuggestion(suggestions[activeIdx].description); }
    else if (e.key === "Escape") { setShowSug(false); }
  };

  // ── Whisper toggle ──
  const toggleWhisper = ucb(async () => {
    // STOP: if currently recording, stop the MediaRecorder
    if (recState === "recording") {
      if (mediaRecorderRef.current && mediaRecorderRef.current.state !== "inactive") {
        mediaRecorderRef.current.stop();
      }
      return;
    }
    // START: request mic and begin recording
    setWhisperMsg(""); setRecState("idle");
    if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
      setWhisperMsg("Microphone not available. Please use HTTPS (e.g. Netlify)."); setRecState("error"); return;
    }
    if (!window.isSecureContext) {
      setWhisperMsg("Microphone requires HTTPS."); setRecState("error"); return;
    }

    let stream;
    try {
      stream = await navigator.mediaDevices.getUserMedia({ audio: { echoCancellation: true, noiseSuppression: true, sampleRate: 16000 } });
      streamRef.current = stream;
    } catch(err) {
      const msg = err.name === "NotAllowedError" ? "Microphone access denied. Allow it in your browser settings." : "Could not access microphone: " + err.message;
      setWhisperMsg(msg); setRecState("error"); return;
    }

    audioChunksRef.current = [];
    // Pick best supported MIME type
    const mime = ["audio/webm;codecs=opus","audio/webm","audio/ogg;codecs=opus","audio/ogg","audio/mp4",""].find(m => !m || MediaRecorder.isTypeSupported(m)) || "";
    const mr = new MediaRecorder(stream, mime ? { mimeType: mime } : {});
    mediaRecorderRef.current = mr;

    mr.ondataavailable = (e) => { if (e.data && e.data.size > 0) audioChunksRef.current.push(e.data); };

    mr.onstop = async () => {
      // Release microphone immediately
      stream.getTracks().forEach(t => t.stop());
      streamRef.current = null;

      if (audioChunksRef.current.length === 0) { setRecState("idle"); return; }

      setRecState("processing");
      setWhisperMsg(WhisperService.isLoaded() ? "Transcribing…" : "Loading model (first use, ~40 MB)…");

      // Track model download progress
      const unsubProgress = WhisperService.onLoadProgress((pct) => {
        setLoadPct(pct);
        if (pct < 100) setWhisperMsg("Downloading model: " + pct + "%");
        else setWhisperMsg("Transcribing…");
      });

      try {
        const blob = new Blob(audioChunksRef.current, { type: mime || "audio/webm" });
        const lang = (speechLang || "en-US").startsWith("ko") ? "ko" : "en";
        const text = await WhisperService.transcribe(blob);
        unsubProgress();
        if (text && text.length > 0) {
          onChange(text);
          setWhisperMsg("✓ Filled");
          setRecState("done");
          setTimeout(() => { setRecState("idle"); setWhisperMsg(""); }, 2500);
        } else {
          setWhisperMsg("Nothing detected — try again."); setRecState("error");
          setTimeout(() => { setRecState("idle"); setWhisperMsg(""); }, 3000);
        }
      } catch(err) {
        unsubProgress();
        setWhisperMsg("Transcription error — check internet connection (model download needed once)."); setRecState("error");
        setTimeout(() => { setRecState("idle"); setWhisperMsg(""); }, 4000);
      }
    };

    mr.start(250); // collect data every 250ms for reliability
    setRecState("recording");
    setWhisperMsg("Recording… tap again to stop");
  }, [recState, onChange, speechLang]);

  // Colour coding for mic button states
  const micBg      = recState === "recording" ? "var(--green)" : recState === "processing" ? "rgba(76,175,106,0.12)" : recState === "done" ? "rgba(5,150,105,0.1)" : "var(--bg-1)";
  const micBorder  = recState === "recording" ? "var(--green)" : recState === "processing" ? "rgba(76,175,106,0.12)" : recState === "done" ? "rgba(5,150,105,0.12)" : "var(--border-0)";
  const micIcon    = recState === "recording" ? "⏹" : recState === "processing" ? "⏳" : recState === "done" ? "✓" : "🎤";
  const micPulse   = recState === "recording" ? "pulse 1s infinite" : "none";
  const micTitle   = recState === "recording" ? "Recording — tap to stop" : recState === "processing" ? "Processing audio…" : recState === "done" ? "Done!" : "Tap to speak address (HIPAA-compliant, on-device)";

  return (
    <div ref={wrapRef} style={{ gridColumn: "1 / -1", position: "relative" }}>
      {/* Label row */}
      <div style={{ display: "flex", alignItems: "center", marginBottom: 4, gap: 6 }}>
        <label style={{...labelStyle, marginBottom: 0, flex: 1, color: highlight ? "var(--red)" : labelStyle.color}}>
          {label}{highlight && <span style={{ color: "var(--red)" }}> *</span>}
          {mapsReady && <span style={{ fontSize: 10, color: "#3a6a3a", marginLeft: 6, fontWeight: 400 }}>📍 Maps</span>}
        </label>
        {/* HIPAA badge */}
        <span style={{ fontSize: 9, padding: "2px 6px", borderRadius: 4, background: "rgba(59,158,255,0.07)", color: "#3a6a9a", border: "1px solid #1a2a3a", fontWeight: 700, letterSpacing: "0.05em", flexShrink: 0 }}>HIPAA</span>
        {/* Mic toggle button */}
        <button
          onClick={toggleWhisper}
          disabled={recState === "processing"}
          title={micTitle}
          style={{
            width: 30, height: 30, borderRadius: "50%", flexShrink: 0,
            border: "1.5px solid " + micBorder,
            background: micBg,
            color: recState === "idle" ? "#a8b0c0" : "#fff",
            fontSize: 14, cursor: recState === "processing" ? "default" : "pointer",
            display: "flex", alignItems: "center", justifyContent: "center",
            animation: micPulse, transition: "all 0.2s",
            boxShadow: recState === "recording" ? "0 0 8px rgba(255,58,48,0.5)" : "none"
          }}
        >{micIcon}</button>
      </div>

      {/* Input */}
      <input
        type="text" value={value}
        onChange={e => handleChange(e.target.value)}
        onKeyDown={handleKeyDown}
        onFocus={() => { if (value.length >= 2 && suggestions.length) setShowSug(true); }}
        placeholder={
          recState === "recording" ? "🔴 Recording — tap ⏹ to stop…"
          : recState === "processing" ? "⏳ Transcribing on-device…"
          : mapsReady ? "Type or speak address…"
          : "Enter address"
        }
        autoComplete="off"
        style={{
          ...inputStyle,
          border: recState === "recording" ? "1.5px solid #ff3a30"
            : recState === "processing" ? "1.5px solid #1a4a8a"
            : recState === "done" ? "1.5px solid #1a6a3a"
            : highlight ? "1.5px solid #ff3a30" : inputStyle.border,
          boxShadow: recState === "recording" ? "0 0 0 2px rgba(255,58,48,0.15)"
            : recState === "processing" ? "0 0 0 2px rgba(76,175,106,0.08)"
            : highlight ? "0 0 0 1px rgba(220,38,38,0.15)" : "none",
          transition: "all 0.2s"
        }}
      />

      {/* Status / progress bar */}
      {whisperMsg && (
        <div style={{ marginTop: 5, display: "flex", alignItems: "center", gap: 8 }}>
          {recState === "processing" && loadPct > 0 && loadPct < 100 && (
            <div style={{ flex: 1, height: 3, background: "var(--border-0)", borderRadius: 2, overflow: "hidden" }}>
              <div style={{ height: "100%", width: loadPct + "%", background: "linear-gradient(90deg, #3b9eff, #6bc4ff)", borderRadius: 2, transition: "width 0.3s" }} />
            </div>
          )}
          <p style={{
            fontSize: 11, margin: 0,
            color: recState === "error" ? "var(--red)" : recState === "done" ? "var(--green)" : recState === "recording" ? "var(--green)" : "var(--text-2)"
          }}>{whisperMsg}</p>
        </div>
      )}

      {/* Google Places suggestions */}
      {showSug && suggestions.length > 0 && (
        <div style={{
          position: "absolute", top: "100%", left: 0, right: 0, zIndex: 300,
          background: "var(--bg-2)", border: "1px solid var(--border-1)", borderRadius: 8,
          marginTop: 3, boxShadow: "0 8px 24px rgba(0,0,0,0.7)", overflow: "hidden"
        }}>
          {suggestions.map((s, i) => {
            const main = s.structured_formatting ? s.structured_formatting.main_text : s.description.split(",")[0];
            const secondary = s.structured_formatting ? s.structured_formatting.secondary_text : s.description.split(",").slice(1).join(",").trim();
            return (
              <div key={s.place_id} onMouseDown={() => selectSuggestion(s.description)}
                style={{ padding: "10px 14px", cursor: "pointer", borderBottom: i < suggestions.length - 1 ? "1px solid #1e2028" : "none",
                  background: i === activeIdx ? "rgba(255,107,53,0.1)" : "transparent", display: "flex", alignItems: "flex-start", gap: 10 }}>
                <span style={{ fontSize: 16, marginTop: 1, flexShrink: 0 }}>📍</span>
                <div style={{ overflow: "hidden" }}>
                  <div style={{ fontSize: 14, fontWeight: 600, color: i === activeIdx ? "var(--green)" : "var(--text-1)", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{main}</div>
                  {secondary && <div style={{ fontSize: 12, color: "#909aaa", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{secondary}</div>}
                </div>
              </div>
            );
          })}
          <div style={{ padding: "5px 10px", background: "var(--bg-1)", display: "flex", alignItems: "center", justifyContent: "flex-end" }}>
            <img src="https://maps.gstatic.com/mapfiles/api-3/images/google_logo.png" alt="Google" style={{ height: 12, opacity: 0.5 }} />
          </div>
        </div>
      )}
    </div>
  );
}


function Badge({ label, ok, neutral }) {
  return (
    <span style={{
      padding: "2px 8px", borderRadius: 4, fontSize: 11, fontWeight: 600,
      fontFamily: "var(--mono)", letterSpacing: "0.06em",
      background: neutral ? "rgba(139,146,168,0.08)" : ok ? "rgba(34,197,94,0.08)" : "rgba(239,68,68,0.08)",
      color: neutral ? "var(--text-2)" : ok ? "var(--green)" : "#ef4444",
      border: `1px solid ${neutral ? "var(--border-1)" : ok ? "rgba(34,197,94,0.2)" : "rgba(239,68,68,0.2)"}`
    }}>{label}</span>
  );
}

function BookingSection({ title, bookings, onEdit, onDelete }) {
  if (!bookings.length) return null;
  const groups = {};
  bookings.forEach(b => {
    const key = `${b.date}|${b.timeSlot}`;
    if (!groups[key]) groups[key] = [];
    groups[key].push(b);
  });
  return (
    <div style={{ marginBottom: 28 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 14 }}>
        <h3 style={{ fontSize: 10, fontWeight: 500, color: "var(--green)", letterSpacing: "0.18em", fontFamily: "var(--mono)", whiteSpace: "nowrap", lineHeight: 1 }}>{title.replace(/[^\w\s]/g,"").trim().toUpperCase()}</h3>
        <div style={{ flex: 1, height: 1, background: "linear-gradient(90deg, var(--border-0) 0%, transparent 100%)" }} />
        <span style={{ fontSize: 9, color: "var(--text-3)", fontFamily: "var(--mono)", letterSpacing: "0.08em", fontFamily: "var(--mono)", letterSpacing: "0.1em" }}>{bookings.length}</span>
      </div>
      {Object.entries(groups).map(([key, cluster]) => (
        <div key={key} style={{ marginBottom: 6 }}>
          {cluster.length > 1 && (
            <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "3px 12px", marginBottom: 3 }}>
              <span style={{ fontSize: 10, fontWeight: 700, color: "#f59e0b", background: "rgba(245,158,11,0.08)", padding: "2px 8px", borderRadius: 4, fontFamily: "var(--mono)", letterSpacing: "0.08em" }}>{cluster.length} SAME SLOT</span>
              <span style={{ fontSize: 13, color: "var(--text-3)", fontFamily: "var(--mono)" }}>{cluster[0].date} · {cluster[0].timeSlot}</span>
            </div>
          )}
          {cluster.map(b => <BookingCard key={b.id} booking={b} onEdit={onEdit} onDelete={onDelete} isCluster={cluster.length > 1} />)}
        </div>
      ))}
    </div>
  );
}

function BookingCard({ booking: b, onEdit, onDelete, isCluster }) {
  const dayName = DAYS[new Date(b.date + "T12:00:00").getDay()];
  const flightColor = b.flightStatus === "on-time" || b.flightStatus === "landed" ? "var(--green)" : b.flightStatus === "delayed" ? "#f59e0b" : b.flightStatus === "cancelled" ? "#ef4444" : "var(--green)";
  return (
    <div style={{
      background: "var(--bg-1)", border: `1px solid ${isCluster ? "rgba(245,158,11,0.2)" : "var(--border-1)"}`,
      borderRadius: 10, padding: "12px 14px", marginBottom: 5,
      borderLeft: `2px solid ${isCluster ? "#f59e0b" : "var(--green)"}`,
      transition: "border-color 0.15s"
    }}>
      {/* Top row: date/time/driver + actions */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 10 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
          <span style={{ fontSize: 15, fontWeight: 700, color: "var(--text-1)", fontFamily: "var(--mono)" }}>{b.date}</span>
          <span style={{ fontSize: 13, color: "var(--text-3)", fontFamily: "var(--mono)" }}>{dayName.toUpperCase()}</span>
          <span style={{ fontSize: 14, fontWeight: 700, color: "var(--green)", background: "rgba(76,175,106,0.08)", padding: "2px 8px", borderRadius: 5, fontFamily: "var(--mono)", border: "1px solid rgba(76,175,106,0.15)" }}>{b.timeSlot}</span>
          {b.flightStatus && (
            <span style={{ fontSize: 10, fontWeight: 700, padding: "2px 7px", borderRadius: 4, textTransform: "uppercase", letterSpacing: "0.08em", fontFamily: "var(--mono)", color: flightColor, background: `${flightColor}12`, border: `1px solid ${flightColor}30` }}>✈ {b.flightStatus}</span>
          )}
        </div>
        <div style={{ display: "flex", gap: 3, flexShrink: 0 }}>
          <button onClick={() => onEdit(b)} style={{ padding: "6px 10px", borderRadius: 6, border: "1px solid #1c2035", background: "transparent", color: "var(--text-2)", fontSize: 13, cursor: "pointer" }}>✏️</button>
          <button onClick={() => {
            const w = window.open("","_blank","width=420,height=660");
            const d = b.date ? new Date(b.date+"T12:00:00").toLocaleDateString("en-US",{weekday:"short",month:"short",day:"numeric",year:"numeric"}) : "—";
            w.document.write('<!DOCTYPE html><html><head><title>Dispatch HQ — Booking Slip</title><style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:"IBM Plex Mono",monospace;background:#fff;color:#0f172a;font-size:13px;padding:24px;max-width:400px;margin:0 auto}h2{font-family:sans-serif;font-size:18px;font-weight:800;letter-spacing:0.1em;margin-bottom:2px}p.sub{font-size:11px;color:#888;margin-bottom:14px;letter-spacing:0.06em}.divider{border:none;border-top:1px solid #e5e5e5;margin:10px 0}.row{display:flex;justify-content:space-between;align-items:baseline;padding:7px 0;border-bottom:1px solid #f5f5f5}.label{font-size:10px;color:#888;text-transform:uppercase;letter-spacing:0.1em}.val{font-weight:600;text-align:right;font-size:13px;max-width:230px}.fare{font-size:26px;font-weight:800;color:var(--mocha,#8b5e3c)}@media print{button{display:none}}</style></head><body>');
            w.document.write('<h2>🚖 DISPATCH HQ</h2><p class="sub">BOOKING CONFIRMATION</p><hr class="divider">');
            w.document.write('<div class="row"><span class="label">Customer</span><span class="val">'+b.customerName+'</span></div>');
            w.document.write('<div class="row"><span class="label">Phone</span><span class="val">'+b.phone+'</span></div>');
            w.document.write('<div class="row"><span class="label">Pickup</span><span class="val">'+b.pickupAddress+'</span></div>');
            w.document.write('<div class="row"><span class="label">Dropoff</span><span class="val">'+b.dropoffAddress+'</span></div>');
            if (b.airline) w.document.write('<div class="row"><span class="label">Flight</span><span class="val">'+b.airline+' '+b.flightNumber+'</span></div>');
            w.document.write('<div class="row"><span class="label">Date</span><span class="val">'+d+'</span></div>');
            w.document.write('<div class="row"><span class="label">Time</span><span class="val">'+b.timeSlot+'</span></div>');
            w.document.write('<div class="row"><span class="label">Driver</span><span class="val">#'+b.driverNumber+'</span></div>');
            w.document.write('<div class="row"><span class="label">Passengers</span><span class="val">'+b.passengers+' pax · '+b.luggage+' bags</span></div>');
            w.document.write('<div class="row"><span class="label">Trip</span><span class="val">'+(b.tripType==="round-trip"?"Round Trip":"One Way")+'</span></div>');
            w.document.write('<div class="row"><span class="label">Payment</span><span class="fare">$'+b.paymentAmount+'</span></div>');
            w.document.write('<p style="font-size:10px;color:#bbb;margin-top:16px;text-align:center;letter-spacing:0.06em">Generated '+new Date().toLocaleString()+'</p>');
            w.document.write('</body></html>');
            w.document.close(); setTimeout(() => w.print(), 300);
          }} style={{ padding: "6px 10px", borderRadius: 6, border: "1px solid #1c2035", background: "transparent", color: "var(--text-2)", fontSize: 13, cursor: "pointer" }} title="Print Slip">🖨</button>
          <button onClick={() => onDelete(b.id)} style={{ padding: "6px 10px", borderRadius: 6, border: "1px solid rgba(220,38,38,0.2)", background: "transparent", color: "#ef4444", fontSize: 13, cursor: "pointer" }}>🗑</button>
        </div>
      </div>
      {/* Info grid */}
      <div style={{ display: "grid", gridTemplateColumns: "auto 1fr 1fr", gap: "5px 14px", alignItems: "center" }}>
        <span style={{ background: "rgba(76,175,106,0.08)", border: "1px solid rgba(76,175,106,0.15)", borderRadius: 5, padding: "2px 9px", fontSize: 14, fontWeight: 700, color: "var(--green)", fontFamily: "var(--mono)", whiteSpace: "nowrap" }}>#{b.driverNumber || "–"}</span>
        <span style={{ fontSize: 15, color: "var(--text-1)", fontWeight: 500 }}>{b.customerName}</span>
        <span style={{ fontSize: 14, color: "var(--text-2)", fontFamily: "var(--mono)" }}>{b.phone || "–"}</span>
        <span style={{ fontSize: 13, color: "var(--text-3)", gridColumn: "1/4", paddingTop: 2 }}>
          <span style={{ color: "var(--text-2)" }}>{b.pickupAddress || "–"}</span>
          <span style={{ color: "var(--border-1)", margin: "0 6px" }}>→</span>
          <span style={{ color: "var(--text-2)" }}>{b.dropoffAddress || "–"}</span>
        </span>
        {b.airline && <span style={{ fontSize: 13, color: "var(--green)", fontFamily: "var(--mono)", gridColumn: "1/3" }}>✈ {b.airline} {b.flightNumber}{b.flightArrival ? ` · ETA ${b.flightArrival}` : ""}</span>}
        <span style={{ fontSize: 13, color: "var(--text-3)", fontFamily: "var(--mono)", gridColumn: b.airline ? "3" : "1/3" }}>{b.passengers}p · {b.luggage}b · {b.tripType === "round-trip" ? "RT" : "OW"}</span>
        <span style={{ fontSize: 15, fontWeight: 700, color: "var(--amber)", fontFamily: "var(--mono)", letterSpacing: "0.02em", gridColumn: "3" }}>{b.paymentAmount ? `$${b.paymentAmount}` : "–"}{b.fareBreakdown ? <span style={{ color: "var(--text-3)", fontSize: 11, fontWeight: 400 }}> {b.fareBreakdown}</span> : ""}</span>
      </div>
    </div>
  );
}

// ── Root entry point — GAS auth gate ──
export default function TaxiDispatcherApp() {
  return <DispatcherApp />;
}
