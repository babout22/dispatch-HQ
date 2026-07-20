// Netlify Function — Places Autocomplete (New) proxy
// Uses the actual "Places API (New)" endpoint (POST + JSON), which is the
// only Google Places tier that supports a real locationRestriction.rectangle
// hard filter. The legacy `maps/api/place/autocomplete/json` GET endpoint
// (previously used here) does NOT recognize a rectangle restriction — it
// silently ignores unknown query params, which is why an earlier attempt at
// this fix compiled and ran with no error but filtered nothing at all.
exports.handler = async (event) => {
  const headers = {
    "Access-Control-Allow-Origin": "*",
    "Content-Type": "application/json"
  };

  if (event.httpMethod !== "GET") {
    return { statusCode: 405, headers, body: JSON.stringify({ error: "Method not allowed" }) };
  }

  const input = (event.queryStringParameters || {}).input;
  if (!input || input.trim().length < 2) {
    return { statusCode: 400, headers, body: JSON.stringify({ predictions: [] }) };
  }

  const key = process.env.GOOGLE_MAPS_KEY;
  if (!key) {
    return { statusCode: 500, headers, body: JSON.stringify({ error: "Maps key not configured" }) };
  }

  // NY + NJ hard-restriction rectangle. Verified to fully contain
  // NY (40.4774–45.0159, -79.7624–-71.7517) and NJ (38.7880–41.3574,
  // -75.5595–-73.8850) with an ~0.08° margin at every extreme corner.
  // Corners necessarily spill slightly into bordering PA/CT/MA/VT —
  // Google's rectangle restriction has no arbitrary-polygon option, so this
  // is the closest achievable fit to "NY and NJ only".
  const body = {
    input: input.trim(),
    includedRegionCodes: ["us"],
    locationRestriction: {
      rectangle: {
        low:  { latitude: 38.70, longitude: -79.90 },
        high: { latitude: 45.10, longitude: -71.70 }
      }
    }
  };

  try {
    const resp = await fetch("https://places.googleapis.com/v1/places:autocomplete", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Goog-Api-Key": key
      },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(5000)
    });
    const data = await resp.json();

    if (!resp.ok) {
      return { statusCode: 502, headers, body: JSON.stringify({ error: (data.error && data.error.message) || "Places API error", predictions: [] }) };
    }

    // Map the New API's { suggestions: [{ placePrediction: {...} }] } shape
    // back to the { predictions: [...] } shape the client already expects,
    // so AddressField needs zero changes. Defensive: a single malformed or
    // null entry in Google's array must not kill the whole response — skip
    // it and keep the good ones (same principle as the driver/voice hardening
    // elsewhere in this app: never trust external data to be well-shaped).
    const predictions = (Array.isArray(data.suggestions) ? data.suggestions : [])
      .filter(s => {
        const pp = s && typeof s === "object" ? s.placePrediction : null;
        if (!pp || typeof pp !== "object") return false;
        // Require actual usable content — an empty {} object is shape-valid
        // but would render as a blank row in the dropdown.
        return !!(pp.placeId || (pp.text && pp.text.text));
      })
      .slice(0, 5)
      .map(s => {
        const pp = s.placePrediction;
        return {
          description: (pp.text && pp.text.text) || "",
          place_id: pp.placeId || "",
          main_text: (pp.structuredFormat && pp.structuredFormat.mainText && pp.structuredFormat.mainText.text) || (pp.text && pp.text.text) || "",
          secondary_text: (pp.structuredFormat && pp.structuredFormat.secondaryText && pp.structuredFormat.secondaryText.text) || ""
        };
      });

    return { statusCode: 200, headers, body: JSON.stringify({ predictions }) };
  } catch (e) {
    return { statusCode: 502, headers, body: JSON.stringify({ error: e.message, predictions: [] }) };
  }
};
