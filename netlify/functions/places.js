// Netlify Function — Places autocomplete proxy
// Calls Places API (New) server-side — no CORS, no browser key restrictions
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

  // Restrict autocomplete to NY + NJ — the dispatch service area. Places
  // Autocomplete has no native state-level filter (only country via
  // `components`), so we use a rectangle covering both states with
  // strictbounds=true to HARD-exclude results outside it (not just bias).
  // Rectangle: lat 38.70–45.10, lng -79.90–-71.70 — verified to fully contain
  // NY (40.4774–45.0159, -79.7624–-71.7517) and NJ (38.7880–41.3574,
  // -75.5595–-73.8850) with an ~0.08° margin at each extreme corner.
  // The corners necessarily spill slightly into neighboring PA/CT/MA/VT
  // border areas — Google has no arbitrary-polygon restriction, only
  // rectangle/circle, so a rectangle is the closest achievable fit.
  const NY_NJ_BOUNDS = "locationrestriction=rectangle:38.70,-79.90|45.10,-71.70&strictbounds=true";

  try {
    const resp = await fetch(
      `https://maps.googleapis.com/maps/api/place/autocomplete/json?input=${encodeURIComponent(input.trim())}&components=country:us&${NY_NJ_BOUNDS}&types=geocode|establishment&key=${key}`,
      { signal: AbortSignal.timeout(5000) }
    );
    const data = await resp.json();

    if (data.status !== "OK" && data.status !== "ZERO_RESULTS") {
      return { statusCode: 502, headers, body: JSON.stringify({ error: data.status, predictions: [] }) };
    }

    const predictions = (data.predictions || []).slice(0, 5).map(p => ({
      description: p.description,
      place_id: p.place_id,
      main_text: p.structured_formatting?.main_text || p.description,
      secondary_text: p.structured_formatting?.secondary_text || ""
    }));

    return { statusCode: 200, headers, body: JSON.stringify({ predictions }) };
  } catch (e) {
    return { statusCode: 502, headers, body: JSON.stringify({ error: e.message, predictions: [] }) };
  }
};
