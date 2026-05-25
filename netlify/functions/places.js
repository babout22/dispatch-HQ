exports.handler = async (event) => {
  const headers = {
    "Access-Control-Allow-Origin": "*",
    "Content-Type": "application/json",
  };

  if (event.httpMethod === "OPTIONS") {
    return { statusCode: 200, headers, body: "" };
  }

  const input = event.queryStringParameters?.input || "";
  if (!input || input.length < 2) {
    return { statusCode: 400, headers, body: JSON.stringify({ error: "input required", predictions: [] }) };
  }

  const key = process.env.GOOGLE_MAPS_KEY;
  if (!key) {
    return { statusCode: 500, headers, body: JSON.stringify({ error: "Maps key not configured", predictions: [] }) };
  }

  try {
    const url = `https://maps.googleapis.com/maps/api/place/autocomplete/json?input=${encodeURIComponent(input)}&key=${key}&components=country:us&types=address&language=en`;
    const resp = await fetch(url);
    const data = await resp.json();

    if (data.status !== "OK" && data.status !== "ZERO_RESULTS") {
      return { statusCode: 200, headers, body: JSON.stringify({ error: data.status, predictions: [] }) };
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
