const fmt = (iso) => {
  if (!iso) return "";
  try {
    return new Date(iso).toLocaleTimeString("en-US", { hour: "numeric", minute: "2-digit", hour12: true, timeZone: "America/New_York" });
  } catch { return iso; }
};

exports.handler = async (event) => {
  const headers = {
    "Access-Control-Allow-Origin": "*",
    "Content-Type": "application/json",
  };

  if (event.httpMethod === "OPTIONS") {
    return { statusCode: 200, headers, body: "" };
  }

  const flight = (event.queryStringParameters?.flight || "").toUpperCase().replace(/\s+/g, "");
  if (!flight) {
    return { statusCode: 400, headers, body: JSON.stringify({ found: false, error: "flight param required" }) };
  }

  const key = process.env.AVIATIONSTACK_KEY;
  if (!key) {
    return { statusCode: 500, headers, body: JSON.stringify({ found: false, error: "Flight API key not configured" }) };
  }

  try {
    const url = `http://api.aviationstack.com/v1/flights?access_key=${key}&flight_iata=${encodeURIComponent(flight)}&limit=1`;
    const resp = await fetch(url);
    const data = await resp.json();

    const f = data?.data?.[0];
    if (!f) {
      return { statusCode: 200, headers, body: JSON.stringify({ found: false, flight }) };
    }

    const delay = f.arrival?.delay || 0;
    const status = f.flight_status || "unknown";
    const arrivalTime = fmt(f.arrival?.actual || f.arrival?.estimated || f.arrival?.scheduled);

    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({
        found: true,
        flight: f.flight?.iata || flight,
        airline: f.airline?.name || "",
        status,
        delay_minutes: delay,
        arrivalTime,
        message: delay > 0 ? "Delayed " + delay + " min, Arrives " + arrivalTime
                : status === "landed" ? "Landed, Arrived " + arrivalTime
                : "ETA " + arrivalTime,
      }),
    };
  } catch (e) {
    return { statusCode: 502, headers, body: JSON.stringify({ error: e.message }) };
  }
};
