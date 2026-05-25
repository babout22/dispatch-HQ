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

    const statusRaw = f.flight_status === "landed"    ? "landed"
                    : f.flight_status === "active"    ? "active"
                    : f.flight_status === "scheduled" ? "scheduled"
                    : f.flight_status === "cancelled" ? "cancelled"
                    : f.flight_status === "diverted"  ? "diverted"
                    : "unknown";

    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({
        found:            true,
        flight:           f.flight?.iata || flight,
        airline:          f.airline?.name || "",
        statusRaw,
        delay:            f.arrival?.delay || 0,
        scheduledArrival: f.arrival?.scheduled || "",
        actualArrival:    f.arrival?.actual || f.arrival?.estimated || "",
        arrival:          f.arrival?.iata || "",
        departure:        f.departure?.iata || "",
        message:          "",
      }),
    };
  } catch (e) {
    return { statusCode: 502, headers, body: JSON.stringify({ error: e.message }) };
  }
};
