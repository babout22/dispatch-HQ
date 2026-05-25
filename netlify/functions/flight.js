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

    const scheduled = f.arrival?.scheduled || "";
    const actual    = f.arrival?.actual || f.arrival?.estimated || "";
    const schDep    = f.departure?.scheduled || "";
    const actDep    = f.departure?.actual || f.departure?.estimated || "";

    const delayMin = f.arrival?.delay || 0;

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
        delay:            delayMin,
        scheduledArrival: scheduled,
        actualArrival:    actual,
        arrival:          f.arrival?.iata || "",
        departure:        f.departure?.iata || "",
        message:          "",
      }),
    };
  } catch (e) {
    return { statusCode: 502, headers, body: JSON.stringify({ found: false, error: e.message }) };
  }
};
