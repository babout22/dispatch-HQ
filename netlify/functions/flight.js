exports.handler = async (event) => {
  const h = { "Access-Control-Allow-Origin": "*", "Content-Type": "application/json" };
  const flight = (event.queryStringParameters || {}).flight;
  if (!flight) return { statusCode: 400, headers: h, body: JSON.stringify({ error: "No flight" }) };
  const key = process.env.AVIATIONSTACK_KEY;
  if (!key) return { statusCode: 500, headers: h, body: JSON.stringify({ error: "No key" }) };
  try {
    const url = "http://api.aviationstack.com/v1/flights?access_key=" + key + "&flight_iata=" + flight.trim().toUpperCase() + "&limit=1";
    const resp = await fetch(url);
    const data = await resp.json();
    if (!data.data || !data.data.length) return { statusCode: 200, headers: h, body: JSON.stringify({ found: false }) };
    const f = data.data[0];
    const fmt = (iso) => { try { return new Date(iso).toLocaleTimeString("en-US", { hour: "numeric", minute: "2-digit", hour12: true }); } catch(e) { return iso || ""; } };
    const delay = f.arrival && f.arrival.delay ? f.arrival.delay : 0;
    const status = f.flight_status || "unknown";
    const arr = f.arrival || {};
    const arrivalTime = fmt(arr.actual || arr.estimated || arr.scheduled);
    const msg = delay > 0 ? "Delayed " + delay + " min, Arrives " + arrivalTime : status === "landed" ? "Landed, Arrived " + arrivalTime : "ETA " + arrivalTime;
    return { statusCode: 200, headers: h, body: JSON.stringify({ found: true, flight: (f.flight && f.flight.iata) || flight, airline: (f.airline && f.airline.name) || "", status: status, delay_minutes: delay, arrivalTime: arrivalTime, message: msg }) };
  } catch(e) {
    return { statusCode: 502, headers: h, body: JSON.stringify({ error: e.message }) };
  }
};
