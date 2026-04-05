const isBrowser = typeof window !== "undefined";
const origin = isBrowser ? window.location.origin : "http://localhost:3000";
const host = isBrowser ? window.location.host : "localhost:3000";
const hostname = isBrowser ? window.location.hostname : "localhost";
const protocol = isBrowser ? window.location.protocol : "http:";
const wsProtocol = protocol === "https:" ? "wss" : "ws";

export const API_URL =
  import.meta.env.VITE_API_URL ||
  (import.meta.env.DEV ? `http://${hostname}:8000` : origin);

export const WS_URL =
  import.meta.env.VITE_WS_URL ||
  (import.meta.env.DEV ? `${wsProtocol}://${hostname}:8000/ws` : `${wsProtocol}://${host}/ws`);

const API_KEY = import.meta.env.VITE_API_KEY?.trim();

export function buildApiHeaders(extraHeaders = {}) {
  if (!API_KEY) {
    return extraHeaders;
  }
  return { ...extraHeaders, "X-API-Key": API_KEY };
}
