var ADDRESS = "x";
var TOKEN = "x";
var WORKER_ADDRESS = "https://alist-243004.243004.xyz";

// Upload settings may also be supplied through Cloudflare environment bindings.
// UPLOAD_TOKEN must match the GuangYaPan storage's upload_proxy_token.
var UPLOAD_TOKEN = "";

const UPLOAD_PATH = "/__openlist_upload";
const TARGET_HEADER = "X-OpenList-Upload-Target";
const HEADERS_HEADER = "X-OpenList-Upload-Headers";
const SIGN_HEADER = "X-OpenList-Upload-Sign";

function getConfig(env = {}) {
  // Resolve per request: never put environment credentials into shared globals.
  return {
    ADDRESS: env.ADDRESS ?? ADDRESS,
    TOKEN: env.TOKEN ?? TOKEN,
    WORKER_ADDRESS: env.WORKER_ADDRESS ?? WORKER_ADDRESS,
    UPLOAD_TOKEN: env.UPLOAD_TOKEN ?? UPLOAD_TOKEN
  };
}

function jsonError(status, message) {
  return new Response(JSON.stringify({ code: status, message }), {
    status,
    headers: {
      "content-type": "application/json;charset=UTF-8",
      "cache-control": "no-store"
    }
  });
}

function decodeBase64URL(value) {
  return Uint8Array.from(atob(value.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
}

// src/verify.ts
var verify = async (data, _sign, token = TOKEN, requireExpiry = false) => {
  const signSlice = _sign.split(":");
  const expiryText = signSlice[signSlice.length - 1];
  if (signSlice.length < 2 || !expiryText) {
    return "expire missing";
  }
  const expire = Number(expiryText);
  if (!/^\d+$/.test(expiryText) || !Number.isSafeInteger(expire)) {
    return "expire invalid";
  }
  if (requireExpiry && expire === 0) return "expire missing";
  if (expire < Date.now() / 1e3 && expire > 0) {
    return "expire expired";
  }
  // Keep the original HMAC format, while letting Web Crypto compare signatures.
  const key = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(token),
    { name: "HMAC", hash: "SHA-256" }, false, ["verify"]
  );
  try {
    const valid = await crypto.subtle.verify(
      "HMAC", key, decodeBase64URL(signSlice.slice(0, -1).join(":")),
      new TextEncoder().encode(`${data}:${expire}`)
    );
    return valid ? "" : "sign mismatch";
  } catch {
    return "sign mismatch";
  }
};

// Signed OSS upload requests from drivers/guangyapan/upload_proxy.go.
async function handleUpload(request, config) {
  if (!["PUT", "POST", "DELETE"].includes(request.method)) {
    return jsonError(405, "upload method not allowed");
  }
  if (!config.UPLOAD_TOKEN) {
    return jsonError(503, "configure UPLOAD_TOKEN");
  }
  const targetText = request.headers.get(TARGET_HEADER) || "";
  const encodedHeaders = request.headers.get(HEADERS_HEADER) || "";
  const error = await verify(
    `${request.method}\n${targetText}\n${encodedHeaders}`,
    request.headers.get(SIGN_HEADER) || "", config.UPLOAD_TOKEN, true
  );
  if (error) return jsonError(401, error);

  let target;
  let headers;
  try {
    target = new URL(targetText);
    const originalHeaders = JSON.parse(new TextDecoder().decode(decodeBase64URL(encodedHeaders)));
    headers = new Headers();
    for (const [name, values] of Object.entries(originalHeaders)) {
      if (!Array.isArray(values) || values.some((value) => typeof value !== "string")) {
        return jsonError(400, "invalid upload headers");
      }
      for (const value of values) headers.append(name, value);
    }
  } catch {
    return jsonError(400, "invalid upload target or headers");
  }
  if (target.protocol !== "https:" || target.username || target.password || target.port || target.hash) {
    return jsonError(400, "upload target must be an HTTPS URL on port 443");
  }
  // Reconstruct OSS headers from the signed envelope. Download-only custom
  // headers and client credentials must not be mixed into OSS authentication.
  for (const name of ["Host", "Connection", "Transfer-Encoding", "Cookie", "Origin", "Referer"]) {
    headers.delete(name);
  }
  headers.set("Accept-Encoding", "identity");
  const lengthText = headers.get("Content-Length") || "";
  const length = Number(lengthText);
  if (!/^\d+$/.test(lengthText) || !Number.isSafeInteger(length)) {
    return jsonError(400, "upload requires a known Content-Length");
  }
  if (length > 0 && !request.body) return jsonError(400, "missing upload body");
  let body = length === 0 ? null : request.body;
  // Workers derives Content-Length from the body stream; it ignores a manually
  // assigned length for unknown-length streams. This does not buffer the part.
  if (body && typeof FixedLengthStream === "function") {
    const fixed = new FixedLengthStream(length);
    body.pipeTo(fixed.writable).catch(() => {}); // The readable also receives pipe failures.
    body = fixed.readable;
  }
  const upstream = await fetch(target.href, {
    method: request.method, headers, body, redirect: "manual"
  });
  if (upstream.status >= 300 && upstream.status < 400) {
    await upstream.body?.cancel();
    return jsonError(502, "OSS upload redirect refused");
  }
  const response = new Response(upstream.body, upstream);
  response.headers.delete("set-cookie");
  response.headers.set("cache-control", "no-store");
  return response;
}

// src/handleDownload.ts
async function handleDownload(request, config, depth = 0) {
  if (!["GET", "HEAD", "POST"].includes(request.method)) return jsonError(405, "download method not allowed");
  if (!config.ADDRESS || !config.TOKEN) return jsonError(503, "configure ADDRESS and TOKEN");
  if (depth >= 10) return jsonError(502, "too many download redirects");
  const origin = request.headers.get("origin") ?? "*";
  const url = new URL(request.url);
  let path;
  try {
    path = decodeURIComponent(url.pathname);
  } catch {
    return jsonError(400, "invalid download path");
  }
  const sign = url.searchParams.get("sign") ?? "";
  const verifyResult = await verify(path, sign, config.TOKEN);
  if (verifyResult !== "") {
    const resp2 = new Response(
      JSON.stringify({
        code: 401,
        message: verifyResult
      }),
      {
        status: 401,
        headers: {
          "content-type": "application/json;charset=UTF-8"
        }
      }
    );
    resp2.headers.set("Access-Control-Allow-Origin", origin);
    return resp2;
  }
  let resp = await fetch(`${config.ADDRESS.replace(/\/+$/, "")}/api/fs/link`, {
    method: "POST",
    headers: {
      "content-type": "application/json;charset=UTF-8",
      Authorization: config.TOKEN
    },
    body: JSON.stringify({
      path
    }),
    redirect: "error"
  });
  if (!resp.ok) {
    await resp.body?.cancel();
    return jsonError(502, `OpenList link API returned HTTP ${resp.status}`);
  }
  let res = await resp.json();
  if (res.code !== 200 || !res.data?.url) {
    const status = Number.isInteger(res.code) && res.code >= 400 && res.code <= 599 ? res.code : 502;
    return jsonError(status, res.message || "OpenList link API returned no download URL");
  }
  request = new Request(res.data.url, request);
  // Remove client credentials before applying headers supplied by the driver.
  for (const name of ["Host", "Content-Length", "Cookie", "Referer", "Origin", "Authorization", TARGET_HEADER, HEADERS_HEADER, SIGN_HEADER]) {
    request.headers.delete(name);
  }
  if (res.data.header) {
    for (const k in res.data.header) {
      for (const v of res.data.header[k]) {
        request.headers.set(k, v);
      }
    }
  }
  // 伪造地区头
  request.headers.set("Accept-Language", "en-US,en;q=0.9");

  // 伪造IP头
  request.headers.set("X-Forwarded-For", "20.27.43.217"); // 替换为你想要的IP地址
  request.headers.set("X-Real-IP", "20.27.43.217"); // 替换为你想要的IP地址
  request = new Request(request, { redirect: "manual" });
  let response = await fetch(request);
  while (response.status >= 300 && response.status < 400) {
    const location = response.headers.get("Location");
    if (location) {
      await response.body?.cancel();
      if (++depth >= 10) return jsonError(502, "too many download redirects");
      const target = new URL(location, request.url);
      const worker = new URL(config.WORKER_ADDRESS || url.origin);
      if (target.origin === worker.origin) {
        request = new Request(target.href, request);
        return await handleDownload(request, config, depth);
      } else {
        request = new Request(target.href, request);
        response = await fetch(request);
      }
    } else {
      break;
    }
  }
  response = new Response(response.body, response);
  response.headers.delete("set-cookie");
  response.headers.set("Access-Control-Allow-Origin", origin);
  response.headers.append("Vary", "Origin");
  return response;
}


// src/handleOptions.ts
function handleOptions(request) {
  const corsHeaders = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET,HEAD,POST,OPTIONS",
    "Access-Control-Max-Age": "86400"
  };
  let headers = request.headers;
  if (headers.get("Origin") !== null && headers.get("Access-Control-Request-Method") !== null) {
    let respHeaders = {
      ...corsHeaders,
      "Access-Control-Allow-Headers": request.headers.get("Access-Control-Request-Headers") || ""
    };
    return new Response(null, {
      headers: respHeaders
    });
  } else {
    return new Response(null, {
      headers: {
        Allow: "GET, HEAD, POST, OPTIONS"
      }
    });
  }
}

// src/handleRequest.ts
async function handleRequest(request, config) {
  if (new URL(request.url).pathname === UPLOAD_PATH) {
    try {
      return await handleUpload(request, config);
    } catch {
      return jsonError(502, "upload proxy request failed");
    }
  }
  let response;
  try {
    response = request.method === "OPTIONS"
      ? handleOptions(request)
      : await handleDownload(request, config);
  } catch {
    response = jsonError(502, "download proxy request failed");
  }
  response.headers.set("Access-Control-Allow-Origin", request.headers.get("Origin") || "*");
  response.headers.set("Access-Control-Expose-Headers", "Content-Length, Content-Range, Accept-Ranges, ETag");
  if (!(response.headers.get("Vary") || "").split(",").some((value) => value.trim().toLowerCase() === "origin")) {
    response.headers.append("Vary", "Origin");
  }
  return response;
}

// src/index.ts
var src_default = {
  async fetch(request, env, ctx) {
    return await handleRequest(request, getConfig(env));
  }
};
export {
  src_default as default
};
