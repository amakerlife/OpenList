import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import test from "node:test";
import worker from "./worker.mjs";

const host = "example-bucket.oss-cn-example.aliyuncs.com";
const env = {
  ADDRESS: "https://openlist.example.com",
  TOKEN: "test-openlist-token",
  UPLOAD_TOKEN: "test-upload-secret",
};

// Match pkg/sign.HMACSign: padded URL-safe Base64, followed by :expiry.
function sign(data, token, expiry = Math.floor(Date.now() / 1000) + 300) {
  return createHmac("sha256", token).update(`${data}:${expiry}`).digest("base64")
    .replace(/\+/g, "-").replace(/\//g, "_") + `:${expiry}`;
}

function uploadRequest({
  method = "PUT", target = `https://${host}/folder/a%20b?partNumber=1&uploadId=a%2Bb`,
  body = "abc", expiry, token = env.UPLOAD_TOKEN,
} = {}) {
  const originalHeaders = {
    Authorization: ["OSS example-access-key:original-signature"],
    "X-Oss-Security-Token": ["temporary-session-token"],
    "X-Oss-Date": ["Tue, 06 Oct 2026 00:00:00 GMT"],
    "Content-Type": ["application/octet-stream"],
    "Content-Length": [String(Buffer.byteLength(body))],
  };
  const encoded = Buffer.from(JSON.stringify(originalHeaders)).toString("base64url");
  return new Request("https://worker.example.com/__openlist_upload", {
    method,
    body: method === "GET" ? undefined : body || undefined,
    headers: {
      "X-OpenList-Upload-Target": target,
      "X-OpenList-Upload-Headers": encoded,
      "X-OpenList-Upload-Sign": sign(`${method}\n${target}\n${encoded}`, token, expiry),
      // These simulated ingress headers must never replace the signed headers.
      Authorization: "untrusted-client-authorization",
      "X-Oss-Date": "changed-on-ingress",
      Cookie: "client-cookie=private",
    },
  });
}

test("upload streams the body and preserves OSS request and response metadata", async (t) => {
  const request = uploadRequest();
  const originalBody = request.body;
  const fetchMock = t.mock.method(globalThis, "fetch", async (url, init) => {
    assert.equal(url, `https://${host}/folder/a%20b?partNumber=1&uploadId=a%2Bb`);
    assert.equal(init.method, "PUT");
    assert.equal(init.redirect, "manual");
    assert.equal(init.body, originalBody);
    assert.equal(init.headers.get("Authorization"), "OSS example-access-key:original-signature");
    assert.equal(init.headers.get("X-Oss-Date"), "Tue, 06 Oct 2026 00:00:00 GMT");
    assert.equal(init.headers.get("X-Oss-Security-Token"), "temporary-session-token");
    assert.equal(init.headers.get("Content-Length"), "3");
    assert.equal(init.headers.get("Cookie"), null);
    assert.equal(init.headers.get("X-OpenList-Upload-Sign"), null);
    assert.equal(await new Response(init.body).text(), "abc");
    return new Response("", { headers: { ETag: '"part-etag"', "X-Oss-Hash-Crc64ecma": "12345" } });
  });
  const response = await worker.fetch(request, env);
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("ETag"), '"part-etag"');
  assert.equal(response.headers.get("X-Oss-Hash-Crc64ecma"), "12345");
  assert.equal(response.headers.get("Cache-Control"), "no-store");
  assert.equal(fetchMock.mock.callCount(), 1);
});

test("upload also forwards initiation, completion, abort and empty objects", async (t) => {
  for (const [method, query, body] of [
    ["POST", "?uploads", ""], ["POST", "?uploadId=example", "<CompleteMultipartUpload/>"],
    ["DELETE", "?uploadId=example", ""], ["PUT", "", ""],
  ]) {
    await t.test(`${method} ${query || "empty object"}`, async (t) => {
      t.mock.method(globalThis, "fetch", async (url, init) => {
        assert.equal(url, `https://${host}/file${query}`);
        assert.equal(init.method, method);
        assert.equal(await new Response(init.body).text(), body);
        return new Response("<Result/>", { status: 200 });
      });
      const response = await worker.fetch(uploadRequest({ method, target: `https://${host}/file${query}`, body }), env);
      assert.equal(response.status, 200);
      assert.equal(await response.text(), "<Result/>");
    });
  }
});

test("upload rejects invalid authentication and destinations before fetch", async (t) => {
  const cases = [
    ["wrong key", { token: "wrong" }, 401],
    ["expired", { expiry: 1 }, 401],
    ["no expiry", { expiry: 0 }, 401],
    ["HTTP endpoint", { target: `http://${host}/file` }, 400],
    ["unexpected port", { target: `https://${host}:8443/file` }, 400],
    ["URL credentials", { target: `https://user:password@${host}/file` }, 400],
    ["download via upload endpoint", { method: "GET" }, 405],
  ];
  for (const [name, options, status] of cases) {
    await t.test(name, async (t) => {
      const mock = t.mock.method(globalThis, "fetch", () => assert.fail("must not fetch"));
      const response = await worker.fetch(uploadRequest(options), env);
      assert.equal(response.status, status);
      assert.equal(mock.mock.callCount(), 0);
    });
  }
  for (const header of ["X-OpenList-Upload-Target", "X-OpenList-Upload-Headers"]) {
    const request = uploadRequest();
    request.headers.set(header, "tampered");
    assert.equal((await worker.fetch(request, env)).status, 401);
  }
});

test("upload requires configured credentials", async () => {
  assert.equal((await worker.fetch(uploadRequest(), { ...env, UPLOAD_TOKEN: "" })).status, 503);
});

test("upload returns OSS errors and refuses redirects", async (t) => {
  for (const status of [403, 503, 307]) {
    await t.test(String(status), async (t) => {
      const mock = t.mock.method(globalThis, "fetch", async () => new Response("<Error>OSS error</Error>", {
        status, headers: { Location: "https://other.example.com", "X-Oss-Request-Id": "request-id" },
      }));
      const response = await worker.fetch(uploadRequest(), env);
      assert.equal(response.status, status === 307 ? 502 : status);
      if (status !== 307) {
        assert.equal(response.headers.get("X-Oss-Request-Id"), "request-id");
        assert.equal(await response.text(), "<Error>OSS error</Error>");
      }
      assert.equal(mock.mock.callCount(), 1);
    });
  }
});

function downloadRequest(path, options = {}) {
  return new Request(`https://worker.example.com${encodeURI(path)}?sign=${sign(path, env.TOKEN, 0)}`, options);
}

test("downloads retain path signing, ranges and required driver headers", async (t) => {
  const path = "/源盘/文件 + %.bin";
  const mock = t.mock.method(globalThis, "fetch", async (url, init) => {
    if (url instanceof Request) {
      init = url;
      url = url.url;
    }
    if (url === `${env.ADDRESS}/api/fs/link`) {
      assert.equal(JSON.parse(init.body).path, path);
      assert.equal(init.headers.Authorization, env.TOKEN);
      return Response.json({ code: 200, data: {
        url: "https://download.example.com/file",
        header: { Cookie: ["required-source-cookie"], Referer: ["https://source.example.com"] },
      } });
    }
    assert.equal(url, "https://download.example.com/file");
    assert.equal(init.headers.get("Range"), "bytes=1-3");
    assert.equal(init.headers.get("Cookie"), "required-source-cookie");
    assert.equal(init.headers.get("Authorization"), null);
    assert.equal(init.headers.get("Accept-Language"), "en-US,en;q=0.9");
    assert.equal(init.headers.get("X-Forwarded-For"), "20.27.43.217");
    assert.equal(init.headers.get("X-Real-IP"), "20.27.43.217");
    return new Response("bcd", { status: 206, headers: { "Content-Range": "bytes 1-3/10", "Set-Cookie": "private" } });
  });
  const response = await worker.fetch(downloadRequest(path, {
    headers: { Range: "bytes=1-3", Authorization: "client-secret", Origin: "https://ui.example.com" },
  }), env);
  assert.equal(response.status, 206);
  assert.equal(await response.text(), "bcd");
  assert.equal(response.headers.get("Content-Range"), "bytes 1-3/10");
  assert.equal(response.headers.get("Set-Cookie"), null);
  assert.equal(response.headers.get("Access-Control-Allow-Origin"), "https://ui.example.com");
  assert.equal(mock.mock.callCount(), 2);
});

test("download signature and API errors use real HTTP error codes", async (t) => {
  const wrong = new Request(`https://worker.example.com/file?sign=${sign("/wrong", env.TOKEN)}`);
  const response = await worker.fetch(wrong, env);
  assert.equal(response.status, 401);
  assert.equal(await response.text(), '{"code":401,"message":"sign mismatch"}');
  t.mock.method(globalThis, "fetch", async () => Response.json({ code: 403, message: "permission denied" }));
  assert.equal((await worker.fetch(downloadRequest("/file"), env)).status, 403);
});

test("download HEAD, OPTIONS and relative redirects remain supported", async (t) => {
  const mock = t.mock.method(globalThis, "fetch", async (url, init) => {
    if (url instanceof Request) {
      init = url;
      url = url.url;
    }
    if (url === `${env.ADDRESS}/api/fs/link`) {
      return Response.json({ code: 200, data: { url: "https://download.example.com/old" } });
    }
    assert.equal(init.method, "HEAD");
    if (url.endsWith("/old")) return new Response(null, { status: 302, headers: { Location: "/new" } });
    assert.equal(url, "https://download.example.com/new");
    return new Response(null, { headers: { "Content-Length": "100" } });
  });
  const response = await worker.fetch(downloadRequest("/file", { method: "HEAD" }), env);
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("Content-Length"), "100");
  assert.equal(mock.mock.callCount(), 3);
  const options = await worker.fetch(new Request("https://worker.example.com/file", { method: "OPTIONS" }), env);
  assert.equal(options.status, 200);
  assert.equal(mock.mock.callCount(), 3);
});
