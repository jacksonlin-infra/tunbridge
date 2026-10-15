import assert from "node:assert/strict";
import { Readable, Writable } from "node:stream";
import { pipeline } from "node:stream/promises";
import test from "node:test";

import { exactByteCount } from "../fetch-macos-mihomo.mjs";

function sink() {
  return new Writable({
    write(_chunk, _encoding, callback) {
      callback();
    },
  });
}

test("locked download size accepts the exact byte count", async () => {
  await pipeline(
    Readable.from([Buffer.from("abc"), Buffer.from("def")]),
    exactByteCount(6),
    sink(),
  );
});

test("locked download size rejects truncated and oversized responses", async () => {
  await assert.rejects(
    pipeline(Readable.from([Buffer.from("short")]), exactByteCount(6), sink()),
    /did not match locked archive size/,
  );
  await assert.rejects(
    pipeline(Readable.from([Buffer.from("toolong")]), exactByteCount(6), sink()),
    /exceeded locked archive size/,
  );
});
