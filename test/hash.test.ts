import test from "node:test";
import assert from "node:assert/strict";
import { hashCanonical, sha256Text } from "../src/hash.js";

test("hashCanonical uses canonical key ordering and protocol sha256 wire form", () => {
  const a = hashCanonical({ verb: "verify", family: "trust", version: "1.0.0" });
  const b = hashCanonical({ version: "1.0.0", family: "trust", verb: "verify" });
  assert.equal(a, b);
  assert.equal(a, "sha256:7f84cc113290c283fe97e3beb9bd3f65e5de0022e278cad25ef7619c398b1bab");
});

test("sha256Text hashes exact UTF-8 text", () => {
  assert.equal(sha256Text("{}"), "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a");
});
