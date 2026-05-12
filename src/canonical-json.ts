// RFC 8785 JSON Canonicalization Scheme (JCS), restricted to the value
// space A2A-IDF attestations and delegation payloads actually use:
// null, booleans, strings, integers, arrays, and objects.
//
// Full RFC 8785 also covers non-integer numbers via IEEE 754 → ECMAScript
// `Number.prototype.toString` with a few carve-outs. A2A-IDF payloads only
// hold integers (timestamps, depths, expiry seconds), so we reject any
// non-integer number explicitly rather than risk a subtly-non-canonical
// serialization. Promote to full JCS in a follow-up when fractional
// numbers actually appear in fixtures.

export function canonicalize(value: unknown): string {
  return serialize(value);
}

function serialize(v: unknown): string {
  if (v === null) return "null";
  switch (typeof v) {
    case "boolean":
      return v ? "true" : "false";
    case "string":
      return serializeString(v);
    case "number":
      if (!Number.isInteger(v)) {
        throw new Error(
          `canonical-json: non-integer numbers not supported at MVP (got ${v})`,
        );
      }
      return v.toString();
    case "object":
      if (Array.isArray(v)) return serializeArray(v);
      return serializeObject(v as Record<string, unknown>);
    default:
      throw new Error(`canonical-json: unsupported value type ${typeof v}`);
  }
}

function serializeArray(arr: unknown[]): string {
  return "[" + arr.map(serialize).join(",") + "]";
}

function serializeObject(obj: Record<string, unknown>): string {
  // RFC 8785 §3.2.3: keys sorted by UTF-16 code-unit values.
  // Note: JS string compare on objects with `<` uses the same UTF-16 order.
  const keys = Object.keys(obj).sort();
  const parts: string[] = [];
  for (const k of keys) {
    const v = obj[k];
    if (v === undefined) continue;
    parts.push(serializeString(k) + ":" + serialize(v));
  }
  return "{" + parts.join(",") + "}";
}

function serializeString(s: string): string {
  // RFC 8785 §3.2.2 references ECMA-262 § 24.5.2.2 (JSON.stringify) for
  // string escapes. `JSON.stringify(s)` produces exactly that output.
  return JSON.stringify(s);
}
