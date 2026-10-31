"""Shared canonical JSON codec. The recovery planner must not trust input checksums blindly."""
import hashlib
import json


def canonical_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def sha256_bytes(value):
    return hashlib.sha256(value).hexdigest()


def strict_json_bytes(value):
    def pairs(items):
        result = {}
        for k, v in items:
            if k in result:
                raise ValueError("duplicate key")
            result[k] = v
        return result

    return json.loads(value.decode("utf-8"), object_pairs_hook=pairs,
                      parse_float=lambda _: (_ for _ in ()).throw(ValueError("float")),
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError("constant")))
