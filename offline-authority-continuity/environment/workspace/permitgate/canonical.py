"""Strict JSON and canonical-byte helpers for the synthetic signed-bundle protocol.

These utilities do NOT implement authorization, signature verification or the grader.
"""
import hashlib
import json
import math

class DuplicateJSONKey(ValueError):
    pass

def reject_duplicate_pairs(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise DuplicateJSONKey(f"duplicate JSON key: {key}")
        obj[key] = value
    return obj

def reject_non_json_constant(value):
    raise ValueError(f"non-JSON numeric constant: {value}")

def _parse_finite_float(token):
    value = float(token)
    if not math.isfinite(value):
        raise ValueError("non-finite JSON number")
    return value

def _reject_unpaired_surrogates(value):
    if isinstance(value, str):
        if any(0xD800 <= ord(ch) <= 0xDFFF for ch in value):
            raise ValueError("unpaired surrogate code point")
    elif isinstance(value, dict):
        for key, item in value.items():
            _reject_unpaired_surrogates(key)
            _reject_unpaired_surrogates(item)
    elif isinstance(value, list):
        for item in value:
            _reject_unpaired_surrogates(item)

def parse_line(line):
    obj = json.loads(line, object_pairs_hook=reject_duplicate_pairs,
                     parse_constant=reject_non_json_constant,
                     parse_float=_parse_finite_float)
    _reject_unpaired_surrogates(obj)
    return obj

def canonical_json(obj):
    return json.dumps(obj, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False, allow_nan=False).encode('utf-8')

def content_hash(obj):
    return hashlib.sha256(canonical_json(obj)).hexdigest()
