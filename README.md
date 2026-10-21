# sctp-chunk-header-parser

Parses and constructs SCTP chunk headers and parameter TLVs from raw bytes.

```python
from sctp_chunk_header_parser import (
    parse_chunk_header, build_chunk_header,
    parse_parameter_tlv, build_parameter_tlv,
)

header, next_off = parse_chunk_header(b"\x01\x00\x00\x04")
print(header.chunk_type, header.flags, header.length)  # 1 0 4

wire = build_chunk_header(1, 0, b"ABC")  # b'\x01\x00\x00\x07ABC\x00'
param, off = parse_parameter_tlv(build_parameter_tlv(0x8001, b"V"))
print(hex(param.param_type), param.value)  # 0x8001 b'V'
```

## Why this exists

Working with an SCTP capture means walking a chain of chunks and parameters, each a TLV whose length field counts only the unpadded bytes while the value is padded to a four-byte boundary. Doing that by hand is repetitive and error-prone; this library does the bookkeeping and nothing else — no sockets, no checksums, no association state.

The trade-off: parsing preserves the on-wire length field verbatim instead of “fixing” it, so a caller can inspect malformed captures. A header whose length is below the 4-byte header size or exceeds the remaining buffer is returned with `valid_length=False` rather than raising. Building, by contrast, always computes the length from the value, because the length field is a derived value there.

## The awkward edge

The `valid_length` property is a sanity check, not a correctness guarantee: it confirms the length is at least the header size and at most the padded value size, but it does not validate chunk types, parameter types, or semantics. A capture that declares a plausible length for an unknown chunk type will still parse as `valid_length=True`.

## Design notes

The window stores values eagerly rather than keeping running aggregates. Running
sums drift with floating point over long streams, and recomputing from a small
buffer is cheap enough that the drift is not worth the speed.

