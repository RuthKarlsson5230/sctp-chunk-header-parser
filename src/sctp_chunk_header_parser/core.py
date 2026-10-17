"""Parse and construct SCTP chunk headers and parameter TLVs from raw bytes.

SCTP (RFC 4960) packs chunk headers and parameters as TLV (Type-Length-Value)
triples.  Both share the same shape: a 16-bit type, a 16-bit length that covers
the header plus the value, and a value field padded to a four-byte boundary.

The length field counts the *unpadded* bytes (type + length + value).  When we
parse we preserve that length verbatim so callers can inspect a capture exactly
as it appeared on the wire, including malformed lengths.  When we build we
compute the length from the value and add the padding.

Ambiguity resolved: RFC 4960 says the length includes the header bytes.  Some
legacy captures carry a length that is too short (fewer than 4) or that exceeds
the remaining buffer.  We return those as-is with ``valid_length=False`` rather
than raising, because the whole point of this library is to let a caller walk
a capture and decide what to do with each malformed entry.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Tuple


HEADER_SIZE = 4
WORD_ALIGN = 4


def _padded_len(value_len: int) -> int:
    """Return the number of bytes ``value_len`` occupies including padding."""
    remainder = value_len % WORD_ALIGN
    if remainder == 0:
        return value_len
    return value_len + (WORD_ALIGN - remainder)


def _u16_be(buf: bytes, offset: int) -> int:
    """Read an unsigned 16-bit big-endian integer from ``buf`` at ``offset``."""
    return int.from_bytes(buf[offset:offset + 2], "big")


def _pack_u16_be(value: int) -> bytes:
    """Pack ``value`` as an unsigned 16-bit big-endian integer."""
    if not 0 <= value <= 0xFFFF:
        raise ValueError(f"uint16 out of range: {value}")
    return value.to_bytes(2, "big")


@dataclass(frozen=True)
class ChunkHeader:
    """A parsed SCTP chunk header plus its value and any trailing padding."""

    chunk_type: int
    flags: int
    length: int
    value: bytes
    padding: bytes

    @property
    def valid_length(self) -> bool:
        """True when ``length`` is plausible for the captured bytes."""
        return HEADER_SIZE <= self.length <= HEADER_SIZE + len(self.value) + len(self.padding)

    def to_bytes(self) -> bytes:
        """Rebuild the on-wire bytes, recomputing length and padding."""
        return build_chunk_header(self.chunk_type, self.flags, self.value)


@dataclass(frozen=True)
class ParameterTLV:
    """A parsed SCTP parameter TLV plus its value and any trailing padding."""

    param_type: int
    length: int
    value: bytes
    padding: bytes

    @property
    def valid_length(self) -> bool:
        """True when ``length`` is plausible for the captured bytes."""
        return HEADER_SIZE <= self.length <= HEADER_SIZE + len(self.value) + len(self.padding)

    def to_bytes(self) -> bytes:
        """Rebuild the on-wire bytes, recomputing length and padding."""
        return build_parameter_tlv(self.param_type, self.value)


def parse_chunk_header(data: bytes, offset: int = 0) -> Tuple[ChunkHeader, int]:
    """Parse one chunk header starting at ``offset``.

    Returns the parsed header and the offset of the next chunk (i.e. past this
    chunk's padded value).  If there are not enough bytes for even the header
    we raise ``ValueError``; we cannot meaningfully return a partial header.
    """
    if offset < 0:
        raise ValueError(f"offset must be non-negative, got {offset}")
    if len(data) - offset < HEADER_SIZE:
        raise ValueError(
            f"not enough bytes for chunk header at offset {offset}: "
            f"have {len(data) - offset}, need {HEADER_SIZE}"
        )

    chunk_type = data[offset]
    flags = data[offset + 1]
    length = _u16_be(data, offset + 2)

    available = len(data) - offset - HEADER_SIZE
    declared_value = max(0, length - HEADER_SIZE) if length >= HEADER_SIZE else 0
    used_value = min(declared_value, available)
    value = data[offset + HEADER_SIZE: offset + HEADER_SIZE + used_value]

    padded_value = _padded_len(used_value)
    padding_len = max(0, padded_value - used_value)
    padding = data[offset + HEADER_SIZE + used_value: offset + HEADER_SIZE + used_value + padding_len]

    next_offset = offset + HEADER_SIZE + len(value) + len(padding)
    return ChunkHeader(chunk_type, flags, length, value, padding), next_offset


def parse_parameter_tlv(data: bytes, offset: int = 0) -> Tuple[ParameterTLV, int]:
    """Parse one parameter TLV starting at ``offset``.

    Mirrors :func:`parse_chunk_header`.  Parameters use the same TLV layout as
    chunk headers; the type field is just wider in spirit but still 16 bits.
    """
    if offset < 0:
        raise ValueError(f"offset must be non-negative, got {offset}")
    if len(data) - offset < HEADER_SIZE:
        raise ValueError(
            f"not enough bytes for parameter header at offset {offset}: "
            f"have {len(data) - offset}, need {HEADER_SIZE}"
        )

    param_type = _u16_be(data, offset)
    length = _u16_be(data, offset + 2)

    available = len(data) - offset - HEADER_SIZE
    declared_value = max(0, length - HEADER_SIZE) if length >= HEADER_SIZE else 0
    used_value = min(declared_value, available)
    value = data[offset + HEADER_SIZE: offset + HEADER_SIZE + used_value]

    padded_value = _padded_len(used_value)
    padding_len = max(0, padded_value - used_value)
    padding = data[offset + HEADER_SIZE + used_value: offset + HEADER_SIZE + used_value + padding_len]

    next_offset = offset + HEADER_SIZE + len(value) + len(padding)
    return ParameterTLV(param_type, length, value, padding), next_offset


def build_chunk_header(chunk_type: int, flags: int, value: bytes = b"") -> bytes:
    """Build on-wire bytes for a chunk header with the given value.

    The length field is computed (header + value); padding to a four-byte
    boundary is appended.  We do NOT round-trip a caller-supplied length field
    because the on-wire length is a derived value, not an independent input.
    """
    if not isinstance(chunk_type, int):
        raise TypeError("chunk_type must be int")
    if not isinstance(flags, int):
        raise TypeError("flags must be int")
    if not isinstance(value, (bytes, bytearray)):
        raise TypeError("value must be bytes")
    value = bytes(value)

    length = HEADER_SIZE + len(value)
    out = bytearray()
    out.append(chunk_type & 0xFF)
    out.append(flags & 0xFF)
    out += _pack_u16_be(length)
    out += value
    pad = _padded_len(len(value)) - len(value)
    if pad:
        out += b"\x00" * pad
    return bytes(out)


def build_parameter_tlv(param_type: int, value: bytes = b"") -> bytes:
    """Build on-wire bytes for a parameter TLV with the given value."""
    if not isinstance(param_type, int):
        raise TypeError("param_type must be int")
    if not isinstance(value, (bytes, bytearray)):
        raise TypeError("value must be bytes")
    value = bytes(value)

    length = HEADER_SIZE + len(value)
    out = bytearray()
    out += _pack_u16_be(param_type)
    out += _pack_u16_be(length)
    out += value
    pad = _padded_len(len(value)) - len(value)
    if pad:
        out += b"\x00" * pad
    return bytes(out)
