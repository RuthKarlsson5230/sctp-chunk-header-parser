"""Tests for sctp_chunk_header_parser.core."""

import unittest

from sctp_chunk_header_parser import (
    ChunkHeader,
    ParameterTLV,
    parse_chunk_header,
    parse_parameter_tlv,
    build_chunk_header,
    build_parameter_tlv,
)


class TestBuildChunkHeader(unittest.TestCase):

    def test_empty_value_rounds_up_to_word(self):
        out = build_chunk_header(1, 0, b"")
        self.assertEqual(out, b"\x01\x00\x00\x04")

    def test_three_byte_value_padded_to_four(self):
        out = build_chunk_header(1, 2, b"ABC")
        self.assertEqual(out, b"\x01\x02\x00\x07ABC\x00")

    def test_four_byte_value_no_padding(self):
        out = build_chunk_header(6, 0, b"DDDD")
        self.assertEqual(out, b"\x06\x00\x00\x08DDDD")

    def test_five_byte_value_padded_to_eight(self):
        out = build_chunk_header(6, 0, b"EEEEE")
        self.assertEqual(out, b"\x06\x00\x00\x09EEEEE\x00\x00\x00")

    def test_flags_and_type_are_masked(self):
        out = build_chunk_header(0xFF, 0xFF, b"")
        self.assertEqual(out, b"\xff\xff\x00\x04")

    def test_rejects_non_bytes_value(self):
        with self.assertRaises(TypeError):
            build_chunk_header(1, 0, "not bytes")  # type: ignore[arg-type]

    def test_rejects_non_int_type(self):
        with self.assertRaises(TypeError):
            build_chunk_header("1", 0, b"")  # type: ignore[arg-type]


class TestParseChunkHeader(unittest.TestCase):

    def test_empty_value(self):
        header, nxt = parse_chunk_header(b"\x01\x00\x00\x04")
        self.assertEqual(header.chunk_type, 1)
        self.assertEqual(header.flags, 0)
        self.assertEqual(header.length, 4)
        self.assertEqual(header.value, b"")
        self.assertEqual(header.padding, b"")
        self.assertTrue(header.valid_length)
        self.assertEqual(nxt, 4)

    def test_padded_value(self):
        data = b"\x01\x02\x00\x07ABC\x00"
        header, nxt = parse_chunk_header(data)
        self.assertEqual(header.chunk_type, 1)
        self.assertEqual(header.flags, 2)
        self.assertEqual(header.length, 7)
        self.assertEqual(header.value, b"ABC")
        self.assertEqual(header.padding, b"\x00")
        self.assertTrue(header.valid_length)
        self.assertEqual(nxt, 8)

    def test_two_chunks_back_to_back(self):
        data = (
            b"\x01\x00\x00\x04"  # chunk 1, empty
            b"\x06\x00\x00\x08DDDD"  # chunk 2, 4-byte value
        )
        h1, off = parse_chunk_header(data, 0)
        self.assertEqual(h1.chunk_type, 1)
        self.assertEqual(off, 4)
        h2, off = parse_chunk_header(data, off)
        self.assertEqual(h2.chunk_type, 6)
        self.assertEqual(h2.value, b"DDDD")
        self.assertEqual(off, 12)

    def test_length_too_short_invalid(self):
        # length 2 is below the header size; flagged invalid, value empty.
        header, nxt = parse_chunk_header(b"\x01\x00\x00\x02")
        self.assertEqual(header.length, 2)
        self.assertFalse(header.valid_length)
        self.assertEqual(header.value, b"")
        self.assertEqual(nxt, 4)

    def test_length_exceeds_buffer(self):
        # declares 8 bytes of value but only 2 are present.
        header, nxt = parse_chunk_header(b"\x01\x00\x00\x0cAB")
        self.assertEqual(header.length, 12)
        self.assertEqual(header.value, b"AB")
        # No padding is synthesised beyond what the buffer holds.
        self.assertEqual(header.padding, b"")
        self.assertFalse(header.valid_length)
        self.assertEqual(nxt, 6)

    def test_offset_skips_prefix(self):
        prefix = b"ZZZZ"
        data = prefix + b"\x01\x00\x00\x04"
        header, nxt = parse_chunk_header(data, 4)
        self.assertEqual(header.chunk_type, 1)
        self.assertEqual(nxt, 8)

    def test_negative_offset_raises(self):
        with self.assertRaises(ValueError):
            parse_chunk_header(b"\x01\x00\x00\x04", -1)

    def test_too_few_bytes_raises(self):
        with self.assertRaises(ValueError):
            parse_chunk_header(b"\x01\x00")

    def test_round_trip(self):
        original = build_chunk_header(6, 0, b"DATA")
        header, _ = parse_chunk_header(original)
        self.assertEqual(header.to_bytes(), original)


class TestParameterTLV(unittest.TestCase):

    def test_build_and_parse(self):
        on_wire = build_parameter_tlv(0x8001, b"V")
        self.assertEqual(on_wire, b"\x80\x01\x00\x05V\x00\x00\x00")
        param, nxt = parse_parameter_tlv(on_wire)
        self.assertEqual(param.param_type, 0x8001)
        self.assertEqual(param.length, 5)
        self.assertEqual(param.value, b"V")
        self.assertEqual(param.padding, b"\x00\x00\x00")
        self.assertTrue(param.valid_length)
        self.assertEqual(nxt, 8)

    def test_unpadded_param(self):
        on_wire = build_parameter_tlv(5, b"four")
        self.assertEqual(on_wire, b"\x00\x05\x00\x08four")
        param, nxt = parse_parameter_tlv(on_wire)
        self.assertEqual(param.param_type, 5)
        self.assertEqual(param.value, b"four")
        self.assertEqual(param.padding, b"")
        self.assertEqual(nxt, 8)

    def test_param_too_short(self):
        param, nxt = parse_parameter_tlv(b"\x00\x01\x00\x02")
        self.assertEqual(param.length, 2)
        self.assertFalse(param.valid_length)
        self.assertEqual(param.value, b"")
        self.assertEqual(nxt, 4)

    def test_param_round_trip(self):
        original = build_parameter_tlv(7, b"round")
        param, _ = parse_parameter_tlv(original)
        self.assertEqual(param.to_bytes(), original)


if __name__ == "__main__":
    unittest.main()
