"""位编解码核心测试：逐位核对、跨字节、换版、坏串、padding、残片、流式。"""

import base64
import hashlib
import json
import unittest
from pathlib import Path

from src.bit_codec import (
    LayoutError,
    PacketError,
    ShotFact,
    build_layout,
    decode_base64_payload,
    decode_payload,
    decode_shot,
    encode_payload,
    encode_shot,
    iter_decoded_shots,
    iter_encoded_shots,
    iter_packet_stream,
    parse_layouts_doc,
    read_bits,
    roundtrip_payload,
    verify_sha256,
)

ROOT = Path(__file__).resolve().parents[1]

V1_SPEC = {
    "layout_id": "v1",
    "stride_bytes": 1,
    "channels": [{"channel_id": "A", "bit_offset": 0, "width": 2, "valid_bit": 2}],
    "padding_bits": [3, 4, 5, 6, 7],
    "bit_index": "byte_lsb0",
    "field_bit_significance": "increasing_offset_lsb_first",
}


def make_packet_payload(layout_spec, shot_bytes_list):
    layout = build_layout(layout_spec)
    payload = b"".join(shot_bytes_list)
    return layout, payload


class V1FixtureTests(unittest.TestCase):
    def setUp(self):
        self.layouts = parse_layouts_doc(json.loads((ROOT / "fixtures/layouts.json").read_text()))
        self.packets = json.loads((ROOT / "fixtures/packets.json").read_text())["packets"]
        self.v1 = self.layouts["v1"]

    def test_three_shots_bit_by_bit(self):
        packet = self.packets[0]
        self.assertEqual(packet["packet_id"], "p1")
        payload = decode_base64_payload(packet["payload_base64"])
        self.assertEqual(payload, b"\x05\x00\x01")
        verify_sha256(payload, packet["sha256"], "p1")
        decoded = decode_payload(self.v1, payload, packet["shot_count"])
        self.assertEqual(len(decoded), 3)
        (_, f0), (_, f1), (_, f2) = decoded
        a0, a1, a2 = f0[0], f1[0], f2[0]
        # 0x05 = 位2 valid=1，值位0..1 = 01 -> 有效值 1
        self.assertEqual((a0.valid, a0.value, a0.raw_value), (True, 1, 1))
        # 0x00 = valid=0 且原值 0 -> NULL，但原始证据是 0
        self.assertEqual((a1.valid, a1.value, a1.raw_value), (False, None, 0))
        # 0x01 = valid=0 且原值 1 -> NULL，原始证据是 1
        self.assertEqual((a2.valid, a2.value, a2.raw_value), (False, None, 1))
        # 后两者事实值同为 NULL，但原始位证据不同，不得被抹平
        self.assertIsNone(a1.value)
        self.assertIsNone(a2.value)
        self.assertNotEqual(a1.raw_value, a2.raw_value)

    def test_null_is_not_zero_on_reencode(self):
        # 0x01：无效且原值 1。反向编码必须写回原位，而不是 NULL 填 0。
        word, facts = decode_shot(self.v1, b"\x01")
        self.assertEqual(word, 0x01)
        self.assertIsNone(facts[0].value)
        self.assertEqual(encode_shot(self.v1, facts), b"\x01")
        self.assertNotEqual(encode_shot(self.v1, facts), b"\x00")

    def test_full_fixture_roundtrip(self):
        for packet in self.packets:
            with self.subTest(packet=packet["packet_id"]):
                payload = decode_base64_payload(packet["payload_base64"])
                layout = self.layouts[packet["layout_id"]]
                rebuilt = roundtrip_payload(layout, payload, packet["shot_count"])
                self.assertEqual(rebuilt, payload)


class CrossByteTests(unittest.TestCase):
    def setUp(self):
        doc = json.loads((ROOT / "fixtures/layouts.json").read_text())
        self.v2 = parse_layouts_doc(doc)["v2"]  # stride 2, A: offset7 width3, valid bit0

    def test_cross_byte_value_lsb_first(self):
        # 值 5 = 101b 落在位7..9：位7=1(字节0), 位8=0, 位9=1(字节1)
        # 字节0: 位7 -> 0x80，外加 valid 位0=1 -> 0x81
        # 字节1: 位9 -> (1 << 1) = 0x02
        payload = b"\x81\x02"
        _, facts = decode_payload(self.v2, payload, 1)[0]
        fact = facts[0]
        self.assertTrue(fact.valid)
        self.assertEqual(fact.value, 5)
        self.assertEqual(fact.raw_value, 5)
        self.assertEqual(encode_shot(self.v2, facts), payload)

    def test_cross_byte_max_value_and_invalid(self):
        # 值 7 = 111b：位7,8,9 全 1 -> 字节0=0x80, 字节1=0x03；valid=0 故 NULL
        payload = b"\x80\x03"
        _, facts = decode_payload(self.v2, payload, 1)[0]
        self.assertFalse(facts[0].valid)
        self.assertIsNone(facts[0].value)
        self.assertEqual(facts[0].raw_value, 7)
        self.assertEqual(encode_shot(self.v2, facts), payload)

    def test_read_bits_matches_manual_bit_math(self):
        word = int.from_bytes(b"\x81\x02", "little")
        self.assertEqual(read_bits(word, 7, 3), 5)
        self.assertEqual(read_bits(word, 0, 1), 1)


class LayoutValidationTests(unittest.TestCase):
    def _spec(self, **overrides):
        spec = {
            "layout_id": "lx",
            "stride_bytes": 1,
            "channels": [
                {"channel_id": "A", "bit_offset": 0, "width": 2, "valid_bit": 2}
            ],
            "padding_bits": [3, 4, 5, 6, 7],
        }
        spec.update(overrides)
        return spec

    def test_duplicate_channel_id_rejected(self):
        spec = self._spec(
            channels=[
                {"channel_id": "A", "bit_offset": 0, "width": 1, "valid_bit": 1},
                {"channel_id": "A", "bit_offset": 2, "width": 1, "valid_bit": 3},
            ],
            padding_bits=[4, 5, 6, 7],
        )
        with self.assertRaises(LayoutError):
            build_layout(spec)

    def test_overlapping_value_ranges_rejected(self):
        spec = self._spec(
            channels=[
                {"channel_id": "A", "bit_offset": 0, "width": 3, "valid_bit": 3},
                {"channel_id": "B", "bit_offset": 2, "width": 2, "valid_bit": 5},
            ],
            padding_bits=[6, 7],
        )
        with self.assertRaises(LayoutError):
            build_layout(spec)

    def test_valid_bit_inside_own_value_rejected(self):
        spec = self._spec(
            channels=[{"channel_id": "A", "bit_offset": 0, "width": 3, "valid_bit": 1}],
            padding_bits=[3, 4, 5, 6, 7],
        )
        with self.assertRaises(LayoutError):
            build_layout(spec)

    def test_valid_bit_inside_padding_rejected(self):
        spec = self._spec(
            channels=[{"channel_id": "A", "bit_offset": 0, "width": 2, "valid_bit": 3}],
            padding_bits=[3, 4, 5, 6, 7],
        )
        with self.assertRaises(LayoutError):
            build_layout(spec)

    def test_uncovered_bits_rejected(self):
        spec = self._spec(padding_bits=[3, 4, 5, 6])  # 位7 未覆盖
        with self.assertRaises(LayoutError):
            build_layout(spec)

    def test_bit_out_of_stride_rejected(self):
        spec = self._spec(padding_bits=[3, 4, 5, 6, 8])
        with self.assertRaises(LayoutError):
            build_layout(spec)

    def test_bad_doc_markers_rejected(self):
        with self.assertRaises(LayoutError):
            parse_layouts_doc({"bit_index": "other", "layouts": [V1_SPEC]})

    def test_non_positive_stride_rejected(self):
        with self.assertRaises(LayoutError):
            build_layout(self._spec(stride_bytes=0))


class RepositionTests(unittest.TestCase):
    """位置换版：channel 身份不变，位位置改变。"""

    def test_same_identity_different_position(self):
        old = build_layout(V1_SPEC)
        new_spec = {
            "layout_id": "v3",
            "stride_bytes": 1,
            # A 搬到高位：值位 5..6，valid 位 7
            "channels": [{"channel_id": "A", "bit_offset": 5, "width": 2, "valid_bit": 7}],
            "padding_bits": [0, 1, 2, 3, 4],
        }
        new = build_layout(new_spec)
        self.assertNotEqual(old.digest, new.digest)

        # 旧布局 0x05 = 有效值1；新布局中有效值1应编码为 (1<<5)|(1<<7)
        old_word, old_facts = decode_payload(old, b"\x05", 1)[0]
        new_bytes = encode_shot(new, old_facts)
        self.assertEqual(new_bytes, bytes([(1 << 5) | (1 << 7)]))
        _, new_facts = decode_payload(new, new_bytes, 1)[0]
        self.assertEqual(new_facts[0].channel_id, "A")
        self.assertEqual(new_facts[0].value, old_facts[0].value)


class PacketValidationTests(unittest.TestCase):
    def setUp(self):
        self.layout = build_layout(V1_SPEC)

    def test_padding_nonzero_rejected(self):
        with self.assertRaises(PacketError):
            decode_payload(self.layout, b"\x08", 1)  # 位3 是 padding

    def test_trailing_fragment_rejected(self):
        with self.assertRaises(PacketError):  # 多一个残片字节
            decode_payload(self.layout, b"\x05\x00", 1)
        with self.assertRaises(PacketError):  # 字节不足
            decode_payload(self.layout, b"\x05\x00", 3)

    def test_bad_base64_rejected(self):
        for bad in ["BQ@B", " BQAB", "BQAB\n", "===="]:
            with self.subTest(bad=bad):
                with self.assertRaises(PacketError):
                    decode_base64_payload(bad)

    def test_sha256_mismatch_rejected(self):
        with self.assertRaises(PacketError):
            verify_sha256(b"\x05\x00\x01", "00" * 32, "p1")

    def test_negative_shot_count_rejected(self):
        with self.assertRaises(PacketError):
            decode_payload(self.layout, b"", -1)

    def test_zero_shots_empty_payload(self):
        self.assertEqual(decode_payload(self.layout, b"", 0), [])
        self.assertEqual(encode_payload(self.layout, [], shot_count=0), b"")


class StreamingTests(unittest.TestCase):
    def setUp(self):
        self.layout = build_layout(V1_SPEC)

    def test_large_synthetic_packet_bounded_memory(self):
        import tempfile

        shot_count = 200_000
        # 交替：0x05 有效值1 / 0x01 无效原值1 / 0x04 有效值0
        patterns = [b"\x05", b"\x01", b"\x04"]
        chunk_size = 4096  # 与 shot_count 无关的固定块大小

        def raw_chunks():
            for start in range(0, shot_count, chunk_size):
                yield b"".join(patterns[i % 3] for i in range(start, min(start + chunk_size, shot_count)))

        # 管道：分块解码 -> 逐 shot 反向编码 -> 分块落盘，全程不持有整包
        valid_zero = valid_nonzero = invalid = 0
        rebuilt_len = 0
        with tempfile.TemporaryFile() as rebuilt_file:
            pending = bytearray()

            def encoded_chunks():
                nonlocal pending
                for _, facts in iter_packet_stream(self.layout, raw_chunks(), shot_count):
                    pending.extend(encode_shot(self.layout, facts))
                    if len(pending) >= chunk_size:
                        block = bytes(pending)
                        pending.clear()
                        yield block
                if pending:
                    yield bytes(pending)

            for block in encoded_chunks():
                rebuilt_file.write(block)
                rebuilt_len += len(block)

            # 从重建文件分块读回并统计，同样不整包载入
            rebuilt_file.seek(0)

            def file_chunks():
                while True:
                    block = rebuilt_file.read(chunk_size)
                    if not block:
                        return
                    yield block

            for _, facts in iter_packet_stream(self.layout, file_chunks(), shot_count):
                fact = facts[0]
                if fact.valid and fact.value == 0:
                    valid_zero += 1
                elif fact.valid:
                    valid_nonzero += 1
                else:
                    invalid += 1

        self.assertEqual(rebuilt_len, shot_count)
        self.assertEqual(valid_zero + valid_nonzero + invalid, shot_count)
        q, r = divmod(shot_count, 3)
        self.assertEqual(valid_nonzero, q + (1 if r >= 1 else 0))
        self.assertEqual(invalid, q + (1 if r >= 2 else 0))
        self.assertEqual(valid_zero, q)

    def test_stream_rejects_trailing_fragment(self):
        # 1 个 shot 的登记量喂 2 个字节：总长不符
        with self.assertRaises(PacketError):
            list(iter_packet_stream(self.layout, [b"\x05\x00"], 1))
        # 总长正确但某 shot padding 非零
        with self.assertRaises(PacketError):
            list(iter_packet_stream(self.layout, [b"\x05", b"\x08"], 2))

    def test_stream_handles_chunks_smaller_than_stride(self):
        # v2 是 2 字节 stride，逐字节喂入也必须正确拼 shot
        v2 = build_layout(
            {
                "layout_id": "v2",
                "stride_bytes": 2,
                "channels": [{"channel_id": "A", "bit_offset": 7, "width": 3, "valid_bit": 0}],
                "padding_bits": [1, 2, 3, 4, 5, 6, 10, 11, 12, 13, 14, 15],
            }
        )
        decoded = list(iter_packet_stream(v2, [b"\x81", b"\x02"], 1))
        self.assertEqual(decoded[0][1][0].value, 5)

    def test_generator_length_failure_is_eager_content_failure_lazy(self):
        # 长度（残片）错误在生成器创建后首次迭代即抛出
        with self.assertRaises(PacketError):
            list(iter_decoded_shots(self.layout, b"\x05\x00", 3))
        # padding 错误延迟到真正迭代到该 shot
        gen2 = iter_decoded_shots(self.layout, b"\x05\x08", 2)
        _, first = next(gen2)  # 第一个 shot 正常
        self.assertEqual(first[0].value, 1)
        with self.assertRaises(PacketError):
            next(gen2)

    def test_roundtrip_stream_equals_original(self):
        payload = bytes([0x05, 0x00, 0x01, 0x04, 0x01])
        decoded = decode_payload(self.layout, payload, 5)
        rebuilt = b"".join(
            iter_encoded_shots(self.layout, (facts for _, facts in decoded))
        )
        self.assertEqual(rebuilt, payload)

    def test_encode_rejects_value_out_of_width(self):
        fact = ShotFact(channel_id="A", value=4, raw_value=4, valid=True)
        with self.assertRaises(PacketError):
            encode_shot(self.layout, [fact])


if __name__ == "__main__":
    unittest.main()
