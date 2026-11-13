"""位布局解码/编码核心。

只做字节与位域的机械展开和反向重建，不连接设备、不运行实验、不推断任何
物理状态。全部输入均为手工合成材料。

位编号约定（与 fixtures/layouts.json 的标记一致）：

* 一个 shot 占 ``stride_bytes`` 个字节；物理 bit_offset 跨字节连续编号，
  第一个字节的最低有效位为 0，依次向高位、向后续字节递增。
* 字段值按“低 offset 对应低有效位”组合：把整个 shot 视为小端整数后，
  ``(word >> bit_offset) & ((1 << width) - 1)`` 即字段原始值。
* 每个 channel 另有一个 valid 位：valid=0 时事实值为 NULL（Python 的
  ``None``），但值字段的原始位原样保留在 ``raw_value`` 中，反向编码时
  必须原位写回，禁止用 NULL 填 0。
* padding 位必须为 0；包长度必须恰好等于 ``shot_count * stride_bytes``，
  尾部残片一律拒绝。
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from dataclasses import dataclass
from typing import Iterable, Iterator, Mapping, Sequence

BIT_INDEX_MARKER = "byte_lsb0"
FIELD_SIGNIFICANCE_MARKER = "increasing_offset_lsb_first"


class LayoutError(ValueError):
    """布局定义非法（重复 channel、位域交叠、覆盖不全等）。"""


class PacketError(ValueError):
    """包或载荷非法（长度、padding、base64、哈希、残片等）。"""


def _is_plain_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


@dataclass(frozen=True)
class Channel:
    """一个逻辑 channel 在布局中的位域描述。身份是 channel_id，不是位置。"""

    channel_id: str
    bit_offset: int
    width: int
    valid_bit: int

    @property
    def value_mask(self) -> int:
        return (1 << self.width) - 1

    def as_spec(self) -> dict:
        return {
            "channel_id": self.channel_id,
            "bit_offset": self.bit_offset,
            "width": self.width,
            "valid_bit": self.valid_bit,
        }


@dataclass(frozen=True)
class Layout:
    layout_id: str
    stride_bytes: int
    channels: tuple[Channel, ...]
    padding_bits: frozenset[int]
    padding_mask: int
    canonical_json: str
    digest: str

    def channel(self, channel_id: str) -> Channel:
        for channel in self.channels:
            if channel.channel_id == channel_id:
                return channel
        raise LayoutError(f"布局 {self.layout_id} 中没有 channel {channel_id!r}")


@dataclass(frozen=True)
class ShotFact:
    """单个 shot × channel 的事实。

    value 为 None 表示 valid=0（缺测）；raw_value 始终保留值字段的原位原始
    位，因此两条 value 均为 NULL 的事实仍可能因 raw_value 不同而是不同证据。
    """

    channel_id: str
    value: int | None
    raw_value: int
    valid: bool


def build_layout(spec: Mapping[str, object]) -> Layout:
    """校验并构建一个 Layout。

    非法情形全部抛 :class:`LayoutError`：stride 非正整数、channel_id 重复、
    位号越界、值域互相交叠、valid 落入值域或 padding、padding 重复、以及
    存在未被任何值域/valid/padding 覆盖的位。
    """
    if not isinstance(spec, Mapping):
        raise LayoutError("布局定义必须是 JSON 对象")
    layout_id = spec.get("layout_id")
    if not isinstance(layout_id, str) or not layout_id:
        raise LayoutError("layout_id 必须是非空字符串")

    stride = spec.get("stride_bytes")
    if not _is_plain_int(stride) or stride <= 0:
        raise LayoutError(f"布局 {layout_id}: stride_bytes 必须是正整数")
    total_bits = stride * 8

    raw_channels = spec.get("channels")
    if not isinstance(raw_channels, list) or not raw_channels:
        raise LayoutError(f"布局 {layout_id}: channels 必须是非空列表")

    occupied: dict[int, str] = {}

    def claim(bit: int, label: str) -> None:
        if not _is_plain_int(bit) or not 0 <= bit < total_bits:
            raise LayoutError(
                f"布局 {layout_id}: {label} 的位号 {bit!r} 超出 [0, {total_bits - 1}]"
            )
        if bit in occupied:
            raise LayoutError(
                f"布局 {layout_id}: 位 {bit} 同时属于 {occupied[bit]} 和 {label}"
            )
        occupied[bit] = label

    channels: list[Channel] = []
    seen_ids: set[str] = set()
    for index, raw_channel in enumerate(raw_channels):
        if not isinstance(raw_channel, Mapping):
            raise LayoutError(f"布局 {layout_id}: 第 {index} 个 channel 不是对象")
        channel_id = raw_channel.get("channel_id")
        if not isinstance(channel_id, str) or not channel_id:
            raise LayoutError(f"布局 {layout_id}: channel_id 必须是非空字符串")
        if channel_id in seen_ids:
            raise LayoutError(f"布局 {layout_id}: channel_id 重复: {channel_id}")
        seen_ids.add(channel_id)

        offset = raw_channel.get("bit_offset")
        width = raw_channel.get("width")
        valid_bit = raw_channel.get("valid_bit")
        if not _is_plain_int(offset) or not _is_plain_int(width) or not _is_plain_int(valid_bit):
            raise LayoutError(f"布局 {layout_id} channel {channel_id}: 位号必须是整数")
        if width <= 0:
            raise LayoutError(f"布局 {layout_id} channel {channel_id}: width 必须为正整数")

        label = f"channel {channel_id} 值域"
        for bit in range(offset, offset + width):
            claim(bit, label)
        # 若 valid 落在本 channel 或其他 channel 的值域、或已被占用，这里会拒绝。
        claim(valid_bit, f"channel {channel_id} valid 位")
        channels.append(Channel(channel_id, offset, width, valid_bit))

    raw_padding = spec.get("padding_bits", [])
    if not isinstance(raw_padding, list):
        raise LayoutError(f"布局 {layout_id}: padding_bits 必须是列表")
    padding_bits: set[int] = set()
    for bit in raw_padding:
        if not _is_plain_int(bit):
            raise LayoutError(f"布局 {layout_id}: padding 位号必须是整数")
        if bit in padding_bits:
            raise LayoutError(f"布局 {layout_id}: padding 位 {bit} 重复登记")
        claim(bit, "padding 位")
        padding_bits.add(bit)

    if len(occupied) != total_bits:
        missing = sorted(set(range(total_bits)) - set(occupied))
        raise LayoutError(f"布局 {layout_id}: 存在未覆盖位（既非值域/valid 也非 padding）: {missing}")

    channels.sort(key=lambda item: item.channel_id)
    canonical_obj = {
        "layout_id": layout_id,
        "stride_bytes": stride,
        "channels": [channel.as_spec() for channel in channels],
        "padding_bits": sorted(padding_bits),
        "bit_index": BIT_INDEX_MARKER,
        "field_bit_significance": FIELD_SIGNIFICANCE_MARKER,
    }
    canonical_json = json.dumps(
        canonical_obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    digest = hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()
    padding_mask = sum(1 << bit for bit in padding_bits)
    return Layout(
        layout_id=layout_id,
        stride_bytes=stride,
        channels=tuple(channels),
        padding_bits=frozenset(padding_bits),
        padding_mask=padding_mask,
        canonical_json=canonical_json,
        digest=digest,
    )


def parse_layouts_doc(doc: Mapping[str, object]) -> dict[str, Layout]:
    """解析 layouts.json 形态的文档，返回 layout_id -> Layout。"""
    if not isinstance(doc, Mapping):
        raise LayoutError("布局文档必须是 JSON 对象")
    if doc.get("bit_index") != BIT_INDEX_MARKER:
        raise LayoutError(f"bit_index 标记必须为 {BIT_INDEX_MARKER!r}")
    if doc.get("field_bit_significance") != FIELD_SIGNIFICANCE_MARKER:
        raise LayoutError(
            f"field_bit_significance 标记必须为 {FIELD_SIGNIFICANCE_MARKER!r}"
        )
    rows = doc.get("layouts")
    if not isinstance(rows, list) or not rows:
        raise LayoutError("布局文档的 layouts 必须是非空列表")
    layouts: dict[str, Layout] = {}
    for row in rows:
        layout = build_layout(row)
        if layout.layout_id in layouts:
            raise LayoutError(f"layout_id 重复: {layout.layout_id}")
        layouts[layout.layout_id] = layout
    return layouts


def read_bits(word: int, bit_offset: int, width: int) -> int:
    """按低 offset 为低有效位读取位域。"""
    return (word >> bit_offset) & ((1 << width) - 1)


def write_bits(word: int, bit_offset: int, width: int, value: int) -> int:
    """把 value 写入指定位域，其它位保持不变。value 必须在 width 位可表示范围内。"""
    mask = (1 << width) - 1
    if not _is_plain_int(value) or not 0 <= value <= mask:
        raise PacketError(f"值 {value!r} 无法用 width={width} 位表示")
    return (word & ~(mask << bit_offset)) | ((value & mask) << bit_offset)


def decode_shot(layout: Layout, shot_bytes: bytes) -> tuple[int, list[ShotFact]]:
    """解码单个 shot。返回 shot 整数视图与各 channel 事实；padding 非零即拒绝。"""
    if len(shot_bytes) != layout.stride_bytes:
        raise PacketError(
            f"布局 {layout.layout_id}: 单 shot 需要 {layout.stride_bytes} 字节，实际 {len(shot_bytes)}"
        )
    word = int.from_bytes(shot_bytes, "little")
    if word & layout.padding_mask:
        raise PacketError(
            f"布局 {layout.layout_id}: padding 位必须为 0，shot 字=0x{word:0{layout.stride_bytes * 2}x}"
        )
    facts: list[ShotFact] = []
    for channel in layout.channels:
        raw_value = read_bits(word, channel.bit_offset, channel.width)
        valid = bool((word >> channel.valid_bit) & 1)
        facts.append(
            ShotFact(
                channel_id=channel.channel_id,
                value=raw_value if valid else None,
                raw_value=raw_value,
                valid=valid,
            )
        )
    return word, facts


def iter_decoded_shots(
    layout: Layout, payload: bytes, shot_count: int
) -> Iterator[tuple[int, list[ShotFact]]]:
    """流式解码生成器：每次只持有一个 shot 的切片与事实。

    包总长度在生成前立即校验（尾部残片不会被静默接受）；各 shot 的 padding
    等内容问题在迭代到该 shot 时抛 :class:`PacketError`。
    """
    if not _is_plain_int(shot_count) or shot_count < 0:
        raise PacketError("shot_count 必须是非负整数")
    expected = shot_count * layout.stride_bytes
    if len(payload) != expected:
        raise PacketError(
            f"布局 {layout.layout_id}: 载荷 {len(payload)} 字节 != "
            f"shot_count({shot_count}) * stride({layout.stride_bytes}) = {expected}，拒绝尾部残片"
        )
    view = memoryview(payload)
    for shot_index in range(shot_count):
        start = shot_index * layout.stride_bytes
        _, facts = decode_shot(layout, view[start : start + layout.stride_bytes])
        yield shot_index, facts


def decode_payload(
    layout: Layout, payload: bytes, shot_count: int
) -> list[tuple[int, list[ShotFact]]]:
    """完整展开一个包为 shot 序号 -> 事实列表（小包逐位核对用）。"""
    return list(iter_decoded_shots(layout, payload, shot_count))


def iter_packet_stream(
    layout: Layout,
    byte_chunks: Iterable[bytes | bytearray | memoryview],
    shot_count: int,
) -> Iterator[tuple[int, list[ShotFact]]]:
    """从分块字节流（如分块读取的文件）逐 shot 解码。

    内存上界为“块大小 + 不足一个 stride 的残片 + 单 shot 事实”，与
    shot_count 无关。包总长度仍须恰好等于 shot_count * stride，最后一块
    之后若有残片或总长不符一律抛 :class:`PacketError`。
    """
    if not _is_plain_int(shot_count) or shot_count < 0:
        raise PacketError("shot_count 必须是非负整数")
    expected = shot_count * layout.stride_bytes
    buffer = bytearray()
    produced = 0
    total = 0
    for chunk in byte_chunks:
        if not isinstance(chunk, (bytes, bytearray, memoryview)):
            raise PacketError("分块流的每一块必须是字节类对象")
        buffer.extend(chunk)
        total += len(chunk)
        while len(buffer) >= layout.stride_bytes and produced < shot_count:
            # 先拷成独立 bytes 再释放切片，避免 memoryview 导出期间改写 bytearray。
            shot_bytes = bytes(buffer[: layout.stride_bytes])
            _, facts = decode_shot(layout, shot_bytes)
            del buffer[: layout.stride_bytes]
            yield produced, facts
            produced += 1
    if total != expected:
        raise PacketError(
            f"布局 {layout.layout_id}: 流式字节 {total} 个 != "
            f"shot_count({shot_count}) * stride({layout.stride_bytes}) = {expected}，拒绝尾部残片"
        )
    if produced != shot_count or buffer:
        raise PacketError(
            f"布局 {layout.layout_id}: 流结束时仅解出 {produced}/{shot_count} 个 shot，"
            f"残留 {len(buffer)} 字节"
        )


def encode_shot(layout: Layout, facts: Iterable[ShotFact]) -> bytes:
    """根据一个 shot 的事实重建原始字节，无效字段原位写回 raw_value。"""
    by_channel = {fact.channel_id: fact for fact in facts}
    if set(by_channel) != {channel.channel_id for channel in layout.channels}:
        raise PacketError(
            f"布局 {layout.layout_id}: 重建 shot 需要恰好这些 channel: "
            f"{sorted(channel.channel_id for channel in layout.channels)}"
        )
    word = 0
    for channel in layout.channels:
        fact = by_channel[channel.channel_id]
        if not _is_plain_int(fact.raw_value) or not 0 <= fact.raw_value <= channel.value_mask:
            raise PacketError(
                f"channel {channel.channel_id}: raw_value {fact.raw_value!r} 超出 {channel.width} 位值域"
            )
        word = write_bits(word, channel.bit_offset, channel.width, fact.raw_value)
        word = write_bits(word, channel.valid_bit, 1, 1 if fact.valid else 0)
    # padding 位从未被写过，天然为 0。
    return word.to_bytes(layout.stride_bytes, "little")


def encode_payload(
    layout: Layout,
    decoded_shots: Iterable[Iterable[ShotFact]],
    shot_count: int | None = None,
) -> bytes:
    """把展开后的事实重新编码为完整载荷。

    无效字段按 raw_value 原位重建，而不是写 0。若给出 shot_count，则校验
    重建出的 shot 数量一致。
    """
    chunks: list[bytes] = []
    produced = 0
    for facts in decoded_shots:
        chunks.append(encode_shot(layout, facts))
        produced += 1
    if shot_count is not None and produced != shot_count:
        raise PacketError(f"重建 shot 数 {produced} 与登记 shot_count {shot_count} 不一致")
    return b"".join(chunks)


def iter_encoded_shots(
    layout: Layout, decoded_shots: Iterable[Iterable[ShotFact]]
) -> Iterator[bytes]:
    """流式反向编码：逐 shot 产出字节，调用方自行拼接，整包不驻留内存。"""
    for facts in decoded_shots:
        yield encode_shot(layout, facts)


def decode_base64_payload(text: object) -> bytes:
    """严格 base64 解码（拒绝空白与非字母表字符），非法输入转 PacketError。"""
    if not isinstance(text, str):
        raise PacketError("payload_base64 必须是字符串")
    try:
        return base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise PacketError(f"base64 载荷非法: {exc}") from exc


def verify_sha256(payload: bytes, expected: object, packet_id: str = "") -> str:
    """核对载荷 SHA256，返回实际十六进制摘要；不匹配即 PacketError。"""
    if not isinstance(expected, str):
        raise PacketError(f"包 {packet_id}: sha256 必须是十六进制字符串")
    actual = hashlib.sha256(payload).hexdigest()
    if actual != expected.lower():
        raise PacketError(
            f"包 {packet_id}: SHA256 不匹配，登记 {expected}，实际 {actual}"
        )
    return actual


def roundtrip_payload(
    layout: Layout, payload: bytes, shot_count: int
) -> bytes:
    """解码再反向编码的便捷核对，返回重建字节（调用方应断言与原载荷相等）。"""
    decoded = decode_payload(layout, payload, shot_count)
    return encode_payload(
        layout, (facts for _, facts in decoded), shot_count=shot_count
    )
