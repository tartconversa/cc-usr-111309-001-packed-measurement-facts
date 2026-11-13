"""包级原子入仓组件：合成二进制载荷 -> 稳定的 shot × channel 事实宽表。

存储选型：长表（facts 每行一个 shot × channel）。选择理由是布局可换版、
channel 集合不固定，长表无需随布局迁移表结构；且每个事实单独携带
raw_value（无效字段的原位证据）、位域与布局摘要，不会因为 NULL 语义丢失
原始位。

原子性与幂等：

* 每个包的登记与全部事实展开在单个 SQLite 事务内提交；任何一步失败
  （base64、哈希、长度、padding、位域）整体回滚，不留下前半包事实。
* 相同 packet_id + 相同字节（SHA256）重送：直接返回已登记结果，不双写。
* 相同 packet_id + 不同字节：拒绝（PacketConflict），身份不可复用。
* 未知布局：整包进入 pending_packets 原封保存，补注册布局后 replay 即可；
  pending 同样按 packet_id 去重，身份相同内容不同直接拒绝。
* 进程重启后所有状态都在 SQLite 文件里，pending 包可继续重放。
"""

from __future__ import annotations

import argparse
import json
import sqlite3
from pathlib import Path
from typing import Iterable, Mapping, Sequence

from .bit_codec import (
    Layout,
    LayoutError,
    PacketError,
    ShotFact,
    build_layout,
    decode_base64_payload,
    encode_payload,
    iter_decoded_shots,
    parse_layouts_doc,
    verify_sha256,
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS layouts (
    layout_id      TEXT PRIMARY KEY,
    stride_bytes   INTEGER NOT NULL,
    canonical_json TEXT NOT NULL,
    digest         TEXT NOT NULL UNIQUE
);
CREATE TABLE IF NOT EXISTS packets (
    packet_id   TEXT PRIMARY KEY,
    layout_id   TEXT NOT NULL REFERENCES layouts(layout_id),
    shot_count  INTEGER NOT NULL,
    payload_b64 TEXT NOT NULL,
    sha256      TEXT NOT NULL,
    payload_len INTEGER NOT NULL,
    imported_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS pending_packets (
    packet_id   TEXT PRIMARY KEY,
    layout_id   TEXT NOT NULL,
    shot_count  INTEGER NOT NULL,
    payload_b64 TEXT NOT NULL,
    sha256      TEXT NOT NULL,
    payload_len INTEGER NOT NULL,
    queued_at   TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS facts (
    packet_id         TEXT NOT NULL REFERENCES packets(packet_id),
    layout_id         TEXT NOT NULL,
    layout_digest     TEXT NOT NULL,
    shot_index        INTEGER NOT NULL,
    channel_id        TEXT NOT NULL,
    bit_offset        INTEGER NOT NULL,
    width             INTEGER NOT NULL,
    valid_bit         INTEGER NOT NULL,
    valid             INTEGER NOT NULL CHECK (valid IN (0, 1)),
    value             INTEGER,
    raw_value         INTEGER NOT NULL,
    PRIMARY KEY (packet_id, shot_index, channel_id)
);
CREATE INDEX IF NOT EXISTS idx_facts_channel ON facts(channel_id);
CREATE INDEX IF NOT EXISTS idx_packets_sha ON packets(sha256);
"""


class PacketConflict(PacketError):
    """同一 packet_id 已登记过不同内容。"""


def _connect(db_path: str | Path) -> sqlite3.Connection:
    connection = sqlite3.connect(str(db_path))
    connection.execute("PRAGMA foreign_keys = ON")
    connection.executescript(SCHEMA)
    return connection


class FactWarehouse:
    """SQLite 事实仓。可用作上下文管理器，退出时关闭连接。"""

    def __init__(self, db_path: str | Path = ":memory:"):
        self.db_path = str(db_path)
        if self.db_path != ":memory:":
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self.connection = _connect(self.db_path)

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> "FactWarehouse":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # ------------------------------------------------------------------ layouts
    def register_layout(self, layout: Layout) -> bool:
        """注册一个已校验布局。同 ID 同摘要幂等；同 ID 不同定义拒绝。"""
        row = self.connection.execute(
            "SELECT digest, canonical_json FROM layouts WHERE layout_id = ?",
            (layout.layout_id,),
        ).fetchone()
        if row is not None:
            if row[0] != layout.digest:
                raise LayoutError(
                    f"layout_id {layout.layout_id} 已存在且定义不同："
                    f"已登记 {row[0]}，本次 {layout.digest}"
                )
            return False
        self.connection.execute(
            "INSERT INTO layouts(layout_id, stride_bytes, canonical_json, digest) "
            "VALUES (?, ?, ?, ?)",
            (
                layout.layout_id,
                layout.stride_bytes,
                layout.canonical_json,
                layout.digest,
            ),
        )
        self.connection.commit()
        return True

    def register_layouts_doc(self, doc: Mapping[str, object]) -> int:
        layouts = parse_layouts_doc(doc)
        added = 0
        for layout in layouts.values():
            if self.register_layout(layout):
                added += 1
        return added

    def get_layout(self, layout_id: str) -> Layout:
        row = self.connection.execute(
            "SELECT canonical_json FROM layouts WHERE layout_id = ?", (layout_id,)
        ).fetchone()
        if row is None:
            raise LayoutError(f"未知布局 {layout_id!r}")
        return build_layout(json.loads(row[0]))

    def list_layouts(self) -> list[str]:
        return [
            row[0]
            for row in self.connection.execute(
                "SELECT layout_id FROM layouts ORDER BY layout_id"
            )
        ]

    # ------------------------------------------------------------------ packets
    def import_packet(self, packet: Mapping[str, object]) -> str:
        """原子导入单个包登记。

        返回状态字符串：``"imported"``（新导入）、``"duplicate"``（同 ID 同
        字节重送，不双写）、``"pending"``（布局未知，整包待解析）。
        """
        packet_id = packet.get("packet_id")
        layout_id = packet.get("layout_id")
        shot_count = packet.get("shot_count")
        payload_b64 = packet.get("payload_base64")
        sha256 = packet.get("sha256")
        if not isinstance(packet_id, str) or not packet_id:
            raise PacketError("packet_id 必须是非空字符串")
        if not isinstance(layout_id, str) or not layout_id:
            raise PacketError(f"包 {packet_id}: layout_id 必须是非空字符串")
        if not isinstance(shot_count, int) or isinstance(shot_count, bool) or shot_count < 0:
            raise PacketError(f"包 {packet_id}: shot_count 必须是非负整数")
        if not isinstance(payload_b64, str):
            raise PacketError(f"包 {packet_id}: payload_base64 必须是字符串")
        if not isinstance(sha256, str):
            raise PacketError(f"包 {packet_id}: sha256 必须是字符串")

        # 先做字节级校验，任何失败都发生在写事务之前。
        payload = decode_base64_payload(payload_b64)
        verify_sha256(payload, sha256, packet_id)

        existing = self.connection.execute(
            "SELECT sha256 FROM packets WHERE packet_id = ?", (packet_id,)
        ).fetchone()
        if existing is not None:
            if existing[0] == sha256.lower():
                return "duplicate"
            raise PacketConflict(
                f"packet_id {packet_id} 已登记不同字节（SHA256 {existing[0]} != {sha256}）"
            )
        queued = self.connection.execute(
            "SELECT sha256 FROM pending_packets WHERE packet_id = ?", (packet_id,)
        ).fetchone()
        if queued is not None:
            if queued[0] != sha256.lower():
                raise PacketConflict(
                    f"packet_id {packet_id} 在待解析队列中且内容不同（{queued[0]} != {sha256}）"
                )
            # pending 中的同 ID 同字节副本：若布局仍未知则保持 pending。
        if layout_id not in self.list_layouts():
            self._upsert_pending(packet_id, layout_id, shot_count, payload_b64, sha256, len(payload))
            self.connection.commit()
            return "pending"

        layout = self.get_layout(layout_id)
        # 单事务：包登记 + 全部事实，任何异常整体回滚。
        try:
            with self.connection:
                if queued is None:
                    self._upsert_pending(
                        packet_id, layout_id, shot_count, payload_b64, sha256, len(payload)
                    )
                self.connection.execute(
                    "INSERT INTO packets(packet_id, layout_id, shot_count, payload_b64, "
                    "sha256, payload_len) VALUES (?, ?, ?, ?, ?, ?)",
                    (packet_id, layout_id, shot_count, payload_b64, sha256.lower(), len(payload)),
                )
                self._insert_facts(packet_id, layout, payload, shot_count)
                self.connection.execute(
                    "DELETE FROM pending_packets WHERE packet_id = ?", (packet_id,)
                )
        except Exception:
            # with 已回滚；确认没有前半包事实残留后原样抛出。
            assert self.connection.execute(
                "SELECT COUNT(*) FROM facts WHERE packet_id = ?", (packet_id,)
            ).fetchone()[0] == 0
            raise
        return "imported"

    def _upsert_pending(
        self,
        packet_id: str,
        layout_id: str,
        shot_count: int,
        payload_b64: str,
        sha256: str,
        payload_len: int,
    ) -> None:
        self.connection.execute(
            "INSERT OR IGNORE INTO pending_packets(packet_id, layout_id, shot_count, "
            "payload_b64, sha256, payload_len) VALUES (?, ?, ?, ?, ?, ?)",
            (packet_id, layout_id, shot_count, payload_b64, sha256.lower(), payload_len),
        )

    def _insert_facts(
        self, packet_id: str, layout: Layout, payload: bytes, shot_count: int
    ) -> None:
        # 生成器按 shot 惰性产出事实行，executemany 边消费边写，
        # 内存上界是单个 shot 的行数，不随 shot_count 增长。
        def rows() -> Iterable[tuple[object, ...]]:
            for shot_index, facts in iter_decoded_shots(layout, payload, shot_count):
                for fact in facts:
                    channel = layout.channel(fact.channel_id)
                    yield (
                        packet_id,
                        layout.layout_id,
                        layout.digest,
                        shot_index,
                        fact.channel_id,
                        channel.bit_offset,
                        channel.width,
                        channel.valid_bit,
                        1 if fact.valid else 0,
                        fact.value,
                        fact.raw_value,
                    )

        self.connection.executemany(
            "INSERT INTO facts(packet_id, layout_id, layout_digest, shot_index, "
            "channel_id, bit_offset, width, valid_bit, valid, value, raw_value) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            rows(),
        )

    def replay_pending(self) -> dict[str, str]:
        """尝试导入全部待解析包；返回 packet_id -> imported/failed 原因状态。"""
        queued = self.connection.execute(
            "SELECT packet_id, layout_id, shot_count, payload_b64, sha256, payload_len "
            "FROM pending_packets ORDER BY packet_id"
        ).fetchall()
        results: dict[str, str] = {}
        for packet_id, layout_id, shot_count, payload_b64, sha256, payload_len in queued:
            if layout_id not in self.list_layouts():
                results[packet_id] = "pending"
                continue
            packet = {
                "packet_id": packet_id,
                "layout_id": layout_id,
                "shot_count": shot_count,
                "payload_base64": payload_b64,
                "sha256": sha256,
            }
            try:
                results[packet_id] = self.import_packet(packet)
            except PacketError as exc:
                # 保留在 pending 队列，等待修正后的材料。
                self.connection.rollback()
                results[packet_id] = f"failed: {exc}"
        return results

    # ------------------------------------------------------------------ queries
    def get_facts(
        self, packet_id: str | None = None, channel_id: str | None = None
    ) -> list[sqlite3.Row]:
        query = (
            "SELECT packet_id, layout_id, layout_digest, shot_index, channel_id, "
            "bit_offset, width, valid_bit, valid, value, raw_value "
            "FROM facts WHERE 1 = 1"
        )
        params: list[object] = []
        if packet_id is not None:
            query += " AND packet_id = ?"
            params.append(packet_id)
        if channel_id is not None:
            query += " AND channel_id = ?"
            params.append(channel_id)
        query += " ORDER BY packet_id, shot_index, channel_id"
        self.connection.row_factory = sqlite3.Row
        return self.connection.execute(query, params).fetchall()

    def channel_counts(self, packet_id: str | None = None) -> list[sqlite3.Row]:
        """按 channel 统计有效0 / 有效非0 / 无效三类，三者之和等于 shot_count。"""
        where = ""
        params: list[object] = []
        if packet_id is not None:
            where = "WHERE f.packet_id = ?"
            params.append(packet_id)
        self.connection.row_factory = sqlite3.Row
        return self.connection.execute(
            "SELECT f.channel_id AS channel_id, "
            "SUM(CASE WHEN f.valid = 1 AND f.value = 0 THEN 1 ELSE 0 END) AS valid_zero, "
            "SUM(CASE WHEN f.valid = 1 AND f.value <> 0 THEN 1 ELSE 0 END) AS valid_nonzero, "
            "SUM(CASE WHEN f.valid = 0 THEN 1 ELSE 0 END) AS invalid, "
            "COUNT(*) AS total "
            "FROM facts f " + where + " GROUP BY f.channel_id ORDER BY f.channel_id",
            params,
        ).fetchall()

    def packet_shots(self, packet_id: str) -> int:
        row = self.connection.execute(
            "SELECT shot_count FROM packets WHERE packet_id = ?", (packet_id,)
        ).fetchone()
        if row is None:
            raise PacketError(f"未知 packet_id {packet_id!r}")
        return int(row[0])

    def rebuild_payload(self, packet_id: str) -> tuple[bytes, bytes]:
        """从仓内事实反向编码重建载荷，返回 (原始登记字节, 重建字节)。

        重建包含无效字段的原位 raw_value；调用方可直接断言两字节相等。
        """
        row = self.connection.execute(
            "SELECT p.payload_b64, p.shot_count, p.layout_id FROM packets p "
            "WHERE p.packet_id = ?",
            (packet_id,),
        ).fetchone()
        if row is None:
            raise PacketError(f"未知 packet_id {packet_id!r}")
        payload_b64, shot_count, layout_id = row
        original = decode_base64_payload(payload_b64)
        layout = self.get_layout(layout_id)
        channel_order = [channel.channel_id for channel in layout.channels]
        grouped: dict[int, dict[str, ShotFact]] = {}
        for fact_row in self.get_facts(packet_id):
            grouped.setdefault(fact_row["shot_index"], {})[fact_row["channel_id"]] = ShotFact(
                channel_id=fact_row["channel_id"],
                value=fact_row["value"],
                raw_value=fact_row["raw_value"],
                valid=bool(fact_row["valid"]),
            )
        shot_iter = (
            [grouped[index][channel_id] for channel_id in channel_order]
            for index in range(shot_count)
        )
        rebuilt = encode_payload(layout, shot_iter, shot_count=shot_count)
        return original, rebuilt

    def pending_ids(self) -> list[str]:
        return [
            row[0]
            for row in self.connection.execute(
                "SELECT packet_id FROM pending_packets ORDER BY packet_id"
            )
        ]

    def packet_ids(self) -> list[str]:
        return [
            row[0]
            for row in self.connection.execute(
                "SELECT packet_id FROM packets ORDER BY packet_id"
            )
        ]


# --------------------------------------------------------------------------- CLI
def _cli(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="把合成包与布局导入 SQLite 事实仓（不运行实验、不推断物理状态）"
    )
    parser.add_argument("--db", default=".workspace-output/facts.sqlite3", help="SQLite 路径")
    parser.add_argument("--layouts", default="fixtures/layouts.json")
    parser.add_argument("--packets", default="fixtures/packets.json")
    args = parser.parse_args(argv)

    layouts_doc = json.loads(Path(args.layouts).read_text(encoding="utf-8"))
    packets_doc = json.loads(Path(args.packets).read_text(encoding="utf-8"))

    summary: dict[str, object] = {}
    with FactWarehouse(args.db) as warehouse:
        summary["layouts_added"] = warehouse.register_layouts_doc(layouts_doc)
        statuses = [warehouse.import_packet(packet) for packet in packets_doc["packets"]]
        summary["packet_status"] = dict(
            zip((p["packet_id"] for p in packets_doc["packets"]), statuses)
        )
        summary["pending"] = warehouse.pending_ids()
        summary["channel_counts"] = [dict(row) for row in warehouse.channel_counts()]
        checks: dict[str, bool] = {}
        for packet_id in warehouse.packet_ids():
            original, rebuilt = warehouse.rebuild_payload(packet_id)
            checks[packet_id] = original == rebuilt
        summary["roundtrip_ok"] = checks
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(_cli())
