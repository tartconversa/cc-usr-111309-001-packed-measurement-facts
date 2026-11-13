"""入仓组件测试：原子性、幂等、冲突、待解析重放、重启恢复、溯源、统计。"""

import base64
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from src.bit_codec import (
    LayoutError,
    PacketError,
    build_layout,
    decode_base64_payload,
)
from src.fact_warehouse import FactWarehouse, PacketConflict

ROOT = Path(__file__).resolve().parents[1]

V1 = {
    "layout_id": "v1",
    "stride_bytes": 1,
    "channels": [{"channel_id": "A", "bit_offset": 0, "width": 2, "valid_bit": 2}],
    "padding_bits": [3, 4, 5, 6, 7],
    "bit_index": "byte_lsb0",
    "field_bit_significance": "increasing_offset_lsb_first",
}
V2_REPOSITION = {
    "layout_id": "v2",
    "stride_bytes": 1,
    "channels": [{"channel_id": "A", "bit_offset": 5, "width": 2, "valid_bit": 7}],
    "padding_bits": [0, 1, 2, 3, 4],
    "bit_index": "byte_lsb0",
    "field_bit_significance": "increasing_offset_lsb_first",
}


def packet(packet_id, layout_id, payload, shot_count=None):
    if shot_count is None:
        shot_count = len(payload)
    return {
        "packet_id": packet_id,
        "layout_id": layout_id,
        "shot_count": shot_count,
        "payload_base64": base64.b64encode(payload).decode("ascii"),
        "sha256": hashlib.sha256(payload).hexdigest(),
    }


class WarehouseTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Path(self.tmp.name) / "facts.sqlite3"
        self.warehouse = FactWarehouse(self.db)
        self.warehouse.register_layout(build_layout(V1))

    def tearDown(self):
        self.warehouse.close()
        self.tmp.cleanup()

    def test_fixture_p1_import_facts_and_counts(self):
        packets_doc = json.loads((ROOT / "fixtures/packets.json").read_text())
        statuses = [self.warehouse.import_packet(p) for p in packets_doc["packets"]]
        self.assertEqual(statuses, ["imported"])
        facts = self.warehouse.get_facts("p1")
        self.assertEqual(len(facts), 3)
        self.assertEqual(
            [(f["valid"], f["value"], f["raw_value"]) for f in facts],
            [(1, 1, 1), (0, None, 0), (0, None, 1)],
        )
        # NULL 与 0 在存储层是不同的：SQLite value 列真为 None，raw_value 保留位证据
        self.assertIsNone(facts[1]["value"])
        self.assertEqual(facts[1]["raw_value"], 0)
        self.assertIsNone(facts[2]["value"])
        self.assertEqual(facts[2]["raw_value"], 1)

        counts = self.warehouse.channel_counts("p1")
        self.assertEqual(len(counts), 1)
        row = counts[0]
        self.assertEqual(
            (row["channel_id"], row["valid_zero"], row["valid_nonzero"], row["invalid"], row["total"]),
            ("A", 0, 1, 2, 3),
        )
        self.assertEqual(row["valid_zero"] + row["valid_nonzero"] + row["invalid"], 3)
        self.assertEqual(row["total"], self.warehouse.packet_shots("p1"))

    def test_valid_zero_is_distinct_from_invalid(self):
        # 0x04 = valid(位2)=1, 值=0；0x00 = 无效原值0
        status = self.warehouse.import_packet(packet("pz", "v1", b"\x04\x00"))
        self.assertEqual(status, "imported")
        rows = {f["shot_index"]: f for f in self.warehouse.get_facts("pz")}
        self.assertEqual(rows[0]["value"], 0)
        self.assertEqual(rows[0]["valid"], 1)
        self.assertIsNone(rows[1]["value"])
        self.assertEqual(rows[1]["valid"], 0)
        counts = self.warehouse.channel_counts("pz")[0]
        self.assertEqual((counts["valid_zero"], counts["valid_nonzero"], counts["invalid"]), (1, 0, 1))

    def test_identical_resend_deduped_content_changed_rejected(self):
        p = packet("p1", "v1", b"\x05\x00\x01")
        self.assertEqual(self.warehouse.import_packet(p), "imported")
        self.assertEqual(self.warehouse.import_packet(dict(p)), "duplicate")
        self.assertEqual(self.warehouse.import_packet(dict(p)), "duplicate")
        self.assertEqual(len(self.warehouse.get_facts("p1")), 3)  # 不双写

        changed = packet("p1", "v1", b"\x05\x00\x00")
        with self.assertRaises(PacketConflict):
            self.warehouse.import_packet(changed)
        # 冲突不改变既有事实
        self.assertEqual(len(self.warehouse.get_facts("p1")), 3)

    def test_unknown_layout_queued_then_replay(self):
        p = packet("px", "v2", b"\x00")
        self.assertEqual(self.warehouse.import_packet(p), "pending")
        self.assertEqual(self.warehouse.pending_ids(), ["px"])
        self.assertEqual(self.warehouse.get_facts("px"), [])
        # 重启：新连接打开同一文件，pending 仍在
        self.warehouse.close()
        self.warehouse = FactWarehouse(self.db)
        self.assertEqual(self.warehouse.pending_ids(), ["px"])

        self.warehouse.register_layout(build_layout(V2_REPOSITION))
        results = self.warehouse.replay_pending()
        self.assertEqual(results, {"px": "imported"})
        self.assertEqual(self.warehouse.pending_ids(), [])
        facts = self.warehouse.get_facts("px")
        self.assertEqual(len(facts), 1)
        self.assertEqual(facts[0]["layout_id"], "v2")

    def test_pending_conflict_rejected(self):
        first = packet("pq", "v2", b"\x00")
        self.warehouse.import_packet(first)
        with self.assertRaises(PacketConflict):
            self.warehouse.import_packet(packet("pq", "v2", b"\x01"))

    def test_decode_failure_leaves_no_half_packet(self):
        # 3 个 shot，第 2 个 padding 非零 -> 整包回滚
        bad = packet("pb", "v1", b"\x05\x08\x00")
        with self.assertRaises(PacketError):
            self.warehouse.import_packet(bad)
        self.assertEqual(self.warehouse.get_facts("pb"), [])
        self.assertEqual(self.warehouse.packet_ids(), [])
        self.assertEqual(self.warehouse.pending_ids(), [])

    def test_bad_base64_and_bad_hash_rejected_before_write(self):
        p = packet("ph", "v1", b"\x05")
        p["payload_base64"] = "not@base64"
        with self.assertRaises(PacketError):
            self.warehouse.import_packet(p)
        p2 = packet("ph2", "v1", b"\x05")
        p2["sha256"] = "00" * 32
        with self.assertRaises(PacketError):
            self.warehouse.import_packet(p2)
        self.assertEqual(self.warehouse.packet_ids(), [])

    def test_fact_provenance_roundtrip(self):
        p = packet("pp", "v1", b"\x05\x00\x01")
        self.warehouse.import_packet(p)
        layout = self.warehouse.get_layout("v1")
        for fact in self.warehouse.get_facts("pp"):
            self.assertEqual(fact["packet_id"], "pp")
            self.assertEqual(fact["layout_digest"], layout.digest)
            self.assertIn(fact["shot_index"], range(3))
            self.assertEqual(fact["bit_offset"], 0)
            self.assertEqual(fact["width"], 2)
            self.assertEqual(fact["valid_bit"], 2)
        original, rebuilt = self.warehouse.rebuild_payload("pp")
        self.assertEqual(original, b"\x05\x00\x01")
        self.assertEqual(rebuilt, original)  # 无效字段原位值被完整重建

    def test_layout_redefinition_rejected(self):
        moved = dict(V1, layout_id="v1")
        moved["channels"] = [
            {"channel_id": "A", "bit_offset": 1, "width": 2, "valid_bit": 3}
        ]
        moved["padding_bits"] = [0, 4, 5, 6, 7]
        with self.assertRaises(LayoutError):
            self.warehouse.register_layout(build_layout(moved))
        # 重复注册相同布局幂等
        self.assertFalse(self.warehouse.register_layout(build_layout(V1)))

    def test_restart_recovery_and_rebuild_from_file(self):
        self.warehouse.import_packet(packet("pr", "v1", b"\x05\x01\x04"))
        self.warehouse.close()
        with FactWarehouse(self.db) as reopened:
            self.assertEqual(reopened.packet_ids(), ["pr"])
            original, rebuilt = reopened.rebuild_payload("pr")
            self.assertEqual(rebuilt, original)
            counts = reopened.channel_counts("pr")[0]
            self.assertEqual(
                (counts["valid_zero"], counts["valid_nonzero"], counts["invalid"]),
                (1, 1, 1),
            )

    def test_replay_keeps_failed_packet_pending(self):
        # v2 布局 padding 为位0..4；第二 shot 0x01 置位 padding，重放失败但保留 pending
        self.warehouse.import_packet(packet("pf", "v2", b"\x00\x01"))
        self.warehouse.register_layout(build_layout(V2_REPOSITION))
        results = self.warehouse.replay_pending()
        self.assertTrue(results["pf"].startswith("failed:"))
        self.assertEqual(self.warehouse.pending_ids(), ["pf"])
        self.assertEqual(self.warehouse.get_facts("pf"), [])


class CliTests(unittest.TestCase):
    def test_cli_end_to_end_on_fixtures(self):
        with tempfile.TemporaryDirectory() as directory:
            db = Path(directory) / "out.sqlite3"
            # 用 -I 隔离模式，显式把可信 src 放进 sys.path，fixtures 只作路径参数
            script = (
                "import sys; sys.path.insert(0, %r);"
                "from src.fact_warehouse import _cli; _cli()"
                % str(ROOT)
            )
            proc = subprocess.run(
                [sys.executable, "-I", "-c", script,
                 "--db", str(db),
                 "--layouts", str(ROOT / "fixtures/layouts.json"),
                 "--packets", str(ROOT / "fixtures/packets.json")],
                capture_output=True,
                text=True,
                cwd=directory,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            summary = json.loads(proc.stdout)
            self.assertEqual(summary["packet_status"], {"p1": "imported"})
            self.assertTrue(summary["roundtrip_ok"]["p1"])
            self.assertEqual(summary["channel_counts"][0]["invalid"], 2)


if __name__ == "__main__":
    unittest.main()
