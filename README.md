# 位布局版本驱动的实验读数事实展开

本项目保存虚构实验设施的仓湖源数据与Python读取工具。全部设备、样品、记录和数值均为合成，工具不连接设备、不运行实验、不推断物理状态，只做字节与位域的机械展开、入仓和反向重建。

## 字段与单位

payload_base64是手工给定的字节载荷，SHA256验证完整字节；layout以每shot字节数及物理bit_offset描述，最低offset对应最低有效位。

## 位布局解码入仓组件

### 模块

- `src/bit_codec.py`：纯位编解码核心（无存储依赖）。按 `byte_lsb0` 约定编号：一个 shot 的第一个字节最低位为 0，跨字节连续递增；字段值按低 offset 为低有效位组合（等价于把 shot 视为小端整数后移位取位）。
- `src/fact_warehouse.py`：SQLite 事实仓与 CLI，包级原子导入、待解析队列、重放、统计与反向编码核对。
- `src/packet_reader.py`：原有只读 JSON/CSV/JSONL 加载器，保持不变。

### 语义约定

- 每个包登记 `packet_id`、`layout_id`、`shot_count`、base64 载荷与 SHA256；base64 严格解码（拒绝空白与非字母表字符），哈希不符整包拒绝。
- 每个 channel 有值域（`bit_offset`+`width`）和一个 `valid_bit`。`valid=0` 时事实值为 NULL，值字段的原位原始位保留在 `raw_value`；反向编码按 `raw_value` 原位写回，绝不用 NULL 填 0。
- padding 位必须为 0；包长度必须恰好等于 `shot_count * stride_bytes`，尾部残片一律拒绝。
- channel 身份是 `channel_id`：布局换版可以移动位位置，但不更换身份。重复 channel_id、值域互相交叠、valid 落入值域或 padding、位覆盖不全均为非法布局。
- 单字节 v1 布局（A 值位 0..1、valid 位 2、其余 padding）：`0x05` 是有效值 1；`0x00` 是无效且原值 0；`0x01` 是无效且原值 1。后两者事实值同为 NULL，但 `raw_value` 分别为 0 和 1，是两份不同的原始证据。

### 存储选型：长表

facts 表每行一个 shot × channel，单独携带 `raw_value`、位域（bit_offset/width/valid_bit）、布局摘要 digest 与 packet 溯源。选择长表是因为布局可换版、channel 集合不固定，无需随布局迁移表结构；NULL（缺测）与 0（有效值零）在 SQL 层天然可区分，缺测不会被记成 0。每个事实都能回到包哈希（packets.sha256）、shot 序号、字段位域与布局摘要。

### 原子性、幂等与待解析

- 单个包的登记与全部事实展开在一个 SQLite 事务内提交；任何一步失败整体回滚，不留下前半包事实（有测试断言失败后 facts 行数为 0）。
- 相同 `packet_id` + 相同字节（SHA256）重送返回 `duplicate`，不双写；相同 `packet_id` + 不同字节抛 `PacketConflict` 拒绝。
- 未知布局的包整包进入 `pending_packets` 原封保存；补注册布局后 `replay_pending()` 重放。状态全部落在 SQLite 文件，进程重启后 pending 包仍可重放。
- 按 channel 统计三类数量：有效 0、有效非 0、无效，三者之和恒等于 `shot_count`（有断言）。

### 运行

Python 3.11以上，标准库即可，不需安装第三方依赖。

    python -m src.packet_reader fixtures/packets.json
    python -m src.fact_warehouse                      # 导入 fixtures 并打印统计与反向核对
    python -m compileall -q src tests
    python -m unittest discover -s tests -v

处理不可信材料时用隔离模式，并把可信源码目录显式加入 sys.path、材料只作路径参数传入：

    python -I -c "import sys; sys.path.insert(0, '$PWD'); from src.fact_warehouse import _cli; _cli()"

### 小包逐位核对与大包流式内存说明

小包走 `decode_payload` 全量展开，配合测试对 fixture p1 的三个字节逐位断言（0x05/0x00/0x01）并断言反向编码字节相等。

大包不要全量展开：`iter_packet_stream(layout, 分块字节流, shot_count)` 按固定块（如 4KB）喂入，内部只缓冲不足一个 stride 的残片，逐 shot 产出事实；`iter_encoded_shots` 逐 shot 反向编码，调用方分块写盘。内存上界为“块大小 + 一个 stride + 单 shot 事实”，与 shot_count 无关。入仓侧 `executemany` 消费的是惰性生成器，同样不物化整包。

本机实测（tracemalloc，100 万 shot、stride=1）：

| 路径 | 峰值内存 |
| --- | --- |
| 整包 `decode_payload`（全部 ShotFact 驻留） | 297.4 MB |
| `iter_packet_stream` 4KB 分块流式 | 0.37 MB |
| 事实仓流式导入（20 万 shot，SQLite 落盘） | 0.5 MB（库文件约 26 MB） |

## 固定容器

    docker build -t packed-measurement-facts:local .
    docker run --rm packed-measurement-facts:local

容器镜像以完整digest固定，默认仅检查输入契约；实现新增分析功能所需依赖由开发者明确登记。
