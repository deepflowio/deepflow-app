# deepflow-app 项目

## 项目简介

deepflow-app 是 DeepFlow 的后端应用服务，核心功能是**分布式追踪火焰图计算**：将 DeepFlow 采集到的原始 L7 Flow 数据，通过多阶段流水线处理，输出一棵完整的 Span 树（火焰图）。

主要入口：[app/app/application/l7_flow_tracing.py](app/app/application/l7_flow_tracing.py)

---

## 技术约束

### 运行时
- **Python 3.10**
- 使用 `pandas.DataFrame` 承载原始 Flow 数据；排序阶段转为 `SpanNode` 对象图
- 异步框架：Sanic（HTTP 服务层）；业务逻辑为同步计算

### 配置
- 所有可调参数集中在 [app/app.yaml](app/app.yaml)，运行时通过 [app/app/config.py](app/app/config.py) 的 `config` 单例读取
- 新增可配置行为时，**必须**同步在 `app.yaml` 中添加注释说明，且默认值应保持向后兼容（opt-in 原则）

### 向后兼容原则
- **不得破坏已有追踪结果**：新增连接策略时，如果会影响到已有结果，必须默认关闭
- 修改现有连接条件时，需评估对存量用户火焰图结果的影响

---

## 核心架构：追踪流水线

```
Search → Merge → Sort → Prune → Statistics
搜索      合并     排序     裁剪     统计
```

### 1. 搜索（Search）
- 以「入口 Flow」为起点，迭代扩展，基于 `trace_id` / `tcp_seq` / `syscall_trace_id` / `x_request_id` 拉取关联 Flow
- 上限：`config.max_iteration`（默认 30）、`config.l7_tracing_limit`（默认 1000）
- 控制参数：`config.tracing_source`（列表，控制启用哪些扩展维度）

### 2. 合并（Merge）
- 将单向 Flow（只有请求或只有响应）合并成完整会话
- 按 `start_time` 升序，遇到 Response 合并到前置 Request

### 3. 排序（Sort）—— 最复杂阶段

#### SpanSet 构建

| 类型 | 组成 | 关键内部约束 |
|---|---|---|
| **NetworkSpanSet** | 0-1 个 c-p + N 个网络 Span + 0-1 个 s-p | ① 所有 Span 的 `tcp_seq` 必须相等；② 流信息（五元组等）必须相等 |
| **ProcessSpanSet** | 0-1 个 s-p + N 个 App Span + M 个 c-p | ① 所有 Span 的**进程信息**必须相等；② `s-p` 时间必须**完全覆盖** `c-p` |

#### SpanSet 连接（`_connect_process_and_networks`）

连接分两阶段执行：

**准确连接阶段（场景 1-6）**：基于强关联证据，依次执行，结果写入 `network_match_parent`

| 场景 | 连接方向 | 核心条件 |
|---|---|---|
| 1 | Process 叶 → NetworkSpanSet 根 | 共享同一 `c-p`，或叶 `span_id` = 网络首 `span_id` |
| 2 | NetworkSpanSet 尾 → Process 根 | 共享同一 `s-p`，或根 `span_id` = 网络尾 `parent_span_id`/`span_id` |
| 3 | Process 叶 → Process 根 | 共享同一 `c-p`，或叶 `span_id` = 根 `parent_span_id`/`span_id` |
| 4 | Process 根 → Process 内任意 | 根 `parent_span_id` = 目标 `span_id` |
| 5 | NetworkSpanSet → NetworkSpanSet | `x_request_id` 匹配 / `span_id` 相同 / gRPC `stream_id` 相同；前者 `response_duration` ≥ 后者 |
| 6 | NetworkSpanSet → NetworkSpanSet（异步 MQ） | `trace_id` 有交集；仅限 `is_async` 的 WebSphereMQ；client 开始时间早于 server |

**通用约束（场景 1-5）**：两 Span 不能属于同一 SpanSet；当在同一 Agent 下时，Parent 的时延必须大于 Child。

**弱关联阶段（场景 7）**：独立 pass，结果写入 `weak_match_parent`，不影响准确连接

| 场景 | 条件 | 配置开关 |
|---|---|---|
| 7 | client 侧叶（无子）→ server 侧根（无父，`is_net_root=True`）；`trace_id` 有交集且 `tcp_seq` 不同；叶 `response_duration` ≥ 根 | `span_set_connection_strategies: [net_span_c_to_s_via_trace_id]` |
| 8 | client 侧叶（无子）→ server 侧根（无父，`is_ps_root=True`）；`trace_id` 有交集且 `auto_instance` 和 `auto_instance_type` 不同；叶子和根的 `agent_id` 是同一个，且叶子时间覆盖根 | `span_set_connection_strategies: [sys_span_s_to_c_via_trace_id]` |

### 4. 裁剪（Prune）
- 存在多棵树时，以「入口 Span 所在的树」为基准，裁剪时钟偏差超出 `host_clock_offset_us` 的树
- 同 `trace_id` 的 Span 不裁剪；通过强关联（`x_request_id` 等）连接的不裁剪

### 5. 统计（Statistics）
- 自顶向下计算每个 Span 的自身时延（Parent 减去一级子节点时延之和）
- 按 AutoService 分组统计服务总时延

---

## Review / Lint 规范

### 添加新连接关系时的必检清单

添加新的 SpanSet 连接场景时（参考 `_connect_process_and_networks`），必须覆盖以下所有开发点：

#### 1. 核心逻辑
- [ ] 连接条件是否清晰定义（方向、字段、阈值）？
- [ ] 是否正确判断 `is_net_root` / `is_net_leaf` / `children_count` / `get_parent_id()` 等 SpanNode 状态？
- [ ] 是否调用 `_same_span_set()` 防止同组首尾互连？
- [ ] 是否检查 `response_duration` 约束（Parent 时延必须 ≥ Child 时延）？
- [ ] `set_parent()` 调用时是否传入了合理的 `reason` 字符串（用于调试日志）？

#### 2. 准确 vs 弱关联判断
- [ ] 新场景属于**准确连接**（强证据：`tcp_seq` / `span_id` / `x_request_id`）还是**弱关联**（推断性）？
- [ ] 弱关联场景必须：
  - 写入独立的 `weak_match_parent` dict，在准确连接阶段结束后单独执行
  - 通过 `config.span_set_connection_strategies` 配置 opt-in，默认不生效

#### 3. 配置
- [ ] 若新场景需要配置开关，是否在 `app/app/config.py` 的 `parse_spec()` 中读取并赋值到 `config` 对象？
- [ ] 是否在 `app/app.yaml` 的 `spec` 节添加了带注释的配置项（说明用途、默认值、可选值）？
- [ ] 默认值是否保持向后兼容（不改变现有用户的追踪结果）？

#### 4. 文档
- [ ] 是否更新了 [HOW-TO-GET-SPAN-LIKE-DATA.md](HOW-TO-GET-SPAN-LIKE-DATA.md) 的「SpanSet 连接」章节，新增场景的说明（连接方向、条件、配置项）？
- [ ] 是否更新了 [FlowTracingIssue.md](FlowTracingIssue.md) 中「SpanSet 连接」速查表？

---

### 性能检查

`_connect_process_and_networks` 是 O(N²) 的双层循环，N = 所有 SpanNode 数量（上限受 `l7_tracing_limit` 控制）。添加新场景时：

- [ ] **避免在内层循环中重复计算**：将不变量（如 `get_req_tcp_seq()`、`get_trace_id_set()`）提前缓存到局部变量
- [ ] **提前剪枝**：将最能过滤候选的条件放在内层循环最前面（fail-fast）
- [ ] **避免额外数据结构**：不在循环内部创建新 list/dict，若需要，用已有的 `flow_index_to_span` / `related_flow_index_map` 等结构
- [ ] **评估最坏情况**：在 `l7_tracing_limit=1000` 规模下，新场景的额外循环次数是否可接受？

---

## Python 代码审查

> 本项目为 Python，建议在完成较大改动后做专项审查。

检查要点：PEP 8 合规性、类型注解、Pythonic 惯用法、潜在的性能问题和安全风险。

---

## 关键文件索引

| 文件 | 作用 |
|---|---|
| [app/app/application/l7_flow_tracing.py](app/app/application/l7_flow_tracing.py) | 追踪流水线全部核心逻辑 |
| [app/app/config.py](app/app/config.py) | 配置解析，`config` 单例 |
| [app/app.yaml](app/app.yaml) | 配置文件模板及注释 |
| [HOW-TO-GET-SPAN-LIKE-DATA.md](HOW-TO-GET-SPAN-LIKE-DATA.md) | 追踪计算原理的完整设计文档 |
| [FlowTracingIssue.md](FlowTracingIssue.md) | 断链诊断知识库与速查表 |

## 关键函数索引

| 函数 | 位置 | 说明 |
|---|---|---|
| `_connect_process_and_networks` | l7_flow_tracing.py ~L3242 | SpanSet 连接，7 个场景 |
| `_same_span_set` | l7_flow_tracing.py ~L3235 | 防止同组首尾互连的工具函数 |
| `merge_flow` | l7_flow_tracing.py ~L1845 | 合并单向 Flow 为会话 |
| `Config.parse_spec` | config.py L17 | 解析 `spec` 配置节 |
