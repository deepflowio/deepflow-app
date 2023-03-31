# DeepFlow-app

DeepFlow-app 是在[DeepFlow](https://github.com/deepflowys/deepflow)可观测性平台基础上，提供调用链路追踪功能

## 背景和前提

DeepFlow 将系统调用和网络调用相关的细节以 Log Event 格式存储下来，依据 Flow `type` 分类存在这样三种数据：
- request: 单次请求 Event 数据。
- response: 单次响应 Event 数据。
- session: 一次会话 Event 数据，这类数据符合类 Span 数据的基本定义。

所以，这里是将已经存在的 Flow Log Event 转换为类 Span 数据，即：合并 flow `type` 里的 request 和 response 数据为 seesion 数据，并和隶属同一次调用的 session 数据合并排序，转换为符合调用栈顺序的类 Span 数据。

## 如何关联 Flow Log

- 依据`_id`查询到相关的所有 Flow Log Event。
  - 使用 tcp_seq 查询 net span。
  - 使用 syscall_trace_id 查询 sys span。
  - 使用 trace_id, span_id, parent_span_id, x_request_id 查询 app span(APM) 数据。
- 将 request 和 response 数据合并为 seesion 数据，构造类 Span 数据。
- 排序合并后的数据，构建符合调用栈的类 Span 数据。

## 其他
相关细节请参考[这里](https://github.com/deepflowio/deepflow-app/blob/feature-edit-desc/HOW-TO-GET-SPAN-LIKE-DATA.md)
