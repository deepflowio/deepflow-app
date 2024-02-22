
### 关联 flow

- 根据`tcp_seq`获取`network span`和`service间调用的system span`数据
  - `type=request`，使用`req_tcp_seq`关联查询，相同`req_tcp_seq`的`flow`会被关联 
  ```
  req_tcp_seq={flow.req_tcp_seq}
  ```
  - `type=response`，使用`resp_tcp_seq`关联查询，相同`resp_tcp_seq`的`flow`会被关联
  ```
  resp_tcp_seq={flow.resp_tcp_seq}
  ```
  - `type=session`: 使用`req_tcp_seq`和`resp_tcp_seq`关联查询
  ```
  (req_tcp_seq={flow.req_tcp_seq} or resp_tcp_seq={flow.resp_tcp_seq})
  ```
  - 额外条件
  ```
  resp_tcp_seq!=0 OR req_tcp_seq!=0
  span_id相同
  x_request_id相同
  ```
  - [具体代码](https://github.com/deepflowys/deepflow-app/blob/cb291e7da0c5f1239225bbdcd6fa7e76ff1fe476/app/app/application/l7_flow_tracing.py#L550)
- 根据`syscalltraceid`获取`service内部的system span`数据
  - `syscall_trace_id_request`以及`syscall_trace_id_response`只要不为0则都会被关联查询
  ```
  syscall_trace_id_request={flow.syscall_trace_id_request} OR syscall_trace_id_response={flow.syscall_trace_id_request} OR 
  syscall_trace_id_request={flow.syscall_trace_id_response} OR syscall_trace_id_response={flow.syscall_trace_id_response}
  ```
  - 额外条件
  ```
  vtap_id相同
  x_request_id相同
  ```
  - [具体代码](https://github.com/deepflowys/deepflow-app/blob/cb291e7da0c5f1239225bbdcd6fa7e76ff1fe476/app/app/application/l7_flow_tracing.py#L630)
- 获取`app span`数据
  - 根据`trace_id`关联查询
  - 根据`parent_span_id`或`span_id`标记关联关系
  ```
  parent_span_id={flow.span_id} OR span_id={flow.span_id}
  span_id={flow.parent_span_id}
  ```
  [具体代码](https://github.com/deepflowys/deepflow-app/blob/cb291e7da0c5f1239225bbdcd6fa7e76ff1fe476/app/app/application/l7_flow_tracing.py#L502)
- 获取`x_request_id`关联数据
  ```
  x_request_id={flow.x_request_id}
  ```
  [具体代码](https://github.com/deepflowys/deepflow-app/blob/cb291e7da0c5f1239225bbdcd6fa7e76ff1fe476/app/app/application/l7_flow_tracing.py#L480)
- 获取`trace_id`关联数据
  ```
  trace_id={trace_id}
  ```
  [具体代码](https://github.com/deepflowys/deepflow-app/blob/cb291e7da0c5f1239225bbdcd6fa7e76ff1fe476/app/app/application/l7_flow_tracing.py#L459)
- 将上述所有条件用`OR`进行拼接，查询所有符合条件的flow，然后进行细粒度的筛选：
  - network span
      - 时间范围差距不能超过配置的网络最大时延`network_delay_us`
      ```
      abs(self.start_time_us - flow.start_time_us) <= self.network_delay_us
      abs(self.end_time_us - flow.end_time_us) <= self.network_delay_us
      ```
- 查询结果中增加对关联关系的描述
  - 字段：`related_ids`
  - 值：[flowindex-关联type-数据库id]，例如：`["16-traceid-7148686813239271301", "1-app-7148686813239271297"]`
  - 标记数据是如何关联
    - `network`，表示是通过`tcp_seq`关联出的数据
    - `syscall`，表示是通过`syscalltraceid`关联出的数据
    - `app`，表示是通过`span_id`以及`parent_span_id`关联出的数据
    - `traceid`，表示是通过`trace_id`关联出的数据
    - `xrequestid`，表示是通过`x_request_id`关联出的数据
<
<a id="merge_flow"></a>

### 合并 flow

- 以下`flow`不进行合并
  - `type == session && tap_side != sysspan`的非系统span
  - `tap_side != system span`时，每条`flow`的`_id`最多只有一来一回两条， 大于等于两条
  - `vtap_id`, `tap_port`, `tap_port_type`, `l7_protocol`, `request_id`, `tap_side`, `flow_id`不同
  - `request`的`start_time`大于`response`的`start_time`
- 系统Span的`flow`满足以下条件才合并
  - 应用协议为DNS，request_flow的type==session
  - response_flow的type==response
  - request_flow的cap_seq_1+1==response_flow的cap_seq_1
- 合并字段，被合并的`flow`会将`原始flow`中缺少的字段补充进去
  - `flow['type'] == 0`是，按以下字段合并
  ```
  l7_protocol，protocol，version，request_type，request_domain，request_resource，request_id
  ```
  - `flow['type'] == 1`时，按以下字段合并
  ```
  response_status，response_code，response_exception，response_result，http_proxy_client
  ```
  - `flow['type'] == 其他`时，按以下字段合并
  ```
  l7_protocol，protocol，version，
  request_type，request_domain，request_resource，request_id，
  response_status，response_code，response_exception，response_result，
  http_proxy_client，trace_id，span_id，x_request_id
  ]
  ```
  - `request`和`response`合并时，会设置`flow['type;] = 2（session）`
  - `system span`首次合并如果失败，需要将`flow`倒序，再进行第二次合并
- [具体代码](https://github.com/deepflowys/deepflow-app/blob/cb291e7da0c5f1239225bbdcd6fa7e76ff1fe476/app/app/application/l7_flow_tracing.py#L903)

<a id="sort_flow"></a>

### 排序

- 构建`service `
  - `进程span` [Service](https://github.com/deepflowys/deepflow-app/blob/cb291e7da0c5f1239225bbdcd6fa7e76ff1fe476/app/app/application/l7_flow_tracing.py#L759)
    - 基于每个`tap_side = s-p`的`flow`构建一个`service`
    - 将每个`tap_side = c-p`的`flow`添加进所属的`service`中
      - 判断所属`service`的逻辑：`vtap_id`，`process_id`与`service`相同，并且`s-p`的时间范围需要覆盖`c-p`，有多个`service`符合条件的情况下选择`start_time`最近的。
  - `应用span`添加进`service` [attach_app_flow](https://github.com/deepflowys/deepflow-app/blob/cb291e7da0c5f1239225bbdcd6fa7e76ff1fe476/app/app/application/l7_flow_tracing.py#L854)
    - `应用span`的`span_id`与`系统span_id`相同时，如果`系统span`的`tap_side = c-p`，则将该`应用span`添加进`service`
    - `应用span`的`parent_id`与`系统span_id`相同时，如果`系统span`的`tap_side = s-p`，且不存在和`s-p`相同的`c-p`，将该`应用span`添加进`service`
    - 两条`应用span`的`span_id`有关联且`service_name`相同时，将其中一条还未添加进`service`的`flow`添加进另一条`flow`所属的`service`中
- 设置`parent`
  - `网络span` [network_flow_sort](https://github.com/deepflowys/deepflow-app/blob/cb291e7da0c5f1239225bbdcd6fa7e76ff1fe476/app/app/application/l7_flow_tracing.py#L1171)
    - 存在`tcp_seq`相同的`flow`，非`local`和`rest`按照以下优先级确认`parent`，`local`和`rest`就近（比较采集器）排到其他位置（tcp_seq 相同）附近（按时间排）
    ```
    c, c-nd, c-hv, c-gw-hv, c-gw, s-gw, s-gw-hv, s-hv, s-nd, s
    ```
    -  存在`span_id`相同的`应用span`，将该`网络span`的`parent`设置为该`span_id`相同的`应用span`
  - `应用span` [app_flow_sort](https://github.com/deepflowys/deepflow-app/blob/cb291e7da0c5f1239225bbdcd6fa7e76ff1fe476/app/app/application/l7_flow_tracing.py#L1179)
    - 若存在`parent_span_id`，且`tap_side = s`的`flow`的`span_id`等于`parent_span_id`,则将该`应用span`的`parent`设置为该`flow`
    - 若存在`parent_span_id`，且`span_id`等于该`parent_span_id`的`flow`存在`span_id`相同的`网络span`，则将该`应用span`的`parent`设置为该`网络span`
    - 若存在`parent_span_id`, 将该应用span的parent设置为span_id等于该parent_span_id的flow
    - 若有所属`service`，将该`应用span`的`parent`设置为该`service`的`s-p`的`flow`
  - `系统span`
    - `tap_side = c` [c-p_flow_sort](https://github.com/deepflowys/deepflow-app/blob/cb291e7da0c5f1239225bbdcd6fa7e76ff1fe476/app/app/application/l7_flow_tracing.py#L1181)
      - 存在`span_id`相同的`应用span`，将该`系统span`的`parent`设置为该`span_id`相同的`应用span`
      - 所属`service`中存在`应用span`，将该`系统span`的`parent`设置为`service`中最后一条`应用span`
      - 存在`syscalltraceid`相同且`tap_side = s`的`系统span`，该`系统span`的`parent`设置为该`flow`(`syscalltraceid`相同且`tap_side = s`)
    - `tap_side = s` [s-p_flow_sort](https://github.com/deepflowys/deepflow-app/blob/cb291e7da0c5f1239225bbdcd6fa7e76ff1fe476/app/app/application/l7_flow_tracing.py#L1186)
      - 存在`span_id`相同的`应用span`，将该`系统span`的`parent`设置为该`span_id`相同的`应用span`
      - 存在`span_id`相同且存在`parent_span_id`的`flow`，将该`系统span`的`parent`设置为`span_id`等于该`parent_span_id`的`flow`
- [具体代码](https://github.com/deepflowys/deepflow-app/blob/cb291e7da0c5f1239225bbdcd6fa7e76ff1fe476/app/app/application/l7_flow_tracing.py#L1013)
