import math
import uuid
import pandas as pd
from log import logger
from typing import List, Dict, Set, Callable

from ast import Tuple
from pandas import DataFrame
from collections import defaultdict
from data.querier_client import Querier
from config import config
from .base import Base
from common import const
from common.utils import curl_perform, inner_defaultdict_int
from common.const import (HTTP_OK, L7_FLOW_SIGNAL_SOURCE_PACKET,
                          L7_FLOW_SIGNAL_SOURCE_EBPF,
                          L7_FLOW_SIGNAL_SOURCE_OTEL)
from common.disjoint_set import DisjointSet
from opentelemetry.sdk.trace.id_generator import RandomIdGenerator

log = logger.getLogger(__name__)

# 网络位置排序优先级，当采集到这些位置的 span 时固定按此位置排序
NET_SPAN_TAP_SIDE_PRIORITY = {
    item: i
    for i, item in enumerate(['c', 'c-nd', 's-nd', 's'])
}
L7_FLOW_TYPE_REQUEST = 0
L7_FLOW_TYPE_RESPONSE = 1
L7_FLOW_TYPE_SESSION = 2

TAP_SIDE_CLIENT_PROCESS = 'c-p'
TAP_SIDE_SERVER_PROCESS = 's-p'
TAP_SIDE_CLIENT_APP = 'c-app'
TAP_SIDE_SERVER_APP = 's-app'
TAP_SIDE_APP = 'app'
TAP_SIDE_SPAN_ID_RANKS = {
    TAP_SIDE_CLIENT_APP: 1,
    TAP_SIDE_SERVER_APP: 2,
    TAP_SIDE_CLIENT_PROCESS: 3,
    TAP_SIDE_SERVER_PROCESS: 4,
}

L7_FLOW_RELATIONSHIP_TCP_SEQ = 1
L7_FLOW_RELATIONSHIP_X_REQUEST_ID = 1 << 1
L7_FLOW_RELATIONSHIP_SYSCALL_TRACE_ID = 1 << 2
L7_FLOW_RELATIONSHIP_SPAN_ID = 1 << 3
L7_FLOW_RELATIONSHIP_DNS_REQUEST_ID = 1 << 4

# NOTE: 这里为了方便理解，不用数组而用 map
L7_FLOW_RELATIONSHIP_MAP = {
    L7_FLOW_RELATIONSHIP_TCP_SEQ:  # 1
    'network',
    L7_FLOW_RELATIONSHIP_X_REQUEST_ID:  # 2
    'xrequestid',
    L7_FLOW_RELATIONSHIP_TCP_SEQ | L7_FLOW_RELATIONSHIP_X_REQUEST_ID:  # 01 | 10
    'network,xrequestid',
    L7_FLOW_RELATIONSHIP_SYSCALL_TRACE_ID:  # 4
    'syscall',
    L7_FLOW_RELATIONSHIP_TCP_SEQ | L7_FLOW_RELATIONSHIP_SYSCALL_TRACE_ID:  # 001 | 100
    'network,syscall',
    L7_FLOW_RELATIONSHIP_X_REQUEST_ID | L7_FLOW_RELATIONSHIP_SYSCALL_TRACE_ID:  # 010 | 100
    'xrequestid,syscall',
    L7_FLOW_RELATIONSHIP_TCP_SEQ | L7_FLOW_RELATIONSHIP_X_REQUEST_ID | L7_FLOW_RELATIONSHIP_SYSCALL_TRACE_ID:  # 001 | 010 | 100
    'network,xrequestid,syscall',
    L7_FLOW_RELATIONSHIP_SPAN_ID:  # 8
    'app',
    L7_FLOW_RELATIONSHIP_TCP_SEQ | L7_FLOW_RELATIONSHIP_SPAN_ID:  # 0001 | 1000
    'network,app',
    L7_FLOW_RELATIONSHIP_X_REQUEST_ID | L7_FLOW_RELATIONSHIP_SPAN_ID:  # 0010 | 1000
    'xrequestid,app',
    L7_FLOW_RELATIONSHIP_TCP_SEQ | L7_FLOW_RELATIONSHIP_X_REQUEST_ID | L7_FLOW_RELATIONSHIP_SPAN_ID:  # 0001 | 0010 | 1000
    'network,xrequestid,app',
    L7_FLOW_RELATIONSHIP_SYSCALL_TRACE_ID | L7_FLOW_RELATIONSHIP_SPAN_ID:  # 0100 | 1000
    'syscall,app',
    L7_FLOW_RELATIONSHIP_TCP_SEQ | L7_FLOW_RELATIONSHIP_SYSCALL_TRACE_ID | L7_FLOW_RELATIONSHIP_SPAN_ID:  # 0001 | 0100 | 1000
    'network,syscall,app',
    L7_FLOW_RELATIONSHIP_X_REQUEST_ID | L7_FLOW_RELATIONSHIP_SYSCALL_TRACE_ID | L7_FLOW_RELATIONSHIP_SPAN_ID:  # 0010 | 0100 | 1000
    'xrequestid,syscall,app',
    L7_FLOW_RELATIONSHIP_TCP_SEQ | L7_FLOW_RELATIONSHIP_X_REQUEST_ID | L7_FLOW_RELATIONSHIP_SYSCALL_TRACE_ID | L7_FLOW_RELATIONSHIP_SPAN_ID:  # 0001 | 0010 | 0100 | 1000
    'network,xrequestid,syscall,app',
    L7_FLOW_RELATIONSHIP_DNS_REQUEST_ID:  # 16
    'request_id',
    L7_FLOW_RELATIONSHIP_TCP_SEQ | L7_FLOW_RELATIONSHIP_DNS_REQUEST_ID:  # 0001 | 0010
    'network,request_id',
    L7_FLOW_RELATIONSHIP_X_REQUEST_ID | L7_FLOW_RELATIONSHIP_DNS_REQUEST_ID:  # 0010 | 0010
    'xrequestid,request_id',
    L7_FLOW_RELATIONSHIP_TCP_SEQ | L7_FLOW_RELATIONSHIP_X_REQUEST_ID | L7_FLOW_RELATIONSHIP_DNS_REQUEST_ID:  # 0001 | 0010 | 0010
    'network,xrequestid,request_id',
    L7_FLOW_RELATIONSHIP_SYSCALL_TRACE_ID | L7_FLOW_RELATIONSHIP_DNS_REQUEST_ID:  # 0100 | 0010
    'syscall,request_id',
    L7_FLOW_RELATIONSHIP_TCP_SEQ | L7_FLOW_RELATIONSHIP_SYSCALL_TRACE_ID | L7_FLOW_RELATIONSHIP_DNS_REQUEST_ID:  # 0001 | 0100 | 0010
    'network,syscall,request_id',
    L7_FLOW_RELATIONSHIP_X_REQUEST_ID | L7_FLOW_RELATIONSHIP_SYSCALL_TRACE_ID | L7_FLOW_RELATIONSHIP_DNS_REQUEST_ID:  # 0010 | 0100 | 0010
    'xrequestid,syscall,request_id',
    L7_FLOW_RELATIONSHIP_TCP_SEQ | L7_FLOW_RELATIONSHIP_X_REQUEST_ID | L7_FLOW_RELATIONSHIP_SYSCALL_TRACE_ID | L7_FLOW_RELATIONSHIP_DNS_REQUEST_ID:  # 0001 | 0010 | 0100 | 0010
    'network,xrequestid,syscall,request_id',
    L7_FLOW_RELATIONSHIP_SPAN_ID | L7_FLOW_RELATIONSHIP_DNS_REQUEST_ID:  # 1000 | 0010
    'app,request_id',
    L7_FLOW_RELATIONSHIP_TCP_SEQ | L7_FLOW_RELATIONSHIP_SPAN_ID | L7_FLOW_RELATIONSHIP_DNS_REQUEST_ID:  # 0001 | 1000 | 0010
    'network,app,request_id',
    L7_FLOW_RELATIONSHIP_X_REQUEST_ID | L7_FLOW_RELATIONSHIP_SPAN_ID | L7_FLOW_RELATIONSHIP_DNS_REQUEST_ID:  # 0010 | 1000 | 0010
    'xrequestid,app,request_id',
    L7_FLOW_RELATIONSHIP_TCP_SEQ | L7_FLOW_RELATIONSHIP_X_REQUEST_ID | L7_FLOW_RELATIONSHIP_SPAN_ID | L7_FLOW_RELATIONSHIP_DNS_REQUEST_ID:  # 0001 | 0010 | 1000 | 0010
    'network,xrequestid,app,request_id',
    L7_FLOW_RELATIONSHIP_SYSCALL_TRACE_ID | L7_FLOW_RELATIONSHIP_SPAN_ID | L7_FLOW_RELATIONSHIP_DNS_REQUEST_ID:  # 0100 | 1000 | 0010
    'syscall,app,request_id',
    L7_FLOW_RELATIONSHIP_TCP_SEQ | L7_FLOW_RELATIONSHIP_SYSCALL_TRACE_ID | L7_FLOW_RELATIONSHIP_SPAN_ID | L7_FLOW_RELATIONSHIP_DNS_REQUEST_ID:  # 0001 | 0100 | 1000 | 0010
    'network,syscall,app,request_id',
    L7_FLOW_RELATIONSHIP_X_REQUEST_ID | L7_FLOW_RELATIONSHIP_SYSCALL_TRACE_ID | L7_FLOW_RELATIONSHIP_SPAN_ID | L7_FLOW_RELATIONSHIP_DNS_REQUEST_ID:  # 0010 | 0100 | 1000 | 0010
    'xrequestid,syscall,app,request_id',
    L7_FLOW_RELATIONSHIP_TCP_SEQ | L7_FLOW_RELATIONSHIP_X_REQUEST_ID | L7_FLOW_RELATIONSHIP_SYSCALL_TRACE_ID | L7_FLOW_RELATIONSHIP_SPAN_ID | L7_FLOW_RELATIONSHIP_DNS_REQUEST_ID:  # 0001 | 0010 | 0100 | 1000 | 0010
    'network,xrequestid,syscall,app,request_id'
}

RETURN_FIELDS = list(
    set([
        # 追踪Meta信息
        "signal_source",
        "l7_protocol",
        "Enum(l7_protocol)",
        "l7_protocol_str",
        "type",
        "req_tcp_seq",
        "resp_tcp_seq",
        "start_time_us",
        "end_time_us",
        "vtap_id",
        "tap_port",
        "tap_port_name",
        "tap_port_type",
        "resource_from_vtap",
        "syscall_trace_id_request",
        "syscall_trace_id_response",
        "syscall_cap_seq_0",
        "syscall_cap_seq_1",
        "trace_id",
        "span_id",
        "parent_span_id",
        "x_request_id_0",
        "x_request_id_1",
        "_id",
        "flow_id",
        "protocol",
        "version",
        # 资源信息
        "process_id_0",
        "process_id_1",
        "tap_side",
        "Enum(tap_side)",
        "subnet_id_0",
        "subnet_0",
        "ip_0",
        "auto_instance_type_0",
        "auto_instance_id_0",
        "auto_instance_0",
        "process_kname_0",
        "gprocess_0",
        "subnet_id_1",
        "subnet_1",
        "ip_1",
        "app_service",
        "app_instance",
        "auto_instance_type_1",
        "auto_instance_id_1",
        "auto_instance_1",
        "process_kname_1",
        "gprocess_1",
        "auto_service_type_0",
        "auto_service_id_0",
        "auto_service_0",
        "auto_service_type_1",
        "auto_service_id_1",
        "auto_service_1",
        "tap_id",
        "tap",
        # 用于 DNS 五元组匹配
        "client_port",
        "server_port",
        # 指标信息
        "response_status",
        "response_duration",
        "response_code",
        "response_exception",
        "response_result",
        "request_type",
        "request_domain",
        "request_resource",
        "request_id",
        "http_proxy_client",
        "endpoint",
    ]))
FIELDS_MAP = {
    "start_time_us": "toUnixTimestamp64Micro(start_time) as start_time_us",
    "end_time_us": "toUnixTimestamp64Micro(end_time) as end_time_us",
}
# 请求-响应合并的 key，当找到未合并的请求-响应时如果这些 key 相同，将合并为一个 span，标记为会话
MERGE_KEYS = [
    'l7_protocol', 'protocol', 'version', 'request_id', 'http_proxy_client',
    'trace_id', 'span_id', 'x_request_id_0', 'x_request_id_1',
    'l7_protocol_str', 'endpoint'
]
MERGE_KEY_REQUEST = [
    'l7_protocol', 'protocol', 'version', 'request_id', 'trace_id', 'span_id',
    'l7_protocol_str', 'endpoint'
]
MERGE_KEY_RESPONSE = ['http_proxy_client']
DATABASE = "flow_log"

L7_PROTOCOL_HTTP2 = 21
L7_PROTOCOL_GRPC = 41
L7_PROTOCOL_MYSQL = 60
L7_PROTOCOL_DNS = 120

L4_PROTOCOL_TCP = 6
L4_PROTOCOL_UDP = 17

# XXX: 目前是一个人为规定的设计，非协议捕获值
UNIX_SOCKET_SERVER_PORT = 1

# NOTE: 与上面的 L7_FLOW_RELATIONSHIP_MAP 不是同一种语义
TRACING_SRC_TRACE_ID = "trace_id"
TRACING_SRC_SYSCALL = "syscall"
TRACING_SRC_TCP_SEQ = "tcp_seq"
TRACING_SRC_X_REQ_ID = "x_request_id"
TRACING_SRC_DNS = "dns"

DEFAULT_TRACING_SOURCE = [
    TRACING_SRC_TRACE_ID, TRACING_SRC_SYSCALL, TRACING_SRC_TCP_SEQ,
    TRACING_SRC_X_REQ_ID, TRACING_SRC_DNS
]


class L7FlowTracing(Base):

    async def query(self):
        max_iteration = self.args.get("max_iteration", config.max_iteration)
        network_delay_us = self.args.get("network_delay_us")
        host_clock_offset_us = self.args.get("host_clock_offset_us")
        self.failed_regions = set()
        time_filter = f"time>={self.start_time} AND time<={self.end_time}"
        _id = self.args.get("_id")
        self.has_attributes = self.args.get("has_attributes", 0)
        if not _id:
            # tempo 查询入口，先根据 trace_id 获取到任意一个 _id
            trace_id = self.args.get("trace_id")
            _id = await self.get_id_by_trace_id(trace_id, time_filter)
            _id = str(_id)
            self.args._id = _id
        if not _id:
            return self.status, {}, self.failed_regions
        base_filter = f"_id={_id}"
        if self.signal_sources == ['otel']:
            base_filter += f" and signal_source={L7_FLOW_SIGNAL_SOURCE_OTEL}"
            max_iteration = 1
        rst = await self.trace_l7_flow(
            time_filter=time_filter,
            base_filter=base_filter,
            max_iteration=max_iteration,
            network_delay_us=network_delay_us,
            host_clock_offset_us=host_clock_offset_us)
        return self.status, rst, self.failed_regions

    async def get_id_by_trace_id(self, trace_id, time_filter):
        sql = f"SELECT toString(_id) AS `_id` FROM l7_flow_log WHERE FastFilter(trace_id)='{trace_id}' AND {time_filter} limit 1"
        resp = await self.query_ck(sql)
        self.status.append("Query _id", resp)
        data = resp["data"]
        if type(data) != DataFrame or data.empty:
            return ""
        return data["_id"][0]

    def concat_l7_flow_log_dataframe(self, dataframes: list):
        return pd.concat(dataframes, join="outer",
                         ignore_index=True).drop_duplicates(
                             ["_id"]).reset_index(drop=True)

    async def query_and_trace_flowmetas(
            self,
            time_filter: str,
            base_filter: str,
            max_iteration: int = config.max_iteration,
            network_delay_us: int = config.network_delay_us,
            host_clock_offset_us: int = config.host_clock_offset_us,
            app_spans_from_api: list = []) -> Tuple(list, list):
        """多次迭代，查询可追踪到的所有 l7_flow_log 的摘要
        参数说明：
        time_filter: 查询的时间范围过滤条件，SQL表达式
            当使用四元组进行追踪时，time_filter置为希望搜索的一段时间范围，
            当使用五元组进行追踪时，time_filter置为五元组对应流日志的start_time前后一小段时间，以提升精度
        base_filter: 查询的基础过滤条件，用于限定一个四元组或五元组
        max_iteration: 使用Flowmeta信息搜索的次数，每次搜索可认为大约能够扩充一级调用关系
        network_delay_us: 使用Flowmeta进行流日志匹配的时间偏差容忍度，越大漏报率越低但误报率越高，一般设置为网络时延的最大可能值
        host_clock_offset_us: 使用 Flowmeta 进行流日志匹配的时间偏差容忍度，一般设置为两两主机之间的时钟偏差最大值
        """
        only_query_app_spans = self.signal_sources == ['otel']

        req_tcp_seqs = set()  # set(str(req_tcp_seq))
        resp_tcp_seqs = set()  # set(str(resp_tcp_seq))
        syscall_trace_ids = set()  # set(str(syscall_trace_id))
        x_request_ids = set()  # set(x_request_id)
        dns_request_ids = set()  # set(request_id)
        app_spans_from_external = [
        ]  # 主动调用 APM API 或由 Tracing Completion API 传入

        allowed_trace_ids = set()  # 所有被允许的 trace_id 集合
        visited_trace_ids = set()  # 已访问过的 trace_id 集合
        new_trace_ids_for_next_iteration = set()  # 给下一轮迭代查询用的 trace_id 集合

        # Query1: 先获取 _id 对应的数据
        # don't use timefilter here, querier would extract time from _id (e.g.: id>>32)
        dataframe_flowmetas = await self.query_flowmetas("1=1", base_filter)
        if type(dataframe_flowmetas) != DataFrame or dataframe_flowmetas.empty:
            # when app_spans_from_api got values from api, return it
            return [], app_spans_from_api
        l7_flow_ids = set(dataframe_flowmetas['_id'])  # set(flow._id)
        trace_span_ids = set()  # set((flow.trace_id, flow.span_id))

        # 用于下一轮迭代，记录元信息
        build_req_tcp_seqs, build_resp_tcp_seqs, build_x_request_ids, build_syscall_trace_ids, build_request_ids = _build_simple_trace_info_from_dataframe(
            dataframe_flowmetas)

        # remember the initial trace_id
        initial_trace_id = self.args.get(
            "trace_id")  # For Tempo API & Tracing Completion API
        if not initial_trace_id:  # For normal query using _id
            trace_ids = dataframe_flowmetas.at[0, 'trace_id'] or ''
            for trace_id in trace_ids.split(","):
                trace_id = trace_id.strip()
                if not trace_id:
                    continue
                allowed_trace_ids.add(trace_id)
                new_trace_ids_for_next_iteration.add(trace_id)
        else:
            allowed_trace_ids.add(initial_trace_id)
            new_trace_ids_for_next_iteration.add(initial_trace_id)

        # append app_spans from Tracing Completion API
        app_spans_from_external.extend(app_spans_from_api)
        # for Tracing Completion API with multiple trace_id
        if app_spans_from_api and config.allow_multiple_trace_ids_in_tracing_result:
            for app_span in app_spans_from_api:
                trace_id = app_span.get('trace_id', '')
                if trace_id:
                    allowed_trace_ids.add(trace_id)
                    new_trace_ids_for_next_iteration.add(trace_id)

        # max_iterations set to 0 means 1
        # before, it means only query by trace_id
        # but now, we support multiple trace_ids,
        # it means we have to do query iteration multiple times even 'only_query_trace_id'
        # so it's no longer use for 'only_query_trace_id' anymore
        if max_iteration == 0:
            max_iteration = 1

        config.tracing_source = config.tracing_source or DEFAULT_TRACING_SOURCE

        # 进行迭代查询，上限为 config.spec.max_iteration
        for i in range(max_iteration):
            # 1. 使用 trace_id 查询
            if new_trace_ids_for_next_iteration and TRACING_SRC_TRACE_ID in config.tracing_source:
                # 1.1. Call external APM API
                if config.call_apm_api_to_supplement_trace and not config.apm_api_type_pinpoint:
                    new_app_spans_from_apm = []
                    for trace_id in new_trace_ids_for_next_iteration:
                        app_spans = await self.query_apm_for_app_span_completion(
                            trace_id)
                        new_app_spans_from_apm.extend(app_spans)
                    # 此处不需要将 new_app_spans_from_apm 合入 dataframe_flowmetas
                    # app_flow 对迭代查询过程没有更多的帮助
                    app_spans_from_external.extend(new_app_spans_from_apm)

                # 1.2. Query database by trace_id
                new_trace_ids_str = set(
                    [f"'{nti}'" for nti in new_trace_ids_for_next_iteration])
                query_trace_filters = [
                    f"FastFilter(trace_id) IN ({','.join(new_trace_ids_str)})"
                ]
                if only_query_app_spans:
                    query_trace_filters.append(
                        f"signal_source={L7_FLOW_SIGNAL_SOURCE_OTEL}")

                # Query2: 基于 trace_id 获取相关数据，第一层迭代
                new_trace_id_flows = pd.DataFrame()
                new_trace_id_flows = await self.query_flowmetas(
                    time_filter, ' AND '.join(query_trace_filters))

                # 已查询过一次的 trace_id，直接加入 visited，不需要再被查询
                # new_trace_ids_for_next_iteration 已被查询，可在这一步直接清空
                visited_trace_ids.update(new_trace_ids_for_next_iteration)
                new_trace_ids_for_next_iteration.clear()

                if type(new_trace_id_flows
                        ) == DataFrame and not new_trace_id_flows.empty:
                    # remove duplicate or trace_id conflict flows
                    new_trace_id_flow_delete_index = []
                    deleted_trace_ids = set()  # XXX: for debug only
                    for index in range(len(new_trace_id_flows.index)):
                        # delete dup _id
                        _id = new_trace_id_flows.at[index, '_id']
                        if _id in l7_flow_ids:
                            new_trace_id_flow_delete_index.append(index)
                            continue
                        # remove conflict trace_id data, since FastFilter(trace_id) has false positives
                        # 若启用 #deepflow-server:/config.trace-id-with-index，仅会使用 trace_id 的哈希进行过滤，
                        # 因此要去掉不在 allowed_trace_ids 中的 trace_id，否则会有误报。
                        new_trace_ids = new_trace_id_flows.at[index,
                                                              'trace_id']
                        # 这里做一个特殊处理：
                        # 首先，存在上述「误查询」情况，可能会把一些「非预期」的 trace_id 查出来
                        # 其次，需要兼容 trace_ids 也即多个 trace_id 的情况
                        # 所以，这里特殊地针对 new_trace_ids 做分割，如果发现 len>1，说明是多 trace_id 场景，尝试 append 到 new_trace_ids_for_next_iteration 中
                        # 如果 len=1，有两种情况：1.误查询，这类需要去掉；2. 上一轮的多 trace_id 的结果，此类情况应在上一轮已被纳入 visited_trace_id 中，不需要重复 append，所以也丢弃即可。
                        new_trace_id_arr = [
                            new_trace_id.strip()
                            for new_trace_id in new_trace_ids.split(",")
                            if new_trace_id.strip()
                        ]
                        if len(new_trace_id_arr) > 1:
                            for new_trace_id in new_trace_id_arr:
                                if new_trace_id not in visited_trace_ids:
                                    allowed_trace_ids.add(new_trace_id)
                                    new_trace_ids_for_next_iteration.add(
                                        new_trace_id)
                        elif len(new_trace_id_arr) == 1:
                            new_trace_id = new_trace_id_arr[0]
                            if new_trace_id not in allowed_trace_ids:
                                new_trace_id_flow_delete_index.append(index)
                                deleted_trace_ids.add(new_trace_id)
                        else:
                            # 这里还会有 trace_id_index 相同，但 trace_id = 空的情况，把 len=0 也丢弃
                            new_trace_id_flow_delete_index.append(index)
                    if new_trace_id_flow_delete_index:
                        new_trace_id_flows = new_trace_id_flows.drop(
                            new_trace_id_flow_delete_index).reset_index(
                                drop=True)
                    if deleted_trace_ids:
                        log.debug(f"删除的 trace_id 为：{deleted_trace_ids}")

                    # update dataframe_flowmetas and l7_flow_ids
                    dataframe_flowmetas = self.concat_l7_flow_log_dataframe(
                        [dataframe_flowmetas, new_trace_id_flows])
                    l7_flow_ids = set(dataframe_flowmetas['_id'])
                    for i in range(len(dataframe_flowmetas['trace_id'])):
                        trace_span_ids.add((dataframe_flowmetas['trace_id'][i],
                                            dataframe_flowmetas['span_id'][i]))

                    new_trace_req_tcp_seqs, new_trace_resp_tcp_seqs, new_trace_x_request_ids, new_trace_syscall_trace_ids, new_request_ids = _build_simple_trace_info_from_dataframe(
                        new_trace_id_flows)
                    build_req_tcp_seqs += new_trace_req_tcp_seqs
                    build_resp_tcp_seqs += new_trace_resp_tcp_seqs
                    build_x_request_ids += new_trace_x_request_ids
                    build_syscall_trace_ids += new_trace_syscall_trace_ids
                    build_request_ids += new_request_ids

            else:  # no new_trace_ids_in_prev_iteration
                pass

            if only_query_app_spans:  # no more iterations needed
                break

            # 2. Query by tcp_seq / syscall_trace_id / x_request_id / dns request_id
            new_filters = []
            if TRACING_SRC_TCP_SEQ in config.tracing_source:
                # 2.1. new tcp_seqs
                new_req_tcp_seqs = set()  # set(str(req_tcp_seq))
                new_resp_tcp_seqs = set()  # set(str(resp_tcp_seq))
                for nrts in build_req_tcp_seqs:
                    if nrts and nrts not in req_tcp_seqs:
                        req_tcp_seqs.add(nrts)
                        new_req_tcp_seqs.add(str(nrts))
                for nrts in build_resp_tcp_seqs:
                    if nrts and nrts not in resp_tcp_seqs:
                        resp_tcp_seqs.add(nrts)
                        new_resp_tcp_seqs.add(str(nrts))
                # 2.1. Condition 1: 以 req_tcp_seq & resp_tcp_seq 作为条件查询关联 flow
                # 这里查询 tcp_seq 时仅需一侧相等(req/resp)即可，定义为弱关联关系
                tcp_seq_filters = []
                if new_req_tcp_seqs:
                    tcp_seq_filters.append(
                        f"req_tcp_seq IN ({','.join(new_req_tcp_seqs)})")
                if new_resp_tcp_seqs:
                    tcp_seq_filters.append(
                        f"resp_tcp_seq IN ({','.join(new_resp_tcp_seqs)})")
                if tcp_seq_filters:
                    new_filters.append(f"({' OR '.join(tcp_seq_filters)})")
            if TRACING_SRC_SYSCALL in config.tracing_source:
                # 2.2. new syscall_trace_ids
                new_syscall_trace_ids = set()  # set(str(syscall_trace_id))
                for nsti in build_syscall_trace_ids:
                    if nsti and nsti not in syscall_trace_ids:
                        syscall_trace_ids.add(nsti)
                        new_syscall_trace_ids.add(str(nsti))
                # 2.2. Condition 2: 以 syscall_trace_id_request & syscall_trace_id_response 作为条件查询关联 flow
                syscall_trace_id_filters = []
                if new_syscall_trace_ids:
                    syscall_trace_id_filters.append(
                        f"syscall_trace_id_request IN ({','.join(new_syscall_trace_ids)})"
                    )
                    syscall_trace_id_filters.append(
                        f"syscall_trace_id_response IN ({','.join(new_syscall_trace_ids)})"
                    )
                    new_filters.append(
                        f"({' OR '.join(syscall_trace_id_filters)})")
            if TRACING_SRC_X_REQ_ID in config.tracing_source:
                # 2.3. new x_request_ids
                new_x_request_ids = set()  # set(x_request_id)
                for nxri in build_x_request_ids:
                    if nxri and nxri not in x_request_ids:
                        x_request_ids.add(nxri)
                        new_x_request_ids.add(nxri)
                # 2.3. Condition 3: 以 x_request_id_0 & x_request_id_1 作为条件查询关联 flow
                x_request_id_filters = []
                if new_x_request_ids:
                    new_x_request_ids_str = [
                        f"'{xri}'" for xri in new_x_request_ids
                    ]
                    x_request_id_filters.append(
                        f"x_request_id_0 IN ({','.join(new_x_request_ids_str)})"
                    )
                    x_request_id_filters.append(
                        f"x_request_id_1 IN ({','.join(new_x_request_ids_str)})"
                    )
                    new_filters.append(
                        f"({' OR '.join(x_request_id_filters)})")
            if TRACING_SRC_DNS in config.tracing_source:
                # 2.4. new dns request_ids
                new_dns_request_ids = set()
                for ndri in build_request_ids:
                    if ndri and ndri not in dns_request_ids:
                        dns_request_ids.add(ndri)
                        new_dns_request_ids.add(str(ndri))
                # 2.4. Condition 4: 仅对 DNS 协议，以 request_id 与五元组作为条件查询关联 flow
                dns_request_id_filters = []
                if new_dns_request_ids:
                    # 由于 request_id 在不同协议中处理方式不一样，为免错误关联，这里限制仅 DNS 支持此关联查询场景
                    # XXX: 这里可能会有性能 issue，增加了基于 DNS request_id 的查询后需要查询的数据多了不少
                    dns_request_id_filters.append(
                        f"l7_protocol = {L7_PROTOCOL_DNS}")
                    dns_request_id_filters.append(
                        f"request_id in ({','.join(new_dns_request_ids)})")
                    new_filters.append(
                        f"({' AND '.join(dns_request_id_filters)})")

            if not new_filters and not new_trace_ids_for_next_iteration:  # no more iterations needed
                break
            elif not new_filters:  # only new_trace_ids_for_next_iteration got values
                continue

            # Query3: 查询上述基于 Condition[123] 构建出的条件，即与【第一层迭代】关联的所有 flow，此处构建【第二层迭代】查询
            new_flows = pd.DataFrame()
            new_flows = await self.query_flowmetas(time_filter,
                                                   ' OR '.join(new_filters))
            if type(new_flows
                    ) != DataFrame or new_flows.empty:  # no more new flows
                break

            # remove duplicate or trace_id conflict flows
            new_flow_remove_indices = []
            deleted_trace_ids = set()  # XXX: for debug only
            for index in new_flows.index:
                # delete dup _id
                _id = new_flows.at[index, '_id']
                if _id in l7_flow_ids:
                    new_flow_remove_indices.append(index)
                    continue
                # delete different trace id data
                new_trace_ids = new_flows.at[index, 'trace_id']
                if not new_trace_ids:
                    continue
                # 这里的 trace_ids 是通过 eBPF/Packet 关联查询出来的，而不是通过 trace_id 在迭代过程中查出来的
                # 因此，这里无论是否有多个，都应被 allow_multiple_trace_ids_in_tracing_result 判断是否要保留
                for new_trace_id in new_trace_ids.split(","):
                    new_trace_id = new_trace_id.strip()
                    if new_trace_id and new_trace_id not in allowed_trace_ids:
                        if not allowed_trace_ids or config.allow_multiple_trace_ids_in_tracing_result:
                            allowed_trace_ids.add(new_trace_id)
                            new_trace_ids_for_next_iteration.add(new_trace_id)
                        else:  # remove conflict trace_id data
                            new_flow_remove_indices.append(index)
                            deleted_trace_ids.add(new_trace_id)

            if new_flow_remove_indices:
                new_flows = new_flows.drop(
                    new_flow_remove_indices).reset_index(drop=True)
            if deleted_trace_ids:
                log.debug(f"删除的 trace_id 为：{deleted_trace_ids}")

            # check relationship, and remove unrelated data
            # 先标记可能存在的关联关系，在 related_flow_id_map 中通过多次迭代标记上有关联的 _id
            # 如果一个 _id 没有标记到 related_flow_id_map 中，flow 会被删掉，后续逻辑不再处理
            related_flow_id_map = defaultdict(inner_defaultdict_int)
            trace_infos = TraceInfo.construct_from_dataframe(
                dataframe_flowmetas) + TraceInfo.construct_from_dataframe(
                    new_flows)
            # 这里对 network span 使用强关联关系，保证不要产生误关联
            set_all_relate(trace_infos,
                           related_flow_id_map,
                           network_delay_us,
                           host_clock_offset_us,
                           fast_check=True,
                           skip_first_n_trace_infos=len(dataframe_flowmetas))
            # 注意上面的 new_flow_remove_indices append 了多次，此处可能去掉的数据有:
            # 通过 tcp_seq / syscall_trace_id / x_request_id / span_id / request_id 关联不上任何关系的数据。
            new_flow_remove_indices = []
            for index in range(len(new_flows.index)):
                _id = new_flows.at[index, '_id']
                # Delete unrelated data
                if _id not in related_flow_id_map:
                    new_flow_remove_indices.append(index)
            if new_flow_remove_indices:
                new_flows = new_flows.drop(
                    new_flow_remove_indices).reset_index(drop=True)

            if type(new_flows) == DataFrame and not new_flows.empty:
                # update dataframe_flowmetas and l7_flow_ids
                dataframe_flowmetas = self.concat_l7_flow_log_dataframe(
                    [dataframe_flowmetas, new_flows])
                l7_flow_ids = set(dataframe_flowmetas['_id'])

                # reset new_trace_infos
                build_req_tcp_seqs, build_resp_tcp_seqs, build_x_request_ids, build_syscall_trace_ids, build_request_ids = _build_simple_trace_info_from_dataframe(
                    new_flows)

            elif len(
                    new_trace_ids_for_next_iteration
            ) > 0:  # find multiple trace_ids in current iteration, should query for next iteration
                continue
            else:  # no new_flows, no more iterations needed
                break

            # end of `for i in range(max_iteration)`

        # Call external APM (Pinpoint) API
        if config.call_apm_api_to_supplement_trace and config.apm_api_type_pinpoint:
            for trace_id, span_id in trace_span_ids:
                if not span_id:
                    continue
                if isinstance(
                        span_id,
                        str) and not span_id.strip():  # skip empty span_id
                    continue
                app_spans = await self.query_apm_for_app_span_completion(
                    trace_id, span_id)
                app_spans_from_external.extend(app_spans)

        return l7_flow_ids, app_spans_from_external

    async def trace_l7_flow(
        self,
        time_filter: str,
        base_filter: str,
        max_iteration: int = config.max_iteration,
        network_delay_us: int = config.network_delay_us,
        host_clock_offset_us: int = config.host_clock_offset_us,
        app_spans_from_api: list = [],
        related_map_from_api: defaultdict(inner_defaultdict_int) = None
    ) -> dict:
        """L7 FlowLog 追踪入口

        参数说明：
        time_filter: 查询的时间范围过滤条件，SQL表达式
            当使用四元组进行追踪时，time_filter置为希望搜索的一段时间范围，
            当使用五元组进行追踪时，time_filter置为五元组对应流日志的start_time前后一小段时间，以提升精度
        base_filter: 查询的基础过滤条件，用于限定一个四元组或五元组
        max_iteration: 使用Flowmeta信息搜索的次数，每次搜索可认为大约能够扩充一级调用关系
        network_delay_us: 使用Flowmeta进行流日志匹配的时间偏差容忍度，越大漏报率越低但误报率越高，一般设置为网络时延的最大可能值
        """
        # 多次迭代，查询到所有相关的 l7_flow_log 摘要
        l7_flow_ids, app_spans_from_external = await self.query_and_trace_flowmetas(
            time_filter, base_filter, max_iteration, network_delay_us,
            host_clock_offset_us, app_spans_from_api)

        if len(l7_flow_ids) == 0 and len(app_spans_from_external) == 0:
            return {}

        # 查询会获取这些 _id 对应的完整 l7_flow_log 信息。
        # 通过 RETURN_FIELDS 确定需要返回哪些字段（精简有用的返回信息）
        return_fields = RETURN_FIELDS
        if self.has_attributes:
            return_fields.append("attribute")
        l7_flows = pd.DataFrame()
        if len(l7_flow_ids) > 0:
            l7_flows = await self.query_all_flows(time_filter, l7_flow_ids,
                                                  return_fields)
            if type(l7_flows) != DataFrame or l7_flows.empty:
                # 一般不可能发生没有 l7_flows 但有 app_spans_from_external 的情况
                # 实际上几乎不可能发生没有 l7_flows 的情况，因为至少包含初始 flow
                # 但由于 tracing_completion api 也调用此处追踪逻辑，接口可能传入不存在的 trace_id
                # 所以这里兼容 len(l7_flow_ids)=0 场景，仅对: 当 len(l7_flow_ids)>0 但 `query_all_flows` 为空时返回
                return {}

        # 将外部 APM 查询到的 Span 与数据库中的 Span 结果进行合并
        l7_flows = self.concat_l7_flow_log_dataframe(
            [l7_flows, pd.DataFrame(app_spans_from_external)])

        # 将 null 转化为 None
        l7_flows = l7_flows.where(l7_flows.notnull(), None)

        # 对所有调用日志排序，包含几个动作：排序+合并+分组+设置父子关系
        l7_flows_merged, networks, flow_index_to_id0, related_flow_index_map, host_clock_correction, instance_to_agent = sort_all_flows(
            l7_flows, network_delay_us, host_clock_offset_us, return_fields)
        if related_map_from_api:
            related_flow_index_map.update(related_map_from_api)
        return format_final_result(l7_flows_merged, networks,
                                   self.args.get('_id'), host_clock_offset_us,
                                   flow_index_to_id0, related_flow_index_map,
                                   host_clock_correction, instance_to_agent)

    async def query_ck(self, sql: str):
        querier = Querier(to_dataframe=True,
                          debug=self.args.debug,
                          headers=self.headers)
        response = await querier.exec_all_clusters(DATABASE, sql, self.region)
        '''
        database = 'flow_log'  # database
        host = '10.1.20.22'  # ck ip
        client = Client(
            host=host, port=9000, user='default', password='', database=database,
            send_receive_timeout=5
        )
        #rst = client.execute(SQL)
        rows = client.query_dataframe(sql)
        '''
        for region_name, value in response.get('regions', {}).items():
            if value == -1:
                self.failed_regions.add(region_name)
        return response

    async def query_flowmetas(self, time_filter: str,
                              base_filter: str) -> list:
        """找到base_filter对应的L7 Flowmeta

        网络流量追踪信息：
            type, req_tcp_seq, resp_tcp_seq, start_time_us, end_time_us
            通过tcp_seq及流日志的时间追踪

        系统调用追踪信息：
            vtap_id, syscall_trace_id_request, syscall_trace_id_response
            通过eBPF获取到的coroutine_trace_id追踪

        主动注入的追踪信息：
            trace_id：通过Tracing SDK主动注入的trace_id追踪
            x_request_id_0：通过Nginx/HAProxy/BFE等L7网关注入的requst_id追踪
            x_request_id_1：通过Nginx/HAProxy/BFE等L7网关注入的requst_id追踪
        """
        sql = """SELECT
        type, signal_source, req_tcp_seq, resp_tcp_seq, toUnixTimestamp64Micro(start_time) AS start_time_us,
        toUnixTimestamp64Micro(end_time) AS end_time_us, vtap_id, protocol, syscall_trace_id_request,
        syscall_trace_id_response, span_id, parent_span_id, request_id, l7_protocol, trace_id, x_request_id_0,
        x_request_id_1, _id, tap_side
        FROM `l7_flow_log`
        WHERE (({time_filter}) AND ({base_filter})) limit {l7_tracing_limit}
        """.format(time_filter=time_filter,
                   base_filter=base_filter,
                   l7_tracing_limit=config.l7_tracing_limit)
        response = await self.query_ck(sql)
        # Hit Select Limit
        status_discription = "Query FlowMetas"
        if len(response.get("data", [])) == config.l7_tracing_limit:
            status_discription += " Hit Select Limit"
        self.status.append(status_discription, response)
        return response.get("data", [])

    async def query_apm_for_app_span_completion(self, trace_id: str,
                                                span_id: str) -> list:
        try:
            # if get data error from external apm, ignore it
            # it should not interrupt the main tracing process
            get_third_app_span_url = f"http://{config.querier_server}:{config.querier_port}/api/v1/adapter/tracing?traceid={trace_id}&spanid={span_id}"
            app_spans_res, app_spans_code = await curl_perform(
                'get', get_third_app_span_url)
            if app_spans_code != HTTP_OK:
                log.warning(
                    f"Get app spans failed! url: {get_third_app_span_url}")
            app_spans = app_spans_res.get('data', {}).get('spans', [])
            self.complete_app_span(app_spans)
            return app_spans
        except Exception as e:
            log.error(
                f"get apm app_span failed! trace_id: {trace_id}, error: {e}")
            return []

    async def query_all_flows(self, time_filter: str, l7_flow_ids: list,
                              return_fields: list):
        """根据l7_flow_ids查询所有追踪到的应用流日志
                    if(is_ipv4, IPv4NumToString(ip4_0), IPv6NumToString(ip6_0)) AS ip_0,
                if(is_ipv4, IPv4NumToString(ip4_1), IPv6NumToString(ip6_1)) AS ip_1,
                toUnixTimestamp64Micro(start_time) AS start_time_us,
                toUnixTimestamp64Micro(end_time) AS end_time_us,
                dictGet(deepflow.l3_epc_map, ('name'), (toUInt64(l3_epc_id_0))) AS epc_name_0,
                dictGet(deepflow.l3_epc_map, ('name'), (toUInt64(l3_epc_id_1))) AS epc_name_1,
                dictGet(deepflow.device_map, ('name'), (toUInt64(l3_device_type_0),toUInt64(l3_device_id_0))) AS l3_device_name_0,
                dictGet(deepflow.device_map, ('name'), (toUInt64(l3_device_type_1),toUInt64(l3_device_id_1))) AS l3_device_name_1,
                dictGet(deepflow.pod_map, ('name'), (toUInt64(pod_id_0))) AS pod_name_0,
                dictGet(deepflow.pod_map, ('name'), (toUInt64(pod_id_1))) AS pod_name_1,
                dictGet(deepflow.pod_node_map, ('name'), (toUInt64(pod_node_id_0))) AS pod_node_name_0,
                dictGet(deepflow.pod_node_map, ('name'), (toUInt64(pod_node_id_1))) AS pod_node_name_1
        """
        ids = []
        # build _id IN (xxx) conditions
        # fix start_time from min to max extract from _id
        min_start_time = _get_epochsecond(
            list(l7_flow_ids)[0]) if len(l7_flow_ids) > 0 else 0
        max_end_time = 0
        for flow_id in l7_flow_ids:
            second = _get_epochsecond(flow_id)
            if second > max_end_time:
                max_end_time = second
            if second < min_start_time:
                min_start_time = second
            ids.append(str(flow_id))
        if min_start_time > 0:
            time_filter = f"time>={min_start_time} AND time<={max_end_time}"
        fields = []
        for field in return_fields:
            if field in FIELDS_MAP:
                fields.append(FIELDS_MAP[field])
            else:
                fields.append(field)
        sql = """
        SELECT {fields} FROM `l7_flow_log` WHERE (({time_filter}) AND ({l7_flow_ids})) ORDER BY start_time_us asc
        """.format(
            time_filter=time_filter,
            l7_flow_ids=f'_id IN ({", ".join(ids)})',
            #    l7_flow_ids=' OR '.join(ids),
            fields=",".join(fields))
        response = await self.query_ck(sql)
        self.status.append("Query All Flows", response)
        return response["data"]


def set_all_relate(trace_infos: list,
                   related_map: defaultdict(inner_defaultdict_int),
                   network_delay_us: int,
                   host_clock_offset_us: int,
                   fast_check: bool = False,
                   skip_first_n_trace_infos: int = 0,
                   network_allow_weak_related: bool = False):
    """
    用于 span 追溯关联
    先构建 tcp_seq/syscall_trace_id/x_request_id 对 _id 的反向索引，再对每一种类型的关联通过各自的 `set_relate` 判断是否有关联
    fast_check = True: 为每个 trace_infos 中的 trace_info 找到一个关联即可，用于初期剪枝
    skip_first_n_trace_infos > 0：跳过上一轮迭代及之前搜索到的 trace_infos，因为他们肯定不会在新一轮被剪枝
    """
    # tcp_seq => set(TraceInfo)
    tcp_seq_to_trace_infos = defaultdict(set)
    # span_id_id => set(TraceInfo)
    span_id_to_trace_infos = defaultdict(set)
    # x_request_id => set(TraceInfo)
    x_request_id_to_trace_infos = defaultdict(set)
    # syscall_trace_id => set(TraceInfo)
    syscall_trace_id_to_trace_infos = defaultdict(set)
    # dns request_id => Set(Traceinfo)
    dns_request_id_to_trace_infos = defaultdict(set)

    for ti in trace_infos:
        # tcp_seq
        # 由于这里 tcp_seq 在某一侧为 0 但 type=session 时也需要进行比较，这里强制 protocol 必须是 tcp，避免 udp 比较错误
        if ti.signal_source != L7_FLOW_SIGNAL_SOURCE_OTEL and ti.protocol == L4_PROTOCOL_TCP:
            if ti.type != L7_FLOW_TYPE_RESPONSE:  # has req_tcp_seq
                tcp_seq_to_trace_infos[ti.req_tcp_seq].add(ti)
            if ti.type != L7_FLOW_TYPE_REQUEST:  # has resp_tcp_seq
                tcp_seq_to_trace_infos[ti.resp_tcp_seq].add(ti)
        # span_id
        if ti.span_id:
            span_id_to_trace_infos[ti.span_id].add(ti)
        if ti.parent_span_id:
            span_id_to_trace_infos[ti.parent_span_id].add(ti)
        # x_request_id
        if ti.x_request_id_0:
            x_request_id_to_trace_infos[ti.x_request_id_0].add(ti)
        if ti.x_request_id_1:
            x_request_id_to_trace_infos[ti.x_request_id_1].add(ti)
        # syscall_trace_id
        if ti.syscall_trace_id_request:
            syscall_trace_id_to_trace_infos[ti.syscall_trace_id_request].add(
                ti)
        if ti.syscall_trace_id_response:
            syscall_trace_id_to_trace_infos[ti.syscall_trace_id_response].add(
                ti)
        if TRACING_SRC_DNS in config.tracing_source and ti.l7_protocol == L7_PROTOCOL_DNS and ti.request_id:
            dns_request_id_to_trace_infos[ti.request_id].add(ti)

    for ti in trace_infos[skip_first_n_trace_infos:]:
        # tcp_seq
        if ti.signal_source != L7_FLOW_SIGNAL_SOURCE_OTEL:
            # tcp_seq 是否有效（是否需要参与比较）取决于 flow.type，例如：
            # 当 type = SESSION 时即使某一侧 tcp_seq 为 0 也需要比较。
            # 因此当 type 决定了某一侧没有内容时，将 tcp_seq 赋值为 None，
            # 使得在 tcp_seq_to_trace_infos 中无法查询到结果。
            req_tcp_seq = ti.req_tcp_seq if ti.type != L7_FLOW_TYPE_RESPONSE else None
            resp_tcp_seq = ti.resp_tcp_seq if ti.type != L7_FLOW_TYPE_REQUEST else None
            related_trace_infos = tcp_seq_to_trace_infos.get(
                req_tcp_seq, set()) | tcp_seq_to_trace_infos.get(
                    resp_tcp_seq, set())
            if not network_allow_weak_related:
                find_related = L7NetworkMeta.set_relate(
                    ti, related_trace_infos, related_map, network_delay_us,
                    host_clock_offset_us, fast_check)
            else:
                find_related = L7NetworkMeta.set_weak_relate(
                    ti, related_trace_infos, related_map, network_delay_us,
                    host_clock_offset_us, fast_check)
            if fast_check and find_related: continue
        # span_id
        related_trace_infos = span_id_to_trace_infos.get(
            ti.span_id, set()) | span_id_to_trace_infos.get(
                ti.parent_span_id, set())
        find_related = L7AppMeta.set_relate(ti, related_trace_infos,
                                            related_map, fast_check)
        if fast_check and find_related: continue
        # x_request_id
        related_trace_infos = x_request_id_to_trace_infos.get(
            ti.x_request_id_0, set()) | x_request_id_to_trace_infos.get(
                ti.x_request_id_1, set())
        find_related = L7XrequestMeta.set_relate(ti, related_trace_infos,
                                                 related_map, fast_check)
        if fast_check and find_related: continue
        # syscall_trace_id
        related_trace_infos = syscall_trace_id_to_trace_infos.get(
            ti.syscall_trace_id_request,
            set()) | syscall_trace_id_to_trace_infos.get(
                ti.syscall_trace_id_response, set())
        find_related = L7SyscallMeta.set_relate(ti, related_trace_infos,
                                                related_map, fast_check)
        if fast_check and find_related: continue
        # dns request_id
        if TRACING_SRC_DNS not in config.tracing_source: continue
        related_trace_infos = dns_request_id_to_trace_infos.get(
            ti.request_id, set())
        find_related = L7DnsMeta.set_relate(ti, related_trace_infos,
                                            related_map, network_delay_us,
                                            host_clock_offset_us, fast_check)
        if fast_check and find_related: continue


def _build_simple_trace_info_from_dataframe(df: pd.DataFrame):
    req_tcp_seqs = df['req_tcp_seq'].tolist()
    resp_tcp_seqs = df['resp_tcp_seq'].tolist()
    x_request_ids = df['x_request_id_0'].tolist()
    x_request_ids += df['x_request_id_1'].tolist()
    syscall_trace_ids = df['syscall_trace_id_request'].tolist()
    syscall_trace_ids += df['syscall_trace_id_response'].tolist()
    request_ids = df.loc[df['l7_protocol'] == L7_PROTOCOL_DNS,
                         'request_id'].tolist()
    return req_tcp_seqs, resp_tcp_seqs, x_request_ids, syscall_trace_ids, request_ids


class TraceInfo:

    def __init__(self, _id, signal_source, vtap_id, _type, protocol,
                 l7_protocol, start_time_us, end_time_us, req_tcp_seq,
                 resp_tcp_seq, trace_id, span_id, parent_span_id,
                 x_request_id_0, x_request_id_1, syscall_trace_id_request,
                 syscall_trace_id_response, request_id, origin_flow_list,
                 index_in_origin_flow_list):
        self._id = _id
        self.signal_source = signal_source
        self.vtap_id = vtap_id
        self.type = _type
        self.protocol = protocol
        self.l7_protocol = l7_protocol
        # time
        self.start_time_us = start_time_us
        self.end_time_us = end_time_us
        # tcp_seq
        self.req_tcp_seq = req_tcp_seq
        self.resp_tcp_seq = resp_tcp_seq
        # span_id
        self.trace_id = trace_id
        self.span_id = span_id
        self.parent_span_id = parent_span_id
        # x_request_id
        self.x_request_id_0 = x_request_id_0
        self.x_request_id_1 = x_request_id_1
        # syscall_trace_id
        self.syscall_trace_id_request = syscall_trace_id_request
        self.syscall_trace_id_response = syscall_trace_id_response
        # request_id
        self.request_id = request_id
        # origin_flow_list: data records from database
        self.origin_flow_list = origin_flow_list
        # index of origin flow list
        self.index_in_origin_flow_list = index_in_origin_flow_list

    def __eq__(self, rhs):
        return self._id == rhs._id

    def __hash__(self):
        return hash(self._id)

    def get_extra_field(self, key):
        if isinstance(self.origin_flow_list, DataFrame):
            if key in self.origin_flow_list.columns:
                return self.origin_flow_list.at[self.index_in_origin_flow_list,
                                                key]
        elif isinstance(self.origin_flow_list, list):
            return self.origin_flow_list[self.index_in_origin_flow_list].get(
                key)
        return None

    @classmethod
    def construct_from_dataframe(cls, dataframe_flowmetas: DataFrame):
        """
        constructor of traceinfo from database records to build tracing keys
        """
        trace_infos = []  # [TraceInfo]
        for row in dataframe_flowmetas.itertuples():
            trace_infos.append(
                TraceInfo(
                    # key start with '_' can not access through attr
                    dataframe_flowmetas.at[row.Index, '_id'],
                    getattr(row, 'signal_source'),
                    getattr(row, 'vtap_id'),
                    getattr(row, 'type'),
                    getattr(row, 'protocol'),
                    getattr(row, 'l7_protocol'),
                    # time
                    getattr(row, 'start_time_us'),
                    getattr(row, 'end_time_us'),
                    # tcp_seq
                    getattr(row, 'req_tcp_seq'),
                    getattr(row, 'resp_tcp_seq'),
                    # span_id
                    getattr(row, 'trace_id'),
                    getattr(row, 'span_id'),
                    getattr(row, 'parent_span_id'),
                    # x_request_id
                    getattr(row, 'x_request_id_0'),
                    getattr(row, 'x_request_id_1'),
                    # syscall_trace_id
                    getattr(row, 'syscall_trace_id_request'),
                    getattr(row, 'syscall_trace_id_response'),
                    # request_id
                    getattr(row, 'request_id'),
                    # origin_flow_list
                    dataframe_flowmetas,
                    row.Index))
        return trace_infos

    @classmethod
    def construct_from_dict_list(cls, flow_dicts: dict):
        trace_infos = []  # [TraceInfo]
        for index in range(len(flow_dicts)):
            flow = flow_dicts[index]
            trace_infos.append(
                TraceInfo(
                    # flow maybe merged from multiple l7_flow_logs, use _index instead of _id
                    flow['_index'],
                    flow['signal_source'],
                    flow['vtap_id'],
                    flow['type'],
                    flow['protocol'],
                    flow['l7_protocol'],
                    # time
                    flow['start_time_us'],
                    flow['end_time_us'],
                    # tcp_seq
                    flow['req_tcp_seq'],
                    flow['resp_tcp_seq'],
                    # span_id
                    flow['trace_id'],
                    flow['span_id'],
                    flow['parent_span_id'],
                    # x_request_id
                    flow['x_request_id_0'],
                    flow['x_request_id_1'],
                    # syscall_trace_id
                    flow['syscall_trace_id_request'],
                    flow['syscall_trace_id_response'],
                    # request_id
                    flow['request_id'],
                    # origin_flow_list
                    flow_dicts,
                    index))
        return trace_infos


class L7DnsMeta:

    @classmethod
    def flow_field_conflict(cls, lhs: TraceInfo, rhs: TraceInfo) -> bool:
        for key in [
                'protocol',
                'endpoint',
                'request_resource',
                'request_type',
                'request_id',
                'response_code',
                'response_exception',
                'response_result',
                'l7_protocol',
        ]:
            lhs_value = lhs.get_extra_field(key)
            rhs_value = rhs.get_extra_field(key)
            if not lhs_value or not rhs_value:
                continue

            # FIXME: 统一在源头处理这个问题
            # ClickHouse 中的 Nullable(int) 字段在无值时会返回为 dataframe 中的 float(nan)
            # 在 Python 中 float(nan) != float(nan)，因此将其转为 None 方便比较
            # request_id 就是一个 Nullable(uint64) 字段
            if isinstance(lhs_value, float) and math.isnan(lhs_value):
                lhs_value = None
            if isinstance(rhs_value, float) and math.isnan(rhs_value):
                rhs_value = None
            if lhs_value != rhs_value:
                return True
        return False

    @classmethod
    def set_relate(cls,
                   trace_info: TraceInfo,
                   related_trace_infos: set,
                   related_map: defaultdict(inner_defaultdict_int),
                   network_delay_us: int,
                   host_clock_offset_us: int,
                   fast_check: bool = False) -> bool:
        """
        使用 request_id 标记穿越不同观测点的关联关系
             request_id_1 ┌──────┐ request_id_1 ┌─────┐
        user ────────────>│ Node │─────────────>│ Pod │
                          └──────┘              └─────┘

        注意：DNS 协议的 Request_Id 目前取值为 Transaction_Id，在 RFC 规范中定义为随机生成，用于 dns 请求与 dns 响应之间的匹配
        """
        find_related = False
        for rti in related_trace_infos:
            if trace_info._id == rti._id:
                continue
            # network_delay_us 用于判断同一主机两两网络流之间的时间差不应大于【一定值】
            # host_clock_offset_us 用于判断不同主机之间 ntp 同步的时间不应大于【一定值】。
            # 对于不同主机之间的网络流，network_delay_us 和 host_clock_offset_us 时间差同时存在
            # 否则认为超出追踪范围，在后续逻辑中会无法加入 related_map 而被丢弃。
            span_time_deviation = network_delay_us if trace_info.vtap_id == rti.vtap_id else network_delay_us + host_clock_offset_us
            if trace_info.request_id and trace_info.request_id == rti.request_id and abs(
                    trace_info.start_time_us -
                    rti.start_time_us) <= span_time_deviation:
                if not cls.flow_field_conflict(trace_info, rti):
                    related_map[trace_info._id][
                        rti._id] |= L7_FLOW_RELATIONSHIP_DNS_REQUEST_ID
                    find_related = True
                if fast_check and find_related: return find_related

        return find_related


class L7XrequestMeta:

    @classmethod
    def set_relate(cls,
                   trace_info: TraceInfo,
                   related_trace_infos: set,
                   related_map: defaultdict(inner_defaultdict_int),
                   fast_check: bool = False) -> bool:
        """
        当请求穿越网关(可能是 ingress 或云托管 LB)，网关内部生成 x_request_id 标记同一个请求
        因为 nginx 类网关是通过多 worker 进程实现的，所以需要依赖于 x_request_id 来关联
        ┌───────┐                    ┌─────────┐ x_request_id_0_100 ┌──────┐ x_request_id_0_200
        │       │ ───────────────────│─>100    │───────────────────>│->200 │ ──────────────────>
        │ Front │                    │ Ingress |                    │  LB  │
        │       │ <──────────────────│<─100    │<───────────────────│<─200 │ <---
        └───────┘ x_request_id_1_100 └─────────┘ x_request_id_1_200 └──────┘
        当网关内部或有多 worker 工作线程场景: eBPF 无法关联出入请求与出请求
        当网关使用云 LB 时无法部署 agent: 无法获取到任何网关内信息
        """
        find_related = False
        for rti in related_trace_infos:
            if trace_info._id == rti._id:
                continue
            # x_request_id_0 语义是 x_request_id_req，x_request_id_1 语义是 x_request_id_resp
            # x_request_id_0 == x_request_id_1 实际上是标注网关内部的关联关系，把跨进程/线程的请求/响应关联
            # 由于先发生【被请求】，再发生【转发】，所以 x_request_id_1 一定在 x_request_id_0 之上
            # x_request_id_0
            if trace_info.x_request_id_0 and trace_info.x_request_id_0 == rti.x_request_id_1:
                related_map[trace_info._id][
                    rti._id] |= L7_FLOW_RELATIONSHIP_X_REQUEST_ID
                find_related = True
                if fast_check: return True
                continue
            # x_request_id_1
            if trace_info.x_request_id_1 and trace_info.x_request_id_1 == rti.x_request_id_0:
                related_map[trace_info._id][
                    rti._id] |= L7_FLOW_RELATIONSHIP_X_REQUEST_ID
                find_related = True
                if fast_check: return True
                continue

        return find_related


class L7NetworkMeta:

    @classmethod
    def flow_field_conflict(cls, lhs: TraceInfo, rhs: TraceInfo) -> bool:
        # span_id
        if lhs.trace_id and lhs.span_id and rhs.trace_id and rhs.span_id and (
                not set(lhs.trace_id) & set(rhs.trace_id)
                or lhs.span_id != rhs.span_id):
            return True

        is_http2_grpc_and_differ = False

        # other fields
        for key in [
                'l7_protocol',  # 固定此列第一个检查，HTTP2/gRPC 的后续字段检查要用到
                'x_request_id_0',
                'x_request_id_1',
                'http_proxy_client',
                'protocol',
                'l7_protocol_str',
                'version',
                'request_id',
                'endpoint',
                'http_proxy_client',
                'request_type',
                'request_domain',
                # 如果协议是 MySQL，这里 req_resource=SQL语句
                # 当语句超大时，在 eBPF 和 Packet 中收到的包大小可能不一样，导致这里判断不准确
                # 于是，对这个字段只需要判断前 1024 字节即可(Packet 的默认截断大小是 1024)
                # 对别的协议（如 HTTP/gRPC/Redis），req_resource 一般是 URL/Redis 命令，1024 字节也足够比较
                'request_resource',
                'response_code',
                'response_exception',
                'response_result',
        ]:
            if is_http2_grpc_and_differ and key == 'l7_protocol_str':
                # 当已经确认 l7_protocol 忽略差异时，不用比较 l7_protocol_str
                continue

            if is_http2_grpc_and_differ and key == 'request_resource':
                # 某些情况下同一股流量在不同位置可能会被 Agent 分别解析为 HTTP2 和 gRPC
                # 目前这两种协议的 request_resource 取自不同的协议字段，详见下面的文档：
                # https://deepflow.io/docs/zh/features/universal-map/l7-protocols/#http2
                # 于是，当一个协议是 HTTP2、另一个是 gRPC 时，不用比较这些差异字段
                continue

            if is_http2_grpc_and_differ and key == 'endpoint':
                # eBPF 接收协议数据存在乱序现象，此时当协议为 gRPC 时 endpoint 的解析可能会出错
                # 当确定协议是 gRPC 时，忽略此差异
                continue

            lhs_value = lhs.get_extra_field(key)
            rhs_value = rhs.get_extra_field(key)
            if not lhs_value or not rhs_value:
                continue

            # FIXME: 统一在源头处理这个问题
            # ClickHouse 中的 Nullable(int) 字段在无值时会返回为 dataframe 中的 float(nan)
            # 在 Python 中 float(nan) != float(nan)，因此将其转为 None 方便比较
            # request_id 就是一个 Nullable(uint64) 字段
            if isinstance(lhs_value, float) and math.isnan(lhs_value):
                lhs_value = None
            if isinstance(rhs_value, float) and math.isnan(rhs_value):
                rhs_value = None

            # Agent 有可能协议识别有误差，没将 HTTP2 识别为 gRPC。
            # 此处忽略这个差异，虽然 HTTP2 不一定都是 gRPC。
            if key == 'l7_protocol' and lhs_value in [
                    L7_PROTOCOL_HTTP2, L7_PROTOCOL_GRPC
            ] and rhs_value in [L7_PROTOCOL_HTTP2, L7_PROTOCOL_GRPC]:
                if lhs_value != rhs_value:
                    is_http2_grpc_and_differ = True
                continue

            if key == 'request_resource' and len(lhs_value) > 1024 and len(
                    rhs_value) > 1024:
                lhs_value = lhs_value[:1024]
                rhs_value = rhs_value[:1024]

            if lhs_value != rhs_value:
                return True
        return False

    @classmethod
    def set_weak_relate(
        cls,
        trace_info: TraceInfo,
        related_trace_infos: set,
        related_map: defaultdict(inner_defaultdict_int),
        network_delay_us: int,
        host_clock_offset_us: int,
        fast_check: bool = False,
    ) -> bool:
        find_related = False
        for rti in related_trace_infos:
            if trace_info._id == rti._id:
                continue
            # network_delay_us 用于判断同一主机两两网络流之间的时间差不应大于【一定值】
            # host_clock_offset_us 用于判断不同主机之间 ntp 同步的时间不应大于【一定值】。
            # 对于不同主机之间的网络流，network_delay_us 和 host_clock_offset_us 时间差同时存在
            # 否则认为超出追踪范围，在后续逻辑中会无法加入 related_map 而被丢弃。

            # 注意：两个 Span 都是会话时，要求两侧 TCP Seq 必须都相等，即使有一侧 TCP Seq 为 0，
            #       例如 MySQL Close、RabbitMQ Connection.Blocked 等单向 SESSION 的场景。
            #       否则，只需要一侧 TCP Seq 相等即可。

            # 注意：这里用弱关系判断，仅用于 sort_all_flows 中构建溯源关系，保证溯源关系能关联上
            # 在后续构建关联关系时，使用上述强判断（即下方 is_relate 的逻辑）做强校验
            span_time_deviation = network_delay_us if trace_info.vtap_id == rti.vtap_id else network_delay_us + host_clock_offset_us
            if trace_info.req_tcp_seq and trace_info.req_tcp_seq == rti.req_tcp_seq and abs(
                    trace_info.start_time_us -
                    rti.start_time_us) <= span_time_deviation:
                related_map[trace_info._id][
                    rti._id] |= L7_FLOW_RELATIONSHIP_TCP_SEQ
                find_related = True
            if trace_info.resp_tcp_seq and trace_info.resp_tcp_seq == rti.resp_tcp_seq and abs(
                    trace_info.end_time_us -
                    rti.end_time_us) <= span_time_deviation:
                related_map[trace_info._id][
                    rti._id] |= L7_FLOW_RELATIONSHIP_TCP_SEQ
                find_related = True
            if fast_check and find_related: return
        return find_related

    @classmethod
    def set_relate(cls,
                   trace_info: TraceInfo,
                   related_trace_infos: set,
                   related_map: defaultdict(inner_defaultdict_int),
                   network_delay_us: int,
                   host_clock_offset_us: int,
                   fast_check: bool = False) -> bool:
        """
        使用 tcp_seq 标记穿越不同网元的关联关系
             req_tcp_seq_1 ┌──────┐req_tcp_seq_1 ┌─────┐
             ─────────────>│      │─────────────>│     │
        user               │ Node │              │ Pod │
             <─────────────│      │<─────────────│     │
            resp_tcp_seq_2 └──────┘resp_tcp_seq_2└─────┘

        注意：DNS 协议可能是 UDP，双向 tcp_seq 都为 0
        """
        find_related = False
        for rti in related_trace_infos:
            if trace_info._id == rti._id:
                continue
            # network_delay_us 用于判断同一主机两两网络流之间的时间差不应大于【一定值】
            # host_clock_offset_us 用于判断不同主机之间 ntp 同步的时间不应大于【一定值】。
            # 对于不同主机之间的网络流，network_delay_us 和 host_clock_offset_us 时间差同时存在
            # 否则认为超出追踪范围，在后续逻辑中会无法加入 related_map 而被丢弃。

            # 注意：两个 Span 都是会话时，要求两侧 TCP Seq 必须都相等，即使有一侧 TCP Seq 为 0，
            #       例如 MySQL Close、RabbitMQ Connection.Blocked 等单向 SESSION 的场景。
            #       否则，只需要一侧 TCP Seq 相等即可。

            # 注意：这里是完整的强关系判断，用于 query_flowmetas 中避免误关联匹配
            if cls.is_relate(trace_info, rti, network_delay_us,
                             host_clock_offset_us):
                related_map[trace_info._id][
                    rti._id] |= L7_FLOW_RELATIONSHIP_TCP_SEQ
                find_related = True
            if fast_check and find_related: return
            # XXX: vtap_id 相同时应该能有更好的判断，例如 duration 大的 Span 时间范围必须覆盖 duration 小的 Span

        return find_related

    @classmethod
    def is_relate(cls, lhs_ti: TraceInfo, rhs_ti: TraceInfo,
                  network_delay_us: int, host_clock_offset_us: int) -> bool:
        """
        校验一组 TcpSeq 相等的 Network Span 是否能被追踪或放入一组关联关系中
        """
        span_time_deviation = network_delay_us if lhs_ti.vtap_id == rhs_ti.vtap_id else network_delay_us + host_clock_offset_us
        if lhs_ti.type == rhs_ti.type == L7_FLOW_TYPE_SESSION:  # req & resp
            if abs(lhs_ti.start_time_us -
                   rhs_ti.start_time_us) <= span_time_deviation and abs(
                       lhs_ti.end_time_us -
                       rhs_ti.end_time_us) <= span_time_deviation:
                if lhs_ti.req_tcp_seq == rhs_ti.req_tcp_seq and lhs_ti.resp_tcp_seq == rhs_ti.resp_tcp_seq:
                    if not cls.flow_field_conflict(lhs_ti, rhs_ti):
                        return True
        elif lhs_ti.type != L7_FLOW_TYPE_RESPONSE and rhs_ti.type != L7_FLOW_TYPE_RESPONSE:  # req
            if abs(lhs_ti.start_time_us -
                   rhs_ti.start_time_us) <= span_time_deviation:
                if lhs_ti.req_tcp_seq == rhs_ti.req_tcp_seq:
                    if not cls.flow_field_conflict(lhs_ti, rhs_ti):
                        return True
        elif lhs_ti.type != L7_FLOW_TYPE_REQUEST and rhs_ti.type != L7_FLOW_TYPE_REQUEST:  # resp
            if abs(lhs_ti.end_time_us -
                   rhs_ti.end_time_us) <= span_time_deviation:
                if lhs_ti.resp_tcp_seq == rhs_ti.resp_tcp_seq:
                    if not cls.flow_field_conflict(lhs_ti, rhs_ti):
                        return True
        return False


class L7SyscallMeta:

    @classmethod
    def set_relate(cls,
                   trace_info: TraceInfo,
                   related_trace_infos: set,
                   related_map: defaultdict(inner_defaultdict_int),
                   fast_check: bool = False) -> bool:
        """
        syscall_trace_id_x 关联关系连接同一个线程内出入请求
        ┌───────┐ syscall_trace_id_request  ┌─────────┐ syscall_trace_id_request  ┌────────┐
        │       │ ──────────────────────────│─>1   2─>│───────────────────────────│->3     │
        │ Proc1 │                           │  Proc2  |                           │  Proc3 │
        │       │ <─────────────────────────│<─6   5<─│───────────────────────────│<─4     │
        └───────┘ syscall_trace_id_response └─────────┘ syscall_trace_id_response └────────┘

        对于 syscall_trace_id：
        在 Proc2 的关联：
        - syscall_trace_id_request_1 = syscall_trace_id_request_2
        - syscall_trace_id_response_5 = syscall_trace_id_response_6
        在 Proc3 的关联：
        - syscall_trace_id_request_3 = syscall_trace_id_response_4
        """
        if trace_info.syscall_trace_id_request == trace_info.syscall_trace_id_response:
            # this is either an initial or terminal request
            return

        find_related = False
        for rti in related_trace_infos:
            if trace_info._id == rti._id:
                continue
            if trace_info.vtap_id != rti.vtap_id:
                continue
            if rti.syscall_trace_id_request == rti.syscall_trace_id_response:
                # this is either an initial or terminal request
                continue
            # s-p & s-p based on syscall_trace_id should not related each other
            # they should connected based on front-end client syscall
            if rti.get_extra_field("tap_side") == trace_info.get_extra_field(
                    "tap_side") == TAP_SIDE_SERVER_PROCESS:
                continue
            # syscall_trace_id_request
            if trace_info.syscall_trace_id_request:
                if trace_info.syscall_trace_id_request in [
                        rti.syscall_trace_id_request,
                        rti.syscall_trace_id_response
                ]:
                    related_map[trace_info._id][
                        rti._id] |= L7_FLOW_RELATIONSHIP_SYSCALL_TRACE_ID
                    find_related = True
                    if fast_check: return True
                    continue
            # syscall_trace_id_response
            if trace_info.syscall_trace_id_response:
                if trace_info.syscall_trace_id_response in [
                        rti.syscall_trace_id_request,
                        rti.syscall_trace_id_response
                ]:
                    related_map[trace_info._id][
                        rti._id] |= L7_FLOW_RELATIONSHIP_SYSCALL_TRACE_ID
                    find_related = True
                    if fast_check: return True
                    continue

        return find_related


class L7AppMeta:

    @classmethod
    def set_relate(cls,
                   trace_info: TraceInfo,
                   related_trace_infos: set,
                   related_map: defaultdict(inner_defaultdict_int),
                   fast_check: bool = False) -> bool:
        """
        app-span 通过 trace_id/span_id 关联 span，其中，上游的 span_id 到达下游服务后会成为下游服务发起请求的 parent_span_id
                  ┌─────┐ span_id => parent_span_id ┌────────┐ span_id => parent_span_id ┌────────┐
                  │     │ ─────────────────────────>│        │ ─────────────────────────>│        │
        trace_id ─|─Req─| ──────────────────────────│─-Pod1-─| ──────────────────────────│─-Pod2-─│──────> trace_id
                  │     │                           │        │                           │        │
                  └─────┘                           └────────┘                           └────────┘
        """
        if not trace_info.trace_id or not trace_info.span_id:
            return

        find_related = False
        for rti in related_trace_infos:
            if trace_info._id == rti._id:
                continue
            if trace_info.trace_id != rti.trace_id:
                # The span_id of different traces is likely to be the same.
                continue
            # span_id
            if trace_info.span_id in [rti.span_id, rti.parent_span_id]:
                related_map[trace_info._id][
                    rti._id] |= L7_FLOW_RELATIONSHIP_SPAN_ID
                find_related = True
                if fast_check: return True
                continue
            # parent_span_id
            if trace_info.parent_span_id:
                if trace_info.parent_span_id == rti.span_id:
                    related_map[trace_info._id][
                        rti._id] |= L7_FLOW_RELATIONSHIP_SPAN_ID
                    find_related = True
                    if fast_check: return True
                    continue

        return find_related


class NetworkSpanSet:
    """
    一个 NetworkSpanSet 由如下 Span 组成：
    - 零个或一个 c-p
    - 零个或多个网络类型的 observation_point（即 tap_side）
    - 零个或一个 s-p
    """

    def __init__(self):
        # 标识 span_id 方便匹配 app-span
        self.span_id = None
        # 分组聚合所有 tcp_seq 相同的 flow
        self.spans: List[SpanNode] = []
        self.auto_service_0 = None
        self.auto_service_1 = None
        self.auto_service_id_0 = None
        self.auto_service_id_1 = None
        self.auto_service_type_0 = None
        self.auto_service_type_1 = None
        self.auto_instance_type_0 = None
        self.auto_instance_type_1 = None
        self.id = uuid.uuid1().hex

    def __eq__(self, other: 'NetworkSpanSet') -> bool:
        return self.id == other.id

    def __hash__(self) -> int:
        return hash(self.id)

    def _set_auto_service(self, span: 'SpanNode'):
        """
        此方法统一 net_span 的统计字段并为 flow 生成一个无方向的 key
        这里和 ProcessSpanSet._set_auto_service 有如下区别：
        1. ProcessSpanSet 的 _set_auto_service 是为了在剪枝(pruning_trace) 后做服务聚合和时延统计
        2. 这里的 _set_auto_service 只是为了赋值 span.auto_service，方便在「仅有 net span」的场景里，界面可以生成拓扑图
        3. 对 ProcessSpanSet 而言，所有 span 一定都是同一个服务，但是 Network 的 span 可能是不同的服务（取决于观测点）
        4. 所以这里要根据实际观测点来对 span.auto_service_x 赋值，不要统一处理
        """
        direction = "1" if span.tap_side.startswith("s") else "0"
        for key in [
                'auto_service_id',
                'auto_service',
                'auto_service_type',
                'auto_instance_type',
        ]:
            direction_key = f'{key}_{direction}'
            if not span.flow[direction_key]:
                direction_key = f'{key}_0'

            if getattr(self, direction_key):
                if (self.auto_service_type_1 in [
                        const.AUTO_SERVICE_IP,
                        const.AUTO_SERVICE_INTERNET_IP,
                ] or self.auto_service_type_0 in [
                        const.AUTO_SERVICE_IP,
                        const.AUTO_SERVICE_INTERNET_IP,
                ]) or (self.auto_instance_type_0 in [
                        const.AUTO_INSTANCE_IP, const.AUTO_INSTANCE_INTERNET_IP
                ] or self.auto_instance_type_1 in [
                        const.AUTO_INSTANCE_IP, const.AUTO_INSTANCE_INTERNET_IP
                ]):
                    setattr(self, direction_key, span.flow[direction_key])
                span.flow[key] = getattr(self, direction_key)
            else:
                setattr(self, direction_key, span.flow[direction_key])
                span.flow[key] = span.flow[direction_key]

    def append_span_node(self, span: 'SpanNode'):
        """
        将 net-span 与 sys-span 按 tcp_seq 分组
        构造 tcp_seq 分组时已通过 `flow_field_conflict` 函数确保同一组内必是同一个 span_id
        """
        if not self.span_id and span.get_span_id():
            self.span_id = span.get_span_id()
        # 标记 span 是否属于同一组 network_span_set，避免在 _connect_process_and_networks 首尾关联产生环路
        span.network_span_set = self
        # 这里有可能写进来的是 SysSpan，需要避免重复设置，避免服务划分错误
        # 由于在 sort_all_flows 里，是先执行 ProcessSpanSet 初始化，再执行 NetworkSpanSet 初始化
        # 所以可以认为在这个步骤里，所有 SysSpan 已经带上了 auto_service，直接绕开即可
        # 也即：NetworkSpanSet 的 auto_service 不要覆盖掉 SysSpan 已有的 auto_service
        if span.signal_source == L7_FLOW_SIGNAL_SOURCE_PACKET:
            self._set_auto_service(span)
        self.spans.append(span)

    def set_parent_relation(
            self, host_clock_offset_us: int, network_delay_us: int,
            host_clock_correct_callback: Callable[['SpanNode', 'SpanNode'],
                                                  None]):
        """
        对组内 span 设置父子关系
        """
        self._sort_network_spans()
        for i in range(1, len(self.spans), 1):
            child = self.spans[i]
            parent = self.spans[i - 1]
            if child.agent_id != parent.agent_id:
                if not _range_overlap(child.flow['start_time_us'],
                                      child.flow['end_time_us'],
                                      parent.flow['start_time_us'],
                                      parent.flow['end_time_us'],
                                      host_clock_offset_us + network_delay_us):
                    # 当 child/parent 来自不同的主机，但时差超出 host_clock_offset_us + network_delay_us，应认为二者无关
                    continue
            if self.spans[i].signal_source == self.spans[
                    i - 1].signal_source == L7_FLOW_SIGNAL_SOURCE_EBPF:
                if self.spans[
                        i].tap_side == TAP_SIDE_SERVER_PROCESS and self.spans[
                            i - 1].tap_side == TAP_SIDE_CLIENT_PROCESS:
                    # 当顺序为 [c-p, s-p] 说明中间没有 net-span，构成父子关系
                    self.spans[i].set_parent(self.spans[i - 1],
                                             "trace mounted due to tcp_seq",
                                             host_clock_correct_callback)
                else:
                    # 某些情况下，可能会有两个 SYS Span 拥有同样的 TCP Seq，此类情况一般是由于 eBPF 内核适配不完善导致。
                    # 例如：self.flows 数组中可能包含两个 c-p Span（拥有同样的 TCP Seq）、多个 net Span、一个 s-p Span，开头两个 c-p Span 实际上没有父子关系。
                    # 这里做一个简单的处理，当相邻两个 Span 都是同类 SYS Span 时不要按照 TCP Seq 来设置他们的 Parent 关系。
                    continue
            else:
                # if self.spans[i].parent has parent, possibly it's c-p attach to s-p in `try_attach_client_sys_span_via_sys_span`
                # usually, c-p in [0] index and will not try to attach parent here
                # but in grpc _RESPONSE_X mode, sort order would reverse and make c-p not in [0] index
                # for those scenarios, prioritize tcp_seq connection, and clean c-p's index in s-p's childs

                # 如果 self.spans[i] 已有 parent，很大概率是 c-p 在 `try_attach_client_sys_span_via_sys_span` 过程中关联上了 s-p
                # 通常情况下，c-p 一般在[0]索引，不会在这里尝试关联 parent
                # 而目前在 grpc _RESPONSE_X 模式下，会反转顺序，让 c-p 排序在末端，导致在这里尝试再关联 parent
                # 对此类情况，认为 tcp_seq 关联优先级更高，允许关联，并清理 s-p childs 中的 c-p，否则结果中会重复
                if self.spans[i].parent is not None:
                    self.spans[i].parent.flow['childs'].remove(
                        self.spans[i].get_flow_index())

                self.spans[i].set_parent(self.spans[i - 1],
                                         "trace mounted due to tcp_seq",
                                         host_clock_correct_callback)

    def _sort_network_spans(self):
        """
        对网络span进行排序，排序规则：
        1. 按照TAP_SIDE_RANKS进行排序
        2. 按采集器分组排序，与入口 span 同一个采集器的前移，出口 span 同一个采集器的后移，组内按 start_time 排序
        通常情况下 client-side 是 ingress, server-side 是 egress
        """
        sorted_spans = sorted(
            self.spans,
            key=lambda x: (const.TAP_SIDE_RANKS.get(x.tap_side), x.tap_side))

        # 获取入口 agent，顺序向后扫，找遇到的第一个 c-span
        ingress_agent = ''
        for i in range(len(sorted_spans)):
            if sorted_spans[i].tap_side in (const.TAP_SIDE_CLIENT_PROCESS,
                                            const.TAP_SIDE_CLIENT_NIC,
                                            const.TAP_SIDE_CLIENT_POD_NODE):
                ingress_agent = sorted_spans[i].agent_id
                break

        # 获取出口 agent，逆序向前扫，找遇到的第一个 s-span（也就是最后一个 child）
        egress_agent = ''
        for i in range(len(sorted_spans) - 1, -1, -1):
            if sorted_spans[i].tap_side in (const.TAP_SIDE_SERVER_PROCESS,
                                            const.TAP_SIDE_SERVER_NIC,
                                            const.TAP_SIDE_SERVER_POD_NODE):
                egress_agent = sorted_spans[i].agent_id
                break

        # sort rank for ingress & egress agent
        ingress_rank = 0  # up for ingress
        egreass_rank = 2  # down for egress
        # `flow_field_conflict` confirm `l7_protocol` and `request_type` are same in a network_span_set, so get first is enough
        # `flow_field_conflict` 确保了 `l7_protocol` `request_type` 在同一个 network_span_set 中一定相等，取首个即可
        if len(sorted_spans) > 0 and sorted_spans[0].flow['l7_protocol'] in [
                L7_PROTOCOL_GRPC, L7_PROTOCOL_HTTP2
        ]:
            # in `grpc` protocol, _HEADER and _DATA frame is unidirectional flow which identified as `session`
            # but in fact, when 'req_tcp_seq'=0, it's a 'response', from server-side to client-side, request_type=_RESPONSE_DATA/HEADER
            # so we need to reverse ingress and egress here to re-sort network spans

            # 在 grpc 中, _HEADER 和 _DATA frame 是被标记为 session 的单向流
            # 但实际上，如果 req_tcp_seq=0，说明这其实是一个 response，方向为 server-side -> client-side，request_type=_RESPONSE_DATA/HEADER
            # 对此类情况，应要反转 ingress 和 egress 排序
            if not sorted_spans[0].flow['req_tcp_seq'] and \
                sorted_spans[0].flow['type'] == L7_FLOW_TYPE_SESSION:
                ingress_rank = 2
                egress_agent = 0

        for i in range(len(sorted_spans)):
            if sorted_spans[i].agent_id == ingress_agent:
                sorted_spans[i].flow['agent_rank'] = ingress_rank
            elif sorted_spans[i].agent_id == egress_agent:
                sorted_spans[i].flow['agent_rank'] = egreass_rank
            else:
                sorted_spans[i].flow['agent_rank'] = 1

        sorted_spans = sorted(
            sorted_spans,
            key=lambda x: (x.flow['agent_rank'], -x.flow['response_duration'],
                           x.flow['start_time_us'], -x.flow['end_time_us']))

        # 当 ingress_agent=egress_agent 时
        # 如果中间穿过了其他节点数据，需要将所有 server-side span 排序到末尾
        if ingress_agent == egress_agent:
            first_serverside_index = -1
            for i in range(len(sorted_spans)):
                if sorted_spans[i].tap_side in const.SERVER_SIDE_TAP_SIDES:
                    first_serverside_index = i
                    break

            diff_agent_index = -1
            if first_serverside_index != -1:
                for i in range(first_serverside_index, len(sorted_spans)):
                    if sorted_spans[i].flow['agent_rank'] != 0:
                        diff_agent_index = i
                        break

            if diff_agent_index != -1:
                sorted_spans = sorted_spans[:first_serverside_index] + sorted_spans[
                    diff_agent_index:] + sorted_spans[
                        first_serverside_index:diff_agent_index]

        self.spans = sorted_spans
        # 这里直接取头尾做标记，但标记结果有可能既是 root 也是 leaf
        self.spans[0].is_net_root = True
        self.spans[-1].is_net_leaf = True


class SpanNode:

    def __init__(self, flow: dict):
        self.flow: dict = flow
        self.signal_source: int = -1  # overwrite by Child Class
        self.parent: SpanNode = None
        self.tap_side = flow['tap_side']
        self.agent_id = flow['vtap_id']
        self.auto_instance = _get_auto_instance(self)
        self.auto_instance_type = _get_auto_instance_type(self)
        self.is_ps_root = False
        self.is_ps_leaf = False
        self.is_net_root = False
        self.is_net_leaf = False

    def __eq__(self, other: 'SpanNode') -> bool:
        return self.get_flow_index() == other.get_flow_index()

    def __hash__(self) -> int:
        return self.get_flow_index()

    def set_parent(self,
                   parent: 'SpanNode',
                   mounted_info: str = None,
                   mounted_callback: Callable[['SpanNode', 'SpanNode'],
                                              None] = None):
        if mounted_callback is not None:
            mounted_callback(self, parent)
        self.parent = parent
        _set_parent_mount_info(self.flow, parent.flow, mounted_info)

    def detach_parent(self, parent: 'SpanNode'):
        _remove_parent_relate_info(self.flow, parent.flow)

    # 为高频访问字段添加 getter 函数，减少出错

    def get_parent_id(self) -> int:
        return self.flow.get('parent_id', -1)

    def get_flow_index(self) -> int:
        return self.flow['_index']

    def get_span_id(self) -> str:
        return self.flow.get('span_id', '')

    def get_parent_span_id(self) -> str:
        return self.flow.get('parent_span_id', '')

    def get_x_request_id_0(self) -> str:
        return self.flow.get('x_request_id_0', '')

    def get_x_request_id_1(self) -> str:
        return self.flow.get('x_request_id_1', '')

    def get_syscall_trace_id_request(self) -> int:
        return self.flow.get('syscall_trace_id_request', 0)

    def get_syscall_trace_id_response(self) -> int:
        return self.flow.get('syscall_trace_id_response', 0)

    def get_req_tcp_seq(self) -> int:
        return self.flow.get('req_tcp_seq', 0)

    def get_resp_tcp_seq(self) -> int:
        return self.flow.get('resp_tcp_seq', 0)

    def get_request_id(self) -> int:
        return self.flow.get('request_id', 0)

    def get_response_duration(self) -> int:
        return self.flow.get('response_duration', 0)

    def get_trace_id(self) -> list:
        return self.flow.get('trace_id', [])

    def get_server_port(self) -> int:
        return self.flow.get('server_port', 0)

    def time_range_cover(self,
                         other_sys_span: 'SpanNode',
                         allow_lost_resp=False) -> bool:
        covered = self.flow['start_time_us'] <= other_sys_span.flow[
            'start_time_us'] and self.flow[
                'end_time_us'] >= other_sys_span.flow['end_time_us']
        if allow_lost_resp and not covered:
            # 放松条件，允许 self 只校验一半，即可能 server_span 由于发生异常没有响应，导致时延为 0 ，此时 start_time=end_time
            # XXX: 20250523: 注意此场景要求严格校验，即必须存在 syscall_trace_id_request 相等，其他场景暂不允许，否则容易误关联
            covered = self.flow['start_time_us'] <= other_sys_span.flow[
                'start_time_us'] and self.flow['response_duration'] == 0
        return covered


class AppSpanNode(SpanNode):

    def __init__(self, flow_info: dict):
        super().__init__(flow_info)
        self.signal_source = L7_FLOW_SIGNAL_SOURCE_OTEL
        self.process_span_set: ProcessSpanSet = None


class SysSpanNode(SpanNode):

    def __init__(self, flow_info: dict):
        super().__init__(flow_info)
        self.signal_source = L7_FLOW_SIGNAL_SOURCE_EBPF
        self.process_span_set: ProcessSpanSet = None
        self.network_span_set: NetworkSpanSet = None
        self.process_id = _get_process_id(self)

    def process_matched(self, other_sys_span: SpanNode) -> bool:
        if self.agent_id != other_sys_span.agent_id:
            return False
        self_process = _get_process_id(self)
        other_process = _get_process_id(other_sys_span)

        process_id_match = self_process != 0 and other_process != 0 and self_process == other_process

        # when auto_instance_type is k8s pod, allow auto_instance match instead of process_id match
        auto_instance_match = self.auto_instance_type == other_sys_span.auto_instance_type == const.AUTO_INSTANCE_POD \
                            and self.auto_instance != 0 and self.auto_instance == other_sys_span.auto_instance

        return process_id_match or auto_instance_match


class NetworkSpanNode(SpanNode):

    def __init__(self, flow_info: dict):
        super().__init__(flow_info)
        self.signal_source = L7_FLOW_SIGNAL_SOURCE_PACKET
        self.network_span_set: NetworkSpanSet = None


class ProcessSpanSet:
    """
    一个 ProcessSpanSet 由如下 Span 组成：
    - 零个或一个 s-p SysSpan
    - 零个或多个 s-app、app、c-app，他们之间根据 span_id 和 parent_span_id 关系形成一棵树
    - 且树根的 parent_span_id 指向 s-p 的 span_id
    - 当 s-p 没有 span_id 时，AppSpan 的叶子 Span 指向 c-p，c-p 和 s-p 可通过 syscall_trace_id 关联起来
    """

    def __init__(self, group_key: str):
        # group_key 用于标记 ProcessSpanSet 的唯一性
        # 当以 app_span 构建 process_span_set 时，group_key=parent_span_id
        # 当以 sys_span 构建 process_span_set 时，group_key=auto_instance+index(index 标记同进程 s-p 出现的次数)
        self.group_key = group_key
        # 所有 spans
        self.spans: List[SpanNode] = []
        # 用于存放 `app_span` 的所有 root
        self.app_span_roots: List[SpanNode] = None
        # 用于存放 `app_span` 的所有 leaf
        self.app_span_leafs: List[SpanNode] = None
        # 记录叶子节点的 syscall_trace_id, 用以匹配 s-p root
        self.leaf_syscall_trace_id_request: Set[int] = set()
        self.leaf_syscall_trace_id_response: Set[int] = set()
        # 记录本 ProcessSpanSet 构建过程中的所有 TraceId，只要 c-p/s-p 的 TraceId 有交集即可
        self.g_trace_id: Set[str] = set()
        # 记录叶子节点的 x_request_id => index (in self.spans), 用以匹配 s-p root
        self.leaf_x_request_id: Dict[str, List[int]] = {}
        # 用于显示调用拓扑使用
        self.subnet_id = None
        self.subnet = None
        # 用于关联 event
        self.process_id = None
        self.process_kname = None
        self.gprocess = None
        # 用于聚合包含 sys-span 的服务的时延
        self.auto_service = None  # 在结果集中作为 service_uname，i.e. user-service
        self.auto_service_id = None  # 在结果集中作为 service_uid，i.e. 111
        self.ip = None  # service_uname 的第二优先级
        self.auto_service_type = None
        self.auto_instance_type = None
        # 当只有 app_span 数据时，避免被剪枝，记录 app_service
        self.app_service = None
        self.mounted_callback: Callable[[SpanNode, SpanNode], None] = None

    def __eq__(self, other: 'ProcessSpanSet') -> bool:
        return self.group_key == other.group_key

    def __hash__(self) -> int:
        return hash(self.group_key)

    def _set_app_service(self, span: SpanNode):
        """
        此方法仅对本 process_span_set 设置 app_service ，避免被剪枝
        """
        if self.app_service is None:
            # app_span 中的 app_service key 无方向，不需要额外处理
            self.app_service = span.flow.get('app_service', None)

    def _set_auto_service(self, span: SpanNode):
        """
        此方法统一 sys_span 和 app_span 的统计字段并为 flow 生成一个无方向的 key
        sys_span 和 app_span 都要设置 auto_service
        `pruning_trace` 剪枝之后，需要根据剩下的 trace 按 auto_service 分组统计时延消耗
        为了避免同一进程的 span 分组统计错误，这里统一校准字段
        """
        direction = "1" if span.tap_side in [
            TAP_SIDE_SERVER_PROCESS, TAP_SIDE_SERVER_APP, TAP_SIDE_APP
        ] else "0"
        for key in [
                'auto_service_id',
                'auto_service',
                'auto_service_type',
                'auto_instance_type',
        ]:
            direction_key = f'{key}_{direction}'
            if span.tap_side == TAP_SIDE_APP and not span.flow[direction_key]:
                # 仅对 TAP_SIDE_APP: 具体方向未知，优先获取 server_side，找不到值的时候矫正为 client_side
                direction_key = f'{key}_0'

            if getattr(self, key):
                # 当采集流量先于资源匹配时，auto_service_type 可能会被识别为 IP/Internet IP
                # 资源匹配后，同一 IP 会被矫正为匹配后的资源(i.e.: 云服务器/Service Cluster IP)
                # 对此类情况，尝试更新 self.auto_service 信息，直到 auto_service_type 不再被识别为 IP/Internet IP
                if self.auto_service_type in [
                        const.AUTO_SERVICE_IP,
                        const.AUTO_SERVICE_INTERNET_IP,
                ] or self.auto_instance_type in [
                        const.AUTO_INSTANCE_IP, const.AUTO_INSTANCE_INTERNET_IP
                ]:
                    setattr(self, key, span.flow[direction_key])
                span.flow[key] = getattr(self, key)
            else:
                setattr(self, key, span.flow[direction_key])
                span.flow[key] = span.flow[direction_key]

    def _set_extra_value_for_sys_span(self, span: SpanNode):
        """
        此方法统一 sys_span 的统计字段并为 flow 生成一个无方向的 key
        """
        direction = "1" if span.tap_side in [
            TAP_SIDE_SERVER_PROCESS, TAP_SIDE_SERVER_APP
        ] else "0"
        for key in [
                'subnet_id',
                'subnet',
                'ip',
                'process_kname',
                'process_id',
                'gprocess',
        ]:
            direction_key = f'{key}_{direction}'
            if getattr(self, key):
                span.flow[key] = getattr(self, key)
            else:
                setattr(self, key, span.flow[direction_key])
                span.flow[key] = span.flow[direction_key]

    def _copy_meta_data_from(self, other: 'ProcessSpanSet'):
        """
        split_to_multiple_process_span_set 过程中复制元数据
        """
        self.subnet = other.subnet
        self.subnet_id = other.subnet_id
        self.process_id = other.process_id
        self.process_kname = other.process_kname
        self.gprocess = other.gprocess
        self.ip = other.ip
        self.auto_service = other.auto_service
        self.auto_service_id = other.auto_service_id
        self.auto_service_type = other.auto_service_type
        self.app_service = other.app_service
        self.mounted_callback = other.mounted_callback

    def append_app_span(self, app_span: AppSpanNode):
        app_span.process_span_set = self
        self.spans.append(app_span)
        self._set_app_service(app_span)
        self._set_auto_service(app_span)

    def append_sys_span(self, sys_span: SysSpanNode):
        sys_span.process_span_set = self
        self.spans.append(sys_span)
        self._set_extra_value_for_sys_span(sys_span)
        self._set_auto_service(sys_span)
        if sys_span.tap_side == TAP_SIDE_CLIENT_PROCESS:
            cp_syscall_trace_id_req = sys_span.get_syscall_trace_id_request()
            cp_syscall_trace_id_res = sys_span.get_syscall_trace_id_response()
            cp_x_request_id_0 = sys_span.get_x_request_id_0()
            cp_x_request_id_1 = sys_span.get_x_request_id_1()
            if cp_syscall_trace_id_req:
                self.leaf_syscall_trace_id_request.add(
                    sys_span.get_syscall_trace_id_request())
            if cp_syscall_trace_id_res:
                self.leaf_syscall_trace_id_response.add(
                    sys_span.get_syscall_trace_id_response())
            if cp_x_request_id_0:
                # index of sys_span = len(self.spans)-1
                self.leaf_x_request_id.setdefault(
                    cp_x_request_id_0, []).append(len(self.spans) - 1)
            if cp_x_request_id_1 and cp_x_request_id_1 != cp_x_request_id_0:
                self.leaf_x_request_id.setdefault(
                    cp_x_request_id_1, []).append(len(self.spans) - 1)
        if sys_span.get_trace_id():
            self.g_trace_id.update(sys_span.get_trace_id())

    def remove_server_sys_span(self, sys_span: SysSpanNode):
        # 这里应该要做 append_sys_span 的逆操作(但对象仅为 ServerProcess sys_span)
        # 这里如果曾经 append 过，说明进程匹配成功，_set_extra_value_for_sys_span & _set_auto_service 是正确的，不需做逆操作
        sys_span.process_span_set = None
        self.spans.remove(sys_span)

    def mark_root_and_leaf(self):
        has_child: Set[int] = set()
        for span in self.spans:
            if span.parent is None:
                span.is_ps_root = True
            else:
                has_child.add(span.parent)

        for span in self.spans:
            if span not in has_child:
                span.is_ps_leaf = True

    def get_leafs(self) -> List[SpanNode]:
        has_child: Set[int] = set()
        for span in self.spans:
            if span.parent:
                has_child.add(span.parent)
        leafs = [span for span in self.spans if span not in has_child]
        return leafs

    def _build_app_span_tree(self):
        span_id_to_index: Dict[str, int] = {}
        for i in range(len(self.spans)):
            if self.spans[i].signal_source != L7_FLOW_SIGNAL_SOURCE_OTEL:
                continue
            if self.spans[i].get_span_id():
                span_id_to_index[self.spans[i].get_span_id()] = i

        for i in range(len(self.spans)):
            if self.spans[i].signal_source != L7_FLOW_SIGNAL_SOURCE_OTEL:
                continue
            parent_span_id = self.spans[i].get_parent_span_id()
            parent_span_index = span_id_to_index.get(parent_span_id, -1)
            if parent_span_index != -1:
                self.spans[i].set_parent(
                    self.spans[parent_span_index],
                    "app_span mounted due to parent_span_id",
                    self.mounted_callback)

    # return: List[ProcessSpanSet]
    def split_to_multiple_process_span_set(self) -> list:
        # 先构建树、app-span 内部的父子关系，确认 app-span 的结构
        self._build_app_span_tree()

        # 实际上 parent_id 是 flow_index，先构建一个 flow_index 到 span_index 的映射
        flow_index_to_span_index: Dict[int, int] = {}
        max_flow_index = 0
        for i in range(len(self.spans)):
            flow_index = self.spans[i].get_flow_index()
            flow_index_to_span_index[flow_index] = i
            if flow_index > max_flow_index:
                max_flow_index = flow_index

        # 构建一个并查集，将 spans 按 root 划分成多个子树
        disjoint_set = DisjointSet()
        # 这里会跳索引，不是连续顺序，避免 index out of range，预分配大小
        disjoint_set.disjoint_set = [-1] * (max_flow_index + 1)
        for i in range(len(self.spans)):
            parent_span_index = flow_index_to_span_index.get(
                self.spans[i].get_parent_id(), -1)
            disjoint_set.put(i, parent_span_index)
            disjoint_set.get(i)

        # root_parent_span_id => ProcessSpanSet
        split_result: Dict[str, ProcessSpanSet] = {}
        for i in range(len(self.spans)):
            root_span_index = disjoint_set.get(i)
            root_parent_span_id = self.spans[
                root_span_index].get_parent_span_id()
            # 如果 parent_span_id 为空说明这里是请求入口，即整棵树的 root
            # 极端情况下可能会有多个没有 parent_span_id 的入口，这里没法分辨它们的关系，不做拆分
            if root_parent_span_id == '':
                root_parent_span_id = f"root-{len(split_result)}"  # 只是标记 root_parent_span_id，没有实际作用
            if split_result.get(root_parent_span_id, None) is None:
                newSet = ProcessSpanSet(root_parent_span_id)
                newSet.app_span_roots = [self.spans[root_span_index]]
                newSet._copy_meta_data_from(self)
                newSet.spans.append(self.spans[i])
                split_result[root_parent_span_id] = newSet
            else:
                existsSet = split_result[root_parent_span_id]
                existsSet.spans.append(self.spans[i])
                # 多个 span 指向一个 root 时，避免重复
                if self.spans[root_span_index] not in existsSet.app_span_roots:
                    existsSet.app_span_roots.append(
                        self.spans[root_span_index])

        # 为了匹配 sys_span 的 c-p，提前构建 app_span 的叶子节点
        # c-p 会下挂为 app_span 的子节点，避免下挂过程中动态更新
        for i, span_set in split_result.items():
            span_set.app_span_leafs = span_set.get_leafs()

        return split_result.values()

    def attach_sys_span_via_app_span(self, sys_span: SysSpanNode) -> bool:
        '''
        将 sys_span 按规则附加到 app_span 的头/尾:
        s-p: 按 app_span.parent_span_id = sys_span.span_id, 作为 app_span 的 parent
        c-p: 按 app_span.span_id = sys_span.span_id, 作为 app_span 的 child
        '''
        if sys_span.tap_side == TAP_SIDE_SERVER_PROCESS:
            return self._attach_server_sys_span(sys_span)
        elif sys_span.tap_side == TAP_SIDE_CLIENT_PROCESS:
            return self._attach_client_sys_span(sys_span)
        else:
            return False

    def _attach_server_sys_span(self, sys_span: SysSpanNode) -> bool:
        # connection priority: span_id > syscall_trace_id > x_request_id
        span_id_of_sys_span = sys_span.get_span_id()
        syscall_trace_id_request = sys_span.get_syscall_trace_id_request()
        syscall_trace_id_response = sys_span.get_syscall_trace_id_response()
        x_request_id_0 = sys_span.get_x_request_id_0()
        x_request_id_1 = sys_span.get_x_request_id_1()
        if span_id_of_sys_span:
            for app_root in self.app_span_roots:
                if span_id_of_sys_span == app_root.get_parent_span_id():
                    if app_root.get_parent_id() < 0:
                        # 如果 span_id 匹配成功，s-p 作为 app-span 的 parent
                        self.append_sys_span(sys_span)
                        app_root.set_parent(
                            sys_span,
                            "s-p sys_span mounted due to same span_id as parent",
                            self.mounted_callback)
                        return True
                    else:
                        # 当上游服务基于同一个 span_id 发出多个请求时，不同的下游服务采集到的 sys span 的 span_id 会一致
                        # 对此类场景，如果有多个 sys_span 的 span_id 符合要求，需要从中找到【时间偏差】最小的一个 span 作为 parent
                        # 如果 parent 的时间覆盖 app_root，时间偏差=0
                        # 如果 parent 的时间不覆盖 app_root，时间偏差=min(delta_start, delta_end)
                        time_delta_old, time_delta_new = 0, 0
                        if not app_root.parent.time_range_cover(app_root):
                            time_delta_old = min(
                                abs(app_root.parent.flow['start_time_us'] -
                                    app_root.flow['start_time_us']),
                                abs(app_root.parent.flow['end_time_us'] -
                                    app_root.flow['end_time_us']))
                        if not sys_span.time_range_cover(app_root):
                            time_delta_new = min(
                                abs(sys_span.flow['start_time_us'] -
                                    app_root.flow['start_time_us']),
                                abs(sys_span.flow['end_time_us'] -
                                    app_root.flow['end_time_us']))
                        if time_delta_new < time_delta_old:
                            self.remove_server_sys_span(app_root.parent)
                            app_root.detach_parent(app_root.parent)
                            self.append_sys_span(sys_span)
                            app_root.set_parent(
                                sys_span,
                                "s-p sys_span mounted due to same span_id as parent",
                                self.mounted_callback)
                        return True
        # span_id not matched, try syscall_trace_id
        if syscall_trace_id_request or syscall_trace_id_response:
            for app_root in self.app_span_roots:
                # 如果 span_id 不存在，说明可能是入口 span，上游没有注入 span_id，此时根据叶子节点 c-p 的 syscall_trace_id 匹配即可
                # 这里匹配可以严格点，s-p 和 c-p 只会同侧(req-req / res-res)相等，避免误关联一个独立的 c-p
                if app_root.get_parent_id() < 0 and (syscall_trace_id_request in self.leaf_syscall_trace_id_request \
                or syscall_trace_id_response in self.leaf_syscall_trace_id_response):
                    self.append_sys_span(sys_span)
                    app_root.set_parent(
                        sys_span,
                        "s-p sys_span mounted due to syscall_trace_id matched c-p",
                        self.mounted_callback)
                    return True

        # span_id/syscall not matched, try x_request_id
        if x_request_id_0 or x_request_id_1:
            # 场景：过 ingress/nginx 进入服务网关/服务，传递了 x_request_id，且作为首个 span 没有 trace_id/span_id
            # 且发生跨线程调度，无法基于 syscall 关联时，允许通过 s-p.x_request_id(0/1) <=> c-p.x_request_id(0/1) 关联
            # 此处已确保 auto_instance_id 一致 （即同一个进程）

            # x_req_id 同侧相等: 透传 x_req_id，来自上游
            # x_req_id 异侧相等: 注入 x_req_id，内部产生
            x_req_id_matched = False
            # 同一个进程内时间一定覆盖
            for same_xreqid_idx in self.leaf_x_request_id.get(
                    x_request_id_0, []):
                if sys_span.time_range_cover(self.spans[same_xreqid_idx]):
                    x_req_id_matched = True
            if not x_req_id_matched:
                for same_xreqid_idx in self.leaf_x_request_id.get(
                        x_request_id_1, []):
                    if sys_span.time_range_cover(self.spans[same_xreqid_idx]):
                        x_req_id_matched = True
            if x_req_id_matched:
                for app_root in self.app_span_roots:
                    if app_root.get_parent_id() < 0:
                        self.append_sys_span(sys_span)
                        app_root.set_parent(
                            sys_span,
                            "s-p sys_span mounted due to x_request_id matched c-p",
                            self.mounted_callback)
                        return True

        return False

    def _attach_client_sys_span(self, sys_span: SysSpanNode) -> bool:
        span_id_of_sys_span = sys_span.get_span_id()
        if not span_id_of_sys_span:
            return False
        for app_leaf in self.app_span_leafs:
            if span_id_of_sys_span == app_leaf.get_span_id():
                # app_span 作为 sys_span 的 parent
                self.append_sys_span(sys_span)
                sys_span.set_parent(
                    app_leaf,
                    "c-p sys_span mounted due to same span_id as child",
                    self.mounted_callback)
                return True
        return False

    def try_attach_client_sys_span_via_sys_span(self,
                                                client_sys_span: SysSpanNode):
        '''
        检查 client_sys_span 是否能被加入本 ProcessSpanSet 中
        如果 self 有 s-p: s-p 时间必须覆盖 c-p ，且通过 syscall_trace_id 或 x_request_id 关联
        return: SysSpanNode(s-p span), str(mounted_info)
        '''
        mounted_info = ""

        # 对 c-p 与 c-p 之间，只能异侧相等（一个 c-p 接收响应后在同一线程发出另一个请求）
        # 这种情况下，尝试匹配 所有叶子节点 c-p 的 syscall_trace_id
        # 这里包含了兄弟 c-p 的关联关系
        client_syscall_match = client_sys_span.get_syscall_trace_id_request() in self.leaf_syscall_trace_id_response \
            or client_sys_span.get_syscall_trace_id_response() in self.leaf_syscall_trace_id_request

        if client_syscall_match:
            mounted_info = "syscall_trace_id matched to c-p child"

        for span in self.spans:
            if span.tap_side == TAP_SIDE_SERVER_PROCESS:
                # span is SysSpanNode
                # isinstance: 类型安全检查，避免调用函数失败
                # process_matched 防错: 避免 auto_instance 匹配到 host 但实际进程不同的情况
                # time_range_cover: 校验 client_sys_flow 是否落入 s-p 时间范围内
                # 这里假设 c-p 正常完成，但 s-p 后续有异常导致没有响应，允许时间仅校验一半，对应参数 allow_lost_resp
                if isinstance(span, SysSpanNode) and \
                    not (span.process_matched(client_sys_span) and span.time_range_cover(client_sys_span, allow_lost_resp=True)):
                    return None, ""

                sys_span_matched = x_request_id_match = same_process_trace_match = False
                # 优先级：syscall_trace_id > x_request_id
                if not client_syscall_match:
                    # syscall_trace_id 判断
                    # 绝大多数情况下，s-p 跟 c-p 只会同侧相等(syscall_req = syscall_req/syscall_resp = syscall_resp)
                    # 但在 MySQL Quit/Close 这类单向会话的情况下，有可能 s-p.syscall_resp = c-p.syscall_req，即最后的线程关闭连接后响应 client
                    sys_span_matched = span.get_syscall_trace_id_request() == client_sys_span.get_syscall_trace_id_request() \
                        or span.get_syscall_trace_id_response() == client_sys_span.get_syscall_trace_id_response() \
                        or span.get_syscall_trace_id_request() == client_sys_span.get_syscall_trace_id_response() \
                        or span.get_syscall_trace_id_response() == client_sys_span.get_syscall_trace_id_request()

                if not client_syscall_match and not sys_span_matched:
                    # x_request_id 判断
                    # s-p.x_req_id_1 = c-p.x_req_id_0: 注入 x_req_id
                    # s-p.x_req_id_1 = c-p.x_req_id_1: 透传 x_req_id (x_req_id_0 同理)
                    x_request_id_match = span.get_x_request_id_0() and (span.get_x_request_id_0() == client_sys_span.get_x_request_id_0()) \
                                        or (span.get_x_request_id_1() and (span.get_x_request_id_1() == client_sys_span.get_x_request_id_1()\
                                          or span.get_x_request_id_1() == client_sys_span.get_x_request_id_0()))
                # for cross-thread span but in same trace_id/process and time range covered
                if not client_syscall_match and not sys_span_matched and not x_request_id_match:
                    # same proces & time cover already find out above, at here we only find out trace_id match
                    # NOTE: this scenario means not only `trace_id`, also maybe have a global sequence id through all services in 1 request
                    # NOTE: here, we use g_trace_id intersection with client_sys_span.trace_id for match, it's for multiple trace_id like:
                    # [s-p: trace_id_1]
                    # [c-p-1: trace_id_1, trace_id_2] [c-p-2: trace_id_2]
                    same_process_trace_match = self.g_trace_id & set(
                        client_sys_span.flow["trace_id"])

                if sys_span_matched:
                    mounted_info = "syscall_trace_id matched to s-p root"
                elif x_request_id_match:
                    mounted_info = "x_request_id matched to s-p root"
                elif same_process_trace_match:
                    mounted_info = "same process/trace_id and time cover by s-p root"

                if sys_span_matched or x_request_id_match or client_syscall_match or same_process_trace_match:
                    # 同一进程下，如果既有 x_request_id 匹配关系，也有 syscall_trace_id 匹配，如果扫描 process_span_set 顺序不同，会导致挂错
                    # 对此类情况，先不要直接追加，应追加到【时间最接近】的一个 process_span_set
                    return span, f"c-p sys-span mounted due to {mounted_info}"
        return None, ""

    def try_append_to_client_sys_span_via_sys_span(
            self, client_sys_span: SysSpanNode):
        '''
        此为 try_attach_client_sys_span_via_sys_span 的反向操作，即尝试用 client_span 吸引 server_span 作为子 span
        此场景目前出现在同一个 auto_instance(pod/chost) 下，通过非 TCP 方式跨进程调用(e.g.: unix socket)
        条件: self 有 s-p: c-p 时间必须覆盖 s-p, 且通过 trace_id/x_request_id 关联
        如果是同进程调用一般不会产生【额外】的 span, 所以这里 syscall_trace_id 【一定】没有关联关系，不需检查
        return: SysSpanNode(s-p span), str(mounted_info)
        '''
        mounted_info = ""
        # NOTE: 由于目前只有 unix socket 有此场景，保持硬限制
        if not client_sys_span.get_server_port() == UNIX_SOCKET_SERVER_PORT:
            return None, ""
        for span in self.spans:
            if not span.get_server_port() == UNIX_SOCKET_SERVER_PORT or \
                not span.parent is None or \
                    span.tap_side != TAP_SIDE_SERVER_PROCESS:
                continue
            # span is SysSpanNode
            # isinstance: 类型安全检查，避免调用函数失败
            # process_matched 防错: 避免 auto_instance 匹配到 host 但实际进程不同的情况
            # time_range_cover: 校验 s-p 是否落入 c-p 时间范围内
            # allow_lost_resp = False: 由于这里关联关系比较弱，必须要求 req/resp 完整避免误关联
            if isinstance(span, SysSpanNode) and \
                not (span.process_matched(client_sys_span) and client_sys_span.time_range_cover(span, allow_lost_resp=False)):
                return None, ""

            # x_request_id 判断
            # s-p.x_req_id_1 = c-p.x_req_id_0: 注入 x_req_id
            # s-p.x_req_id_1 = c-p.x_req_id_1: 透传 x_req_id (x_req_id_0 同理)
            x_request_id_match = span.get_x_request_id_0() and (span.get_x_request_id_0() == client_sys_span.get_x_request_id_0()) \
                                or (span.get_x_request_id_1() and (span.get_x_request_id_1() == client_sys_span.get_x_request_id_1()\
                                    or span.get_x_request_id_1() == client_sys_span.get_x_request_id_0()))

            same_process_trace_match = False
            # for cross-thread span but in same trace_id/process and time range covered
            if not x_request_id_match:
                # same proces & time cover already find out above, at here we only find out trace_id match
                # NOTE: this scenario means not only `trace_id`, also maybe have a global sequence id through all services in 1 request
                same_process_trace_match = self.g_trace_id & set(
                    client_sys_span.flow["trace_id"])

            if x_request_id_match:
                mounted_info = "x_request_id matched to c-p root"
            elif same_process_trace_match:
                mounted_info = "same process/trace_id and time cover by c-p root"

            if x_request_id_match or same_process_trace_match:
                return span, f"s-p sys-span mounted due to {mounted_info}"
        return None, ""

    def indirect_attach_client_sys_span_via_sys_span(
            self, server_sys_span: SpanNode,
            client_sys_span: SysSpanNode) -> bool:
        """
        如果一个 client_sys_span 的兄弟被关联上 s-p，这里通过间接关系将 client_sys_span 追加到本 ProcessSpanSet 中
        """
        # 防错
        if server_sys_span is None:
            return False

        # 这里是通过兄弟 client_sys_span 关联上的，即兄弟 c-p 存在 syscall_trace_id 相等，支持 allow_lost_resp
        if isinstance(server_sys_span, SysSpanNode) and \
            not (server_sys_span.process_matched(client_sys_span) and server_sys_span.time_range_cover(client_sys_span, allow_lost_resp=True)):
            return False

        if client_sys_span.parent is not None:
            return True

        # 由于这里是通过兄弟 c-p 的 syscall_trace_id 匹配，直接关联，不考虑与 s-p 是否有相等关系
        self.append_sys_span(client_sys_span)
        client_sys_span.set_parent(server_sys_span,
                                   "c-p sys-span mounted due to brother c-p",
                                   self.mounted_callback)
        return True


def _get_auto_instance_type(span: SpanNode) -> str:
    """
    get auto_instance type for span
    only for Ebpf/Packet signal source
    """
    return span.flow["auto_instance_type_0"] if span.tap_side.startswith(
        'c') and span.tap_side != "app" else span.flow["auto_instance_type_1"]


def _get_auto_instance_name(span: SpanNode) -> str:
    """
    get auto_instance name for span
    only for Ebpf/Packet signal source
    """
    return span.flow["auto_instance_0"] if span.tap_side.startswith(
        'c') and span.tap_side != "app" else span.flow["auto_instance_1"]


def _get_auto_instance(span: SpanNode) -> str:
    """
    get auto_instance of span
    note: incase we only get app span(maybe from tracing_completion api), we need to use app_instance to fix `instance`
    """
    server_side_key = 'auto_instance_id_1'
    client_side_key = 'auto_instance_id_0'
    # 对 x-app 位置的 flow，有可能 auto_instance_id=0，说明是外部资源
    # 外部资源不要分到同一组，按 auto_instance/app_instance 的优先级获取
    if span.tap_side == TAP_SIDE_SERVER_APP:
        auto_instance = span.flow[server_side_key] if span.flow[
            server_side_key] else span.flow['auto_instance_1']
        if not auto_instance:
            auto_instance = span.flow['app_instance']
        return auto_instance
    elif span.tap_side == TAP_SIDE_CLIENT_APP:
        auto_instance = span.flow[client_side_key] if span.flow[
            client_side_key] else span.flow['auto_instance_0']
        if not auto_instance:
            auto_instance = span.flow['app_instance']
        return auto_instance
    elif span.tap_side == TAP_SIDE_APP:
        auto_instance = span.flow[server_side_key] if span.flow[
            server_side_key] else span.flow['auto_instance_1']
        if not auto_instance:
            auto_instance = span.flow[client_side_key] if span.flow[
                client_side_key] else span.flow['auto_instance_0']
        if not auto_instance:
            auto_instance = span.flow['app_instance']
        return auto_instance
    # 对 x-p 位置的 flow 一定能获取到 auto_instance_id
    elif span.tap_side == TAP_SIDE_SERVER_PROCESS:
        return span.flow[server_side_key]
    elif span.tap_side == TAP_SIDE_CLIENT_PROCESS:
        return span.flow[client_side_key]
    else:
        return ""


def _get_process_id(span: SpanNode) -> int:
    if span.tap_side == TAP_SIDE_SERVER_PROCESS:
        return span.flow.get('process_id_1', 0)
    elif span.tap_side == TAP_SIDE_CLIENT_PROCESS:
        return span.flow.get('process_id_0', 0)
    else:
        return 0


def _generate_pseudo_process_span_set(network_leaf: dict,
                                      network_root: dict) -> ProcessSpanSet:
    fake_sp = dict(network_leaf)
    fake_sp['tap_side'] = TAP_SIDE_SERVER_PROCESS
    fake_sp['_ids'] = []

    fake_cp = dict(network_root)
    fake_cp['tap_side'] = TAP_SIDE_CLIENT_PROCESS
    fake_cp['_ids'] = []
    pss = ProcessSpanSet(
        f'pseudo-{fake_sp["req_tcp_seq"]}-{fake_sp["resp_tcp_seq"]}')
    pss.append_sys_span(fake_sp)
    pss.append_sys_span(fake_cp)
    return pss


def merge_flow(flows: list, flow: dict) -> bool:
    """
    按如下策略合并：
    按 start_time 递增的顺序从前向后扫描，每发现一个响应，都找一个它前面的请求。
    合并逻辑暂不考虑 HTTP 1.1 中的 Pipeline 机制（发送一系列请求后依次接收响应）。

    DNS sys span 的特殊场景：
    一次 DNS 请求会触发多次 DNS 应答的系统调用，因此这个 DNS 请求需要和后续多个 DNS 响应合并到一起。
    合并条件为：请求的 cap_seq_0 或会话的 cap_seq_1 == 响应的cap_seq_1 - 1

    grpc frame 合并场景：
    grpc stream 模式会在请求或响应时同步触发单向 frame 调用，request_type=_REQUEST_DATA/_RESPONSE_HEADER/_RESPONSE_DATA
    由于 frame 是单向的，无法计算时延，因此将它合并到同观测点、同一个 stream_id 的 Span 里
    """
    # flows 是按照时间顺序从小到大插入的，因此合并过程中只可能出现 RESPONSE 合并到 REQUEST 或 SESSION 中的情况，
    # 而且其中 RESPONSE 合并到 SESSION 的情况只出现在 is_dns_sys_span 的场景。
    if flow['type'] != L7_FLOW_TYPE_RESPONSE and flow['l7_protocol'] not in [
            L7_PROTOCOL_GRPC, L7_PROTOCOL_HTTP2
    ]:
        return False

    # for special case: DNS sys span
    is_sys_span = flow['tap_side'] in [
        TAP_SIDE_SERVER_PROCESS, TAP_SIDE_CLIENT_PROCESS
    ]
    is_dns_sys_span = flow['l7_protocol'] == L7_PROTOCOL_DNS and is_sys_span
    # 这里仅要求 frame 合并到会话中，只过滤 duration=0
    is_grpc_frame_span = flow['l7_protocol'] in [
        L7_PROTOCOL_GRPC, L7_PROTOCOL_HTTP2
    ] and flow['response_duration'] == 0

    # 当存在 request_id 时，一般意味着同一个 L4 Flow 中的请求是并发的（不会等待响应返回就发下一个请求）
    # 但有一个特殊是 MySQL，参考：https://deepflow.io/docs/zh/features/universal-map/l7-protocols/#mysql
    need_compare_request_id = flow['request_id'] and flow[
        'l7_protocol'] != L7_PROTOCOL_MYSQL

    # 对 is_dns_sys_span 和 is_grpc_frame_span，允许合并到非 Request 中
    allow_merge_type = is_dns_sys_span or is_grpc_frame_span

    for i in range(len(flows) - 1, -1, -1):
        if flows[i][
                'type'] != L7_FLOW_TYPE_REQUEST and not allow_merge_type:  # 不满足条件的仅需要合并至 REQUEST
            continue

        # 通过 vtap_id + flow_id + request_id 匹配到同一个 Request
        # vtap_id + flow_id：唯一确定一条 L4 Flow
        # request_id：用于并发请求的场景
        important_field_not_match = False
        for key in ['vtap_id', 'flow_id', 'request_id']:
            if flow[key] != flows[i][key]:
                important_field_not_match = True
                break
        if important_field_not_match:
            continue

        if flows[i]['l7_protocol'] != flow[
                'l7_protocol'] and not is_grpc_frame_span:
            # 一个 L4 Flow 中的前序 flow 是异种协议时，暂不考虑合并，避免误匹配
            # 目前允许 gRPC/HTTP2 frame 合并
            # 可能出现多种协议的情况：HTTP2 和 gRPC、TLS 和应用协议、Service Mesh Sidecar 所有流量
            return False

        if need_compare_request_id:
            # request_id 匹配成功即可合并，下面主要排除一些（不可能发生）的异常场景
            if flows[i][
                    'type'] != L7_FLOW_TYPE_REQUEST and not allow_merge_type:
                # 前序 flow 不是 REQUEST：不可合并，并停止合并以避免误匹配
                return False

        if is_dns_sys_span:
            # DNS sys span，要求 cap_seq 一定要连续才能合并
            if flows[i]['type'] == L7_FLOW_TYPE_REQUEST:
                if flows[i]['syscall_cap_seq_0'] + 1 != flow[
                        'syscall_cap_seq_1']:
                    continue
            else:
                if flows[i]['syscall_cap_seq_1'] + 1 != flow[
                        'syscall_cap_seq_1']:
                    continue
        else:
            if flows[i]['type'] != L7_FLOW_TYPE_REQUEST:
                # 前序 flow 不是 REQUEST：不可合并，并停止合并以避免误匹配
                return False
            if is_sys_span and (flows[i]['syscall_cap_seq_0'] + 1
                                != flow['syscall_cap_seq_1']):
                # 对于 sys span，要求 cap_seq 一定要连续
                continue

        # merge flow
        if flows[i]['type'] == L7_FLOW_TYPE_REQUEST:
            flows[i]['type'] = L7_FLOW_TYPE_SESSION
        for key in flow.keys():
            if key == '_id':
                flows[i][key].extend(flow[key])
            elif not flows[i].get(key):  # attention: L7_FLOW_TYPE_REQUEST = 0
                flows[i][key] = flow[key]
        if flows[i]['end_time_us'] < flow['end_time_us']:
            flows[i]['end_time_us'] = flow['end_time_us']
            flows[i]['response_duration'] = flows[i]['end_time_us'] - flows[i][
                'start_time_us']
        # 对 grpc_frame_span，更新 resp_tcp_seq 和 cap_seq_1 会破坏原来的流信息，这里只做 _id 与 end_time 合并即可
        if not is_grpc_frame_span:
            flows[i]['resp_tcp_seq'] = flow['resp_tcp_seq']
            flows[i]['syscall_cap_seq_1'] = flow['syscall_cap_seq_1']
        return True

    return False


def sort_all_flows(dataframe_flows: DataFrame, network_delay_us: int,
                   host_clock_offset_us: int, return_fields: list) -> list:
    """对应用流日志排序，用于绘制火焰图。（包含合并逻辑）

    1. 根据系统调用追踪信息追踪：
          1 -> +-----+
               |     | -> 2
               |     | <- 2
               | svc |
               |     | -> 3
               |     ! <- 3
          1 <- +-----+
       上图中的服务进程svc在接受请求1以后，向下游继续请求了2、3，他们之间的关系是：
          syscall_trace_id_request_1  = syscall_trace_id_request_2
          syscall_trace_id_response_2 = syscall_trace_id_request_3
          syscall_trace_id_response_3 = syscall_trace_id_response_1
       上述规律可用于追踪系统调用追踪信息发现的流日志。

    2. 根据主动注入的追踪信息追踪：
       主要的原理是通过x_request_id、span_id匹配追踪，这些信息穿越L7网关时保持不变。

    3. 根据网络流量追踪信息追踪：
       主要的原理是通过TCP SEQ匹配追踪，这些信息穿越L2-L4网元时保持不变。

    4. 融合1-3的结果，并将2和3中的结果合并到1中
    """
    flows = []
    # 按start_time升序，用于merge_flow
    dict_flows = dataframe_flows.sort_values(by=["start_time_us"],
                                             ascending=True).to_dict("list")
    for index in range(len(dataframe_flows.index)):
        flow = {}
        for key in return_fields:
            key = key.strip("'")  # XXX: why???
            value = dict_flows[key][index]
            if key == '_id':  # 流合并后会对应多条记录
                flow[key] = [value]
            elif key == 'trace_id':
                # NOTE: trace_id 可能是 xxx,yyy 多值，修改为排序过的 list，方便比较
                # 排序是为了避免 yyy,xxx != xxx,yyy 的情况
                # 注意从这一刻开始，后面所有用到 flow[trace_id] 的地方得到的都是 list(string)
                # 直到 format_final_result 函数
                flow[key] = sorted(
                    [v.strip() for v in value.split(",") if v.strip()])
                flow['origin_trace_id'] = value
            elif isinstance(value, float) and math.isnan(value):
                # XXX: 要在源头统一处理
                # ClickHouse 中的 Nullable(int) 字段在无值时会返回为 dataframe 中的 float(nan)
                # 在 Python 中 float(nan) != float(nan)，因此将其转为 None 方便比较
                # request_id 就是一个 Nullable(uint64) 字段
                flow[key] = None
            else:
                flow[key] = value
        if merge_flow(flows, flow):  # 合并单向Flow为会话
            continue
        flow['_index'] = len(flows)  # assert '_index' not in flow
        flow['_querier_region'] = dict_flows['_querier_region'][
            index]  # set _querier_region for multi-region
        flows.append(flow)
    # 注意：不要对 flows 再做排序，下面的代码会通过 flows[flow_index] 来反查 flow

    # flow 合并之后，添加一个 selftime，后续要用到
    # XXX: 这个字段应该不用添加，考虑直接使用 response_duration
    for flow in flows:
        flow['selftime'] = flow['response_duration']

    # 对合并后的 flow 计算 related_flow_index_map，用于后续操作的加速
    related_flow_index_map = defaultdict(inner_defaultdict_int)
    trace_infos = TraceInfo.construct_from_dict_list(flows)
    # 注意：这里对 network span 使用弱关联关系，使得能体现在 span 溯源关系上
    set_all_relate(trace_infos,
                   related_flow_index_map,
                   network_delay_us,
                   host_clock_offset_us,
                   network_allow_weak_related=True)  # XXX: slow function
    # 构建一个 flow._index 到 flow._id(s) 的映射，方便后续 related_flow_index_map 的使用
    flow_index_to_id0 = [0] * len(flows)
    for flow in flows:
        flow_index_to_id0[flow['_index']] = flow['_id'][0]

    # auto_instance => agent_id
    # data from Packet,Ebpf, for OTel instance mapping
    instance_to_agent = dict()
    network_spans: List[NetworkSpanNode] = []
    app_spans: List[AppSpanNode] = []
    server_sys_spans: List[SysSpanNode] = []
    client_sys_spans: List[SysSpanNode] = []
    # 对 flow 分类，而后分别做排序，方便做层级处理
    # 注意这里 flow_index_to_span 的索引顺序与 trace_infos 的索引顺序是一致的，可以直接用 flow_index 或 _id 互相访问
    # 对 network_flows: net-span 的排序按固定的顺序（TAP_SIDE_RANKS），然后根据 span_id 挂 app-span，根据 tcp_seq 挂 sys-span
    # 对 app_flows: app-span 按固定的规则设置层级（span_id/parent_span_id），按 span_id 挂 sys-span 以及挂到 sys-span 构建的 <service> 上
    # 对 syscall_flows: sys-span 需要提取<vtap_id, local_process_id>分组定义为<service> ，并以此为主体构建火焰图骨架
    flow_index_to_span = [None] * len(flows)
    for i in range(len(flows)):
        flow = flows[i]
        span: SpanNode = None
        if flow['signal_source'] == L7_FLOW_SIGNAL_SOURCE_EBPF:
            span = SysSpanNode(flow)
            if span.tap_side == TAP_SIDE_SERVER_PROCESS:
                server_sys_spans.append(span)
            else:
                client_sys_spans.append(span)
            if span.auto_instance != "":
                instance_to_agent[_get_auto_instance_name(
                    span)] = span.agent_id
        elif flow['signal_source'] == L7_FLOW_SIGNAL_SOURCE_PACKET:
            span = NetworkSpanNode(flow)
            network_spans.append(span)
            if span.auto_instance != "":
                instance_to_agent[_get_auto_instance_name(
                    span)] = span.agent_id
        elif flow['signal_source'] == L7_FLOW_SIGNAL_SOURCE_OTEL:
            span = AppSpanNode(flow)
            app_spans.append(span)
        else:
            # avoid error when signal_source is ''
            span = SpanNode(flow)
            log.warning(
                f"unknown flow: {flow['_id']} signal_source: {flow['signal_source']}"
            )
        flow_index_to_span[i] = span

    host_clock_corrector = HostClockCorrector()

    # 构建 Process Span Set
    # 对 app_span 按 auto_instance_id/auto_instance 进行分组
    # auto_instance => []
    process_span_map: Dict[str, List[ProcessSpanSet]] = defaultdict(
        List[ProcessSpanSet])
    process_span_map = _union_app_spans(
        process_span_map, app_spans,
        host_clock_corrector.calculate_host_clock_correction)
    process_span_map = _union_sys_spans(
        process_span_map, server_sys_spans, client_sys_spans,
        host_clock_corrector.calculate_host_clock_correction)

    # 构建 Network Span Set，每个 Network Span Set 里包含具有同一组 tcp_seq 的 net-span & sys-span
    # 有两个作用：1. 将 net-span 按 tcp_seq 分组，2. 提前找到与 net-span 关联的 sys-span
    united_spans = sorted(network_spans + server_sys_spans + client_sys_spans,
                          key=lambda x: x.flow.get("type"),
                          reverse=True)

    network_span_list = _build_network_span_set(
        united_spans, related_flow_index_map, flow_index_to_span,
        host_clock_offset_us, network_delay_us, trace_infos,
        host_clock_corrector.calculate_host_clock_correction)

    ### Process Span Set 分离
    process_span_list = [
        pss for _, process_span_sets in process_span_map.items()
        for pss in process_span_sets
    ]

    # 准备数据，从所有 process 和 network 获取 root 和 leaf
    for pss in process_span_list:
        pss.mark_root_and_leaf()

    process_root_list: List[SpanNode] = []
    process_leaf_list: List[SpanNode] = []
    for pss in process_span_list:
        for item in pss.spans:
            if item.is_ps_root:
                process_root_list.append(item)
            if item.is_ps_leaf:
                process_leaf_list.append(item)

    network_leafs = [network.spans[-1] for network in network_span_list]
    # network_roots = [network.spans[0] for network in network_span_list]
    # request_id => network_roots
    network_roots_with_req_id = {}
    for network in network_span_list:
        req_id = network.spans[0].get_request_id()
        if req_id is not None and req_id > 0:
            network_roots_with_req_id.setdefault(req_id,
                                                 []).append(network.spans[0])

    # 将 process span set 和 network span set 互相连接
    # 注意这里按如下优先级连接:
    # 1. process <-> net, 2. net <-> process, 3. process <-> process, 4. net <-> net
    _connect_process_and_networks(
        process_root_list, process_leaf_list, network_roots_with_req_id,
        network_leafs, flow_index_to_span, related_flow_index_map,
        host_clock_corrector.calculate_host_clock_correction)

    return process_span_list, network_span_list, flow_index_to_id0, related_flow_index_map, host_clock_corrector.tidy_host_clock_correction(
    ), instance_to_agent


def _union_app_spans(
    process_span_map: Dict[str,
                           List[ProcessSpanSet]], app_spans: List[AppSpanNode],
    host_clock_correct_callback: Callable[[SpanNode, SpanNode], None]
) -> Dict[str, List[ProcessSpanSet]]:
    # 对 auto_instance_type != pod 类型的 app span，有可能所有的 app 都在同一个 instance(i.e.: node) 上
    # 此类情况，允许按照 app_service 划分找到 leaf/root app span
    # 但注意不一定有 app_service attribute，这里只能尽力尝试
    # app_service => index of process_span_map[auto_instance]
    app_service_to_index: Dict[str, int] = {}
    for span in app_spans:
        auto_instance = span.auto_instance
        app_service = span.flow.get("app_service", "")
        split_by_app_service = span.auto_instance_type != const.AUTO_INSTANCE_POD and app_service
        if auto_instance not in process_span_map:
            sp_span_pss = ProcessSpanSet(auto_instance)
            sp_span_pss.mounted_callback = host_clock_correct_callback
            if split_by_app_service:
                app_service_to_index[app_service] = 0
            process_span_map[auto_instance] = [sp_span_pss]
        if split_by_app_service and app_service_to_index.get(app_service,
                                                             -1) == -1:
            # 构建一个新的 app_service 分组
            sp_span_pss = ProcessSpanSet(auto_instance)
            sp_span_pss.mounted_callback = host_clock_correct_callback
            app_service_to_index[app_service] = len(
                process_span_map[auto_instance])
            process_span_map[auto_instance].append(sp_span_pss)

        if split_by_app_service:
            # app_service_to_index.get() 默认值使用 0，避免出错丢弃，即使父子关系挂错也不要少 span
            process_span_map[auto_instance][app_service_to_index.get(
                app_service, 0)].append_app_span(span)
        else:
            process_span_map[auto_instance][0].append_app_span(span)

    # 一组 app-span 构成的 ProcessSpanSet 可能会有多个 root
    # 如果这些 root 有同一个 parent_span_id: 说明只是还没关联 s-p 作为 parent，不需处理，后续逻辑会关联
    # 如果这些 root 有不同的 parent_span_id: 说明这个服务被穿越了多次，要拆分为多个 ProcessSpanSet
    for key, process_span_set_list in process_span_map.items():
        split_process_span_set: List[ProcessSpanSet] = []
        for sp_span_pss in process_span_set_list:
            split_result = sp_span_pss.split_to_multiple_process_span_set()
            split_process_span_set.extend(split_result)
        process_span_map[key] = split_process_span_set
    return process_span_map


def _union_sys_spans(
    process_span_map: Dict[str, List[ProcessSpanSet]],
    server_sys_spans: List[SysSpanNode], client_sys_spans: List[SysSpanNode],
    host_clock_correct_callback: Callable[[SpanNode, SpanNode], None]
) -> Dict[str, List[ProcessSpanSet]]:

    # 先根据 syscall_trace_id_request 构建一个映射，方便查找
    # syscall_trace_id_request => index
    syscall_req_to_index: Dict[int, List[int]] = {}
    # 额外增加 trace_id 的映射，如果这些 c-p 的 trace_id 两两之间有交集，允许通过串联的形式一起 append 到 s-p 下
    trace_id_to_index: Dict[str, List[int]] = {}
    for i in range(len(client_sys_spans)):
        span = client_sys_spans[i]
        if span.get_syscall_trace_id_request() > 0:
            syscall_req_to_index.setdefault(
                span.get_syscall_trace_id_request(), []).append(i)
        for trace_id in span.get_trace_id():
            trace_id_to_index.setdefault(trace_id, []).append(i)

    # 对 client_sys_spans 按 syscall_trace_id 划分为一个个集合
    cp_disjoint_set = DisjointSet()
    cp_disjoint_set.disjoint_set = [-1] * (len(client_sys_spans) + 1)
    for i in range(len(client_sys_spans)):
        span = client_sys_spans[i]
        if span.get_syscall_trace_id_response() > 0:
            # 对任意一个 c-p 的 request，如果它有兄弟 c-p，则 syscall_trace_id_request = 兄弟 c-p 的 syscall_trace_id_response，即为`上一跳`
            parent_indices = syscall_req_to_index.get(
                span.get_syscall_trace_id_response(), [])
            for parent_index in parent_indices:
                cp_disjoint_set.put(i, parent_index)
                cp_disjoint_set.get(i)  # compress
        else:
            # 当有单向 session 的场景（比如 MySQL Quit/Close）时，c-p 的 syscall_trace_id_response = 0，需要根据 syscall_trace_id_request 尝试找到兄弟 c-p
            parent_indices = syscall_req_to_index.get(
                span.get_syscall_trace_id_request(), [])
            for parent_index in parent_indices:
                # 忽略自身
                # 当兄弟 c-p 没有 syscall_trace_id_response 时，避免成环
                if i == parent_index or client_sys_spans[
                        parent_index].get_syscall_trace_id_response() == 0:
                    continue
                # 要把兄弟 c-p 设置为 parent，即：将`下一跳`设置为 parent
                # 当兄弟 c-p 有 syscall_trace_id_response 时，它的 parent 也是下一跳
                cp_disjoint_set.put(i, parent_index)
                cp_disjoint_set.get(i)

        for trace_id in span.get_trace_id():
            parent_indices = trace_id_to_index.get(trace_id, [])
            for parent_index in parent_indices:
                cp_disjoint_set.put(i, parent_index)
                cp_disjoint_set.get(i)

    # 构建一个 cp_infos 的关系，计算 syscall_trace_id_response 对应的所有有关联的 c-p 的索引
    # root_index => { child_indexes }
    cp_related_infos: Dict[int, List[int]] = {}
    for i in range(len(client_sys_spans)):
        root = cp_disjoint_set.get(i)  # find root
        if root != i:
            cp_related_infos.setdefault(root, []).append(i)

    # s-p 按两种方式挂：同一 span_id 关联 app_span，或 s-p 的 span_id 等于空但 s-p 与 c-p 有 syscall_trace_id 关联
    # 后者要求 client_sys_spans 先与 app_span 关联，再尝试关联 server_sys_spans
    # 如果没有 app_span 时，不要做无效扫描
    if len(process_span_map) > 0:
        for span in client_sys_spans + server_sys_spans:  # 先 c-p 后 s-p
            # 这个条件可以直接去掉，全局遍历关联
            # 这里无法预设 app_span 一定包含 auto_instance tag，因此，只能遍历所有 app_span 集合的头尾 span
            # auto_instance = span.auto_instance
            # for sp_span_pss in process_span_map.get(auto_instance, []):
            #     if not sp_span_pss.attach_sys_span_via_app_span(span):
            #         # 这里 attach 失败，但可能关联关系在同一进程其他的 app_span 内，继续尝试
            #         continue
            for auto_instance, sp_span_pss in process_span_map.items():
                for sp_span_ps in sp_span_pss:
                    if sp_span_ps.attach_sys_span_via_app_span(span):
                        break

    # 按 s-p/c-p 的顺序执行关联，确保先通过 s-p 建立 process_span_set，再往上挂 c-p

    # 标记同一进程的 process 数量，同一个 process_span_set 内只允许存在最多一个 s-p
    # sys span 使用 agent_id + process_id 标识唯一进程
    # agent_id + process_id => same process span set
    same_process_sp: Dict[int, int] = defaultdict(int)
    for span in server_sys_spans:
        if span.process_span_set is not None:
            continue
        auto_instance = span.auto_instance
        uniq_process_id = span.agent_id << 32 | span.process_id
        # 可能同一进程被标识为不同的 auto_instance(i.e. 进程内转发，ip 标识为 127.0.0.1)，构建一个映射关系以查找正确的进程关系
        if uniq_process_id not in same_process_sp:
            same_process_sp[uniq_process_id] = auto_instance
        if auto_instance not in process_span_map:
            sp_span_pss = ProcessSpanSet(auto_instance)
            sp_span_pss.mounted_callback = host_clock_correct_callback
            sp_span_pss.append_sys_span(span)
            process_span_map[auto_instance] = [sp_span_pss]
        else:
            # s-p 在每个 ProcessSpanSet 中如果大于1个，说明这个进程被穿越多次，需要单独构建一个 ProcessSpanSet
            index = len(
                process_span_map.get(same_process_sp.get(uniq_process_id, -1),
                                     [])) + 1
            sp_span_pss = ProcessSpanSet(f'{auto_instance}-{index}')
            sp_span_pss.mounted_callback = host_clock_correct_callback
            sp_span_pss.append_sys_span(span)
            process_span_map[auto_instance].append(sp_span_pss)

    # 这里可以认为所有 s-p 已经构建了 ProcessSpanSet
    for i in range(len(client_sys_spans)):
        span = client_sys_spans[i]
        if span.process_span_set is not None:
            continue
        uniq_process_id = span.agent_id << 32 | span.process_id
        # 最终需要上挂的目标 s-p
        target_parent = target_child = None
        target_parent_info = target_child_info = ""
        # 优先级：process_id > auto_instance
        target_sp_list = process_span_map.get(
            same_process_sp.get(uniq_process_id, -1),
            process_span_map.get(span.auto_instance, []))
        for sp_process_span_set in target_sp_list:
            # 检查 c-p 是否在同一进程的 s-p 覆盖范围内，若不在，它应是独立的 ProcessSpanSet
            matched_parent, mounted_info = sp_process_span_set.try_attach_client_sys_span_via_sys_span(
                span)
            if matched_parent is not None:
                if target_parent is None:
                    target_parent = matched_parent
                    target_parent_info = mounted_info
                elif matched_parent.flow['start_time_us'] > target_parent.flow[
                        'start_time_us']:
                    # 在有多个 s-p 都满足匹配条件的情况下，选开始时间最大的(在满足时间覆盖的情况下，这说明此 s-p 最接近 c-p)，它更有可能是直接的【上一跳】
                    target_parent = matched_parent
                    target_parent_info = mounted_info

            matched_child, matched_child_info = sp_process_span_set.try_append_to_client_sys_span_via_sys_span(
                span)
            if matched_child is not None:
                if target_child is None:
                    target_child = matched_child
                    target_child_info = matched_child_info
                elif matched_child.flow['start_time_us'] < target_child.flow[
                        'start_time_us']:
                    target_child = matched_child
                    target_child_info = matched_child_info

        if target_parent is not None:
            target_parent.process_span_set.append_sys_span(span)
            span.set_parent(target_parent, target_parent_info,
                            target_parent.process_span_set.mounted_callback)
            # 如果任意一个 c-p 关联成功，则它的兄弟都尝试关联
            client_root_of_span = cp_disjoint_set.get(i)
            for child in cp_related_infos.get(client_root_of_span, []):
                target_parent.process_span_set.indirect_attach_client_sys_span_via_sys_span(
                    target_parent, client_sys_spans[child])

        if target_child is not None:
            # 不要改变原 process_span_set
            if span.process_span_set is None:
                target_child.process_span_set.append_sys_span(span)
            target_child.set_parent(span, target_child_info,
                                    span.process_span_set.mounted_callback)
    # end of client_sys_span match to server_sys_span

    # 这里分开两次循环，避免[c-p-a 找不到关联关系，先建立了一个 process_span_set，但是 c-p-a 的兄弟 c-p-b 有关联，并将 c-p-a 关联上 s-p，导致重复]的情况
    for i in range(len(client_sys_spans)):
        span = client_sys_spans[i]
        if span.process_span_set is not None:
            continue
        auto_instance = span.auto_instance
        uniq_process_id = span.agent_id << 32 | span.process_id
        # Process Span Set 允许存在多个 c-p，但这些 c-p 如果没有关联关系，需要划分为多个 Process Span Set
        group_key = ''
        auto_instance_index = 0
        if uniq_process_id not in same_process_sp and auto_instance not in process_span_map:
            # 如果找不到 auto_instance，说明没有 s-p，c-p 应作为独立的 ProcessSpanSet
            auto_instance_index = 1
            group_key = auto_instance
            same_process_sp[uniq_process_id] = auto_instance
        else:
            # 如果找到了 auto_instance，但第一轮匹配中没有匹配上任何一个 s-p
            # 此时可能包含两种情况：
            # 1. c-p 无关联关系，或有关系但不在同一个进程的 s-p 时间范围内
            # 2. c-p 同进程的 ProcessSpanSet 内无 s-p
            # xxx: 对情况 2，可以考虑构建一个 pseudo s-p 将所有 c-p 挂接为子
            # 目前这两种情况都作为一个独立的 ProcessSpanSet
            auto_instance_index = len(
                process_span_map.get(same_process_sp.get(uniq_process_id, -1),
                                     process_span_map.get(auto_instance,
                                                          []))) + 1
            group_key = f'{auto_instance}-{auto_instance_index}'
        cp_span_pss = ProcessSpanSet(group_key)
        cp_span_pss.mounted_callback = host_clock_correct_callback
        cp_span_pss.append_sys_span(span)
        process_span_map.setdefault(auto_instance, []).append(cp_span_pss)
    # end of client_sys_span match
    return process_span_map


def _build_network_span_set(
    united_spans: List[SpanNode],
    related_flow_index_map: defaultdict(inner_defaultdict_int),
    flow_index_to_span: List[SpanNode], host_clock_offset_us: int,
    network_delay_us: int, trace_infos: List[TraceInfo],
    host_clock_correct_callback: Callable[[SpanNode, SpanNode], None]
) -> List[NetworkSpanSet]:
    networks: List[NetworkSpanSet] = []

    # 先构建一个 flow index to span 的映射
    flow_aggregated = set()  # set(flow._index)
    for span in united_spans:
        flow_index = span.get_flow_index()
        if flow_index in flow_aggregated:
            continue
        # construct a network
        network = NetworkSpanSet()
        networks.append(network)
        # aggregate self to this network
        network.append_span_node(span)
        flow_aggregated.add(flow_index)
        # aggregate other spans to this network
        for _index, related_types in related_flow_index_map[flow_index].items(
        ):
            if _index in flow_aggregated:
                continue

            if related_types & L7_FLOW_RELATIONSHIP_TCP_SEQ == L7_FLOW_RELATIONSHIP_TCP_SEQ:
                # 这里使用强判断，对 TCP_SEQ 关联的 span要求满足与 L7NetworkMeta.set_relate 等价的条件才能放到一组 network 上
                # 这里每个 span 理论最多被访问一次，会被 flow_aggregated 聚合避免重复访问
                if not L7NetworkMeta.is_relate(
                        trace_infos[flow_index], trace_infos[_index],
                        network_delay_us, host_clock_offset_us):
                    continue
            elif related_types & L7_FLOW_RELATIONSHIP_DNS_REQUEST_ID == L7_FLOW_RELATIONSHIP_DNS_REQUEST_ID:
                pass
            else:
                continue

            network.append_span_node(flow_index_to_span[_index])
            flow_aggregated.add(_index)

    ### 网络span排序
    # 网络 span 按照 tap_side_rank 排序，顺序始终为：c -> 其他 -> s，并按采集器分组排序，同一采集器内按 start_time 排序
    for network in networks:
        network.set_parent_relation(host_clock_offset_us, network_delay_us,
                                    host_clock_correct_callback)
    return networks


def _same_span_set(lhs: SpanNode, rhs: SpanNode, spanset: str) -> bool:
    if hasattr(lhs, spanset) and hasattr(rhs, spanset)\
        and getattr(lhs, spanset) and getattr(rhs, spanset) \
        and getattr(lhs, spanset) == getattr(rhs, spanset):
        return True


def _connect_process_and_networks(
        process_roots: List[SpanNode], process_leafs: List[SpanNode],
        network_roots_with_req_id: Dict[int, SpanNode],
        network_leafs: List[SpanNode], flow_index_to_span: List[SpanNode],
        related_flow_index_map: defaultdict(inner_defaultdict_int),
        host_clock_correct_callback: Callable[[SpanNode, SpanNode], None]):
    # 1. process span set 的 leaf 作为 network span set root 的 parent
    for ps_parent in process_leafs:
        # 避免子循环多次访问字典
        ps_index = ps_parent.get_flow_index()
        ps_span_id = ps_parent.get_span_id()
        ps_response_duration = ps_parent.get_response_duration()
        for _index, related_types in related_flow_index_map.get(ps_index,
                                                                {}).items():
            if related_types & L7_FLOW_RELATIONSHIP_SPAN_ID != L7_FLOW_RELATIONSHIP_SPAN_ID:
                continue
            net_child: SpanNode = flow_index_to_span[_index]
            # NOTE: 这里替代了遍历 net_root 的操作，is_net_root 在 network_span_set 排序后赋值
            if not net_child.is_net_root:
                continue
            if net_child.get_parent_id() >= 0:
                continue
            # 避免同一组 span set 首尾互连
            if _same_span_set(ps_parent, net_child, 'network_span_set') \
                or _same_span_set(ps_parent, net_child, 'process_span_set'):
                continue
            # net_child 只会是 net span / sys span
            if ps_parent.signal_source != L7_FLOW_SIGNAL_SOURCE_OTEL:
                if net_child.agent_id == ps_parent.agent_id and not ps_parent.time_range_cover(
                        net_child):
                    # 对同一个主机采集到的数据，不存在时差
                    continue
                if net_child.get_response_duration(
                ) and ps_response_duration < net_child.get_response_duration():
                    # 如果能取到响应时长（请求响应完整），需要判断响应时长覆盖
                    # 由于 app span 的时长是在 sdk 中统计，如果发生子 span 异步完成，父 span 提前完成，子 span 时间可以大于父 span
                    # 所以这里判断 response_duration 忽略 OTEL signal_source
                    continue
            if ps_span_id and ps_span_id == net_child.get_span_id():
                # net_child 一定是 net-span 且没有 c-p, ps_parent 一定是 app-span，共享一个 span_id
                net_child.set_parent(ps_parent,
                                     "net_span mounted due to same span_id",
                                     host_clock_correct_callback)

    # 2. network span 的 leaf 作为 process span set root 的 parent
    for net_parent in network_leafs:
        net_index = net_parent.get_flow_index()
        net_span_id = net_parent.get_span_id()
        net_response_duration = net_parent.get_response_duration()
        for _index, related_types in related_flow_index_map.get(net_index,
                                                                {}).items():
            if related_types & L7_FLOW_RELATIONSHIP_SPAN_ID != L7_FLOW_RELATIONSHIP_SPAN_ID:
                continue
            ps_child: SpanNode = flow_index_to_span[_index]
            if not ps_child.is_ps_root:
                continue
            if ps_child.get_parent_id() >= 0:
                continue
            if _same_span_set(net_parent, ps_child, 'network_span_set') \
                or _same_span_set(net_parent, ps_child, 'process_span_set'):
                continue
            # net_parent 一定不是 OTEL source
            if ps_child.signal_source != L7_FLOW_SIGNAL_SOURCE_OTEL:
                if ps_child.agent_id == net_parent.agent_id and not net_parent.time_range_cover(
                        ps_child):
                    continue
                if net_response_duration and net_response_duration < ps_child.get_response_duration(
                ):
                    continue
            if ps_index == net_index:
                # 共享一个 s-p，则 ps_child 的 parent == net_parent 的 parent
                continue
            if net_span_id and ps_child.get_span_id(
            ) == net_span_id and ps_child.signal_source != L7_FLOW_SIGNAL_SOURCE_OTEL:
                # ps_child 可能是 s-p, net_parent 可能是 s
                # 这种情况有可能 s-p 在 `flow_field_conflict` 中匹配失败，没有放到同一个 networkspanset 里
                # 为了避免 app_span 连接上末端 net_span 产生环路，这里限制 ps_child 不能是 app_span
                ps_child.set_parent(
                    net_parent,
                    f"{ps_child.tap_side} mounted due to same span_id",
                    host_clock_correct_callback)
            elif net_span_id and ps_child.get_parent_span_id() == net_span_id:
                # ps_child 一定是 app_span 且没有 s-p，net_parent 一定是 net_span 且没有 s-p，二者构成父子关系
                # 注意这里和 [1] 的 ps_parent 匹配 net_child 不一样，因为 net_child 不会创建一个新的 span_id，span_id 一定是相等关系
                # ps_child 如果是 app_span，[apm 规范使用时]它会创建一个新的 span_id，然后通过 parent_span_id 关联
                ps_child.set_parent(
                    net_parent,
                    f"{ps_child.tap_side} mounted due to parent_span_id",
                    host_clock_correct_callback)

    # 3. process span set 互相连接
    for ps_parent in process_leafs:
        ps_parent_index = ps_parent.get_flow_index()
        ps_parent_span_id = ps_parent.get_span_id()
        ps_parent_response_duartion = ps_parent.get_response_duration()
        for _index, related_types in related_flow_index_map.get(
                ps_parent_index, {}).items():
            if related_types & L7_FLOW_RELATIONSHIP_SPAN_ID != L7_FLOW_RELATIONSHIP_SPAN_ID:
                continue
            ps_child: SpanNode = flow_index_to_span[_index]
            if not ps_child.is_ps_root:
                continue
            if ps_child.get_parent_id() >= 0:
                continue
            if _same_span_set(ps_parent, ps_child, 'network_span_set') \
                or _same_span_set(ps_parent, ps_child, 'process_span_set'):
                continue
            if ps_parent.signal_source != L7_FLOW_SIGNAL_SOURCE_OTEL and ps_child.signal_source != L7_FLOW_SIGNAL_SOURCE_OTEL:
                if ps_parent.agent_id == ps_child.agent_id and not ps_parent.time_range_cover(
                        ps_child):
                    continue
                if ps_parent_response_duartion and ps_parent_response_duartion < ps_child.get_response_duration(
                ):
                    continue
            if ps_parent_span_id == ps_child.get_span_id(
            ) and ps_child.signal_source != L7_FLOW_SIGNAL_SOURCE_OTEL:
                # ps_child 可能是 app_span/s-p，ps_leaf 一定是 app_span，都没有 c-p, 共享一个 span_id
                # 这里排除 OTEL source 是因为 OTEL source 不应该在这连接，应在 parent_span_id 关系中连接
                ps_child.set_parent(
                    ps_parent,
                    f"{ps_child.tap_side} mounted due to same span_id",
                    host_clock_correct_callback)
            elif ps_parent_span_id and ps_child.get_parent_span_id(
            ) == ps_parent_span_id:
                ps_child.set_parent(
                    ps_parent,
                    f"{ps_child.tap_side} mounted due to parent_span_id",
                    host_clock_correct_callback)

    # 4. process span set 之间，对 process_roots 尝试连接具有同一个 span_id 的 span
    for ps_child in process_roots:
        if ps_child.get_parent_id() >= 0:
            continue
        ps_child_index = ps_child.get_flow_index()
        ps_child_parent_span_id = ps_child.get_parent_span_id()
        if not ps_child_parent_span_id:
            continue
        # 此场景 related_span 一定是 app_span
        # 因为 sys_span 会在[3]中作为叶子节点关联上 ps_child
        # 只有 app_span 才会有非叶子节点与下级 ps_child 有父子关系的场景
        # 这种情况下关联 ps_child.parent_span_id == ps_parent.span_id 关系
        for _index, related_types in related_flow_index_map.get(
                ps_child_index, {}).items():
            if related_types & L7_FLOW_RELATIONSHIP_SPAN_ID != L7_FLOW_RELATIONSHIP_SPAN_ID:
                continue
            ps_app_parent: SpanNode = flow_index_to_span[_index]
            if ps_app_parent.signal_source != L7_FLOW_SIGNAL_SOURCE_OTEL:
                continue
            if _same_span_set(ps_child, ps_app_parent, 'network_span_set') \
                or _same_span_set(ps_child, ps_app_parent, 'process_span_set'):
                continue
            if not ps_app_parent.time_range_cover(ps_child):
                continue
            if ps_child_parent_span_id == ps_app_parent.get_span_id():
                ps_child.set_parent(
                    ps_app_parent,
                    f"{ps_child.tap_side} mounted due to same span_id",
                    host_clock_correct_callback)

    # 5. network span set 互相连接
    # relations: child.x_request_id_0 == parent.x_request_id_1/child.span_id = parent.span_id
    network_match_parent: Dict[int, int] = {}
    for net_parent in network_leafs:
        net_parent_index = net_parent.get_flow_index()
        net_parent_span_id = net_parent.get_span_id()
        net_parent_x_request_id_0 = net_parent.get_x_request_id_0()
        net_parent_x_request_id_1 = net_parent.get_x_request_id_1()
        net_parent_response_duration = net_parent.get_response_duration()
        for _index, related_types in related_flow_index_map.get(
                net_parent_index, {}).items():
            if related_types & L7_FLOW_RELATIONSHIP_SPAN_ID != L7_FLOW_RELATIONSHIP_SPAN_ID \
                and related_types & L7_FLOW_RELATIONSHIP_X_REQUEST_ID != L7_FLOW_RELATIONSHIP_X_REQUEST_ID:
                continue
            net_child: SpanNode = flow_index_to_span[_index]
            if not net_child.is_net_root:
                continue
            if net_child.get_parent_id() >= 0:
                continue
            if _same_span_set(net_parent, net_child, 'network_span_set') \
                or _same_span_set(net_parent, net_child, 'process_span_set'):
                continue

            # 由于 x_request_id 没有 parent_id 这类设计，容易发生环路，故 net span 都要根据时延判断先后顺序
            if (net_parent_x_request_id_1 and net_parent_x_request_id_1 == net_child.get_x_request_id_0())\
                or (net_parent_x_request_id_0 and net_parent_x_request_id_0 == net_child.get_x_request_id_0()) \
                or (net_parent_x_request_id_1 and net_parent_x_request_id_1 == net_child.get_x_request_id_1()) \
                or (net_parent_span_id and net_parent_span_id == net_child.get_span_id()):

                # 网关注入 x_request_id 的场景: net_parent_x_request_id_1 == net_child.get_x_request_id_0()
                # 网关透传 x_request_id 或透传 http header 中的 span_id
                # 要求 parent 的所有 response_duration > child 最大的 response_duration
                # 由于 network span set 内是按 c 端 agent 在前+ start_time 排序的，可以认为 net_child(root) 就是一组内时延最大的
                if net_parent_response_duration < net_child.get_response_duration(
                ):
                    continue
                # 这里不要直接设置 parent，如果找到了满足条件的情况，都加入列表待处理
                if _index not in network_match_parent:
                    network_match_parent[_index] = net_parent_index
                elif flow_index_to_span[network_match_parent[_index]].get_response_duration() \
                    > net_parent_response_duration:
                    # 根据 `时延最接近` 原则找 parent
                    # 即在满足条件的 parent 里找到时延最接近最小的 net_parent，它更有可能是直接的 `上一跳`
                    # network_match_parent[net_child_index] 指向 net_parent 的 _index，从 flow_index_to_span 中取 response_duration
                    network_match_parent[_index] = net_parent_index
        # end of L7_FLOW_RELATIONSHIP_SPAN_ID and L7_FLOW_RELATION_SHIP_X_REQUEST_ID match

        net_parent_request_id = net_parent.get_request_id()
        net_parent_l7_protocol = net_parent.flow['l7_protocol']
        # XXX: grpc stream here mostly only got 0 response_duration, which makes it difficult to understand in flame graph
        # grpc protocol: request_id get from `stream_id`, means different network_span_set share same stream, it should be connected
        # but other protocol may re-use request_id, so only support grpc now
        # net_child.response_duration <= net_parent.response_duration for case both duration is 0
        # grpc 的 request_id 来源于 `stream_id`, 意味着不同的 network_span_set 在同一个 stream 里，应被连接
        # 但其他协议的 request_id 有可能短时内被多次重用，容易误连接，比如 MySQL 的 StatementID，所以目前仅支持 grpc
        # net_child.response_duration <= net_parent.response_duration 用于双方时延为0 的情况
        # ref: https://www.deepflow.io/docs/zh/features/l7-protocols/http/#http2
        if net_parent_request_id:
            for net_child in network_roots_with_req_id.get(
                    net_parent_request_id, []):
                if net_parent_index == net_child.get_flow_index():
                    continue
                if net_child.get_parent_id() >= 0:
                    continue
                if _same_span_set(net_parent, net_child, 'network_span_set') \
                    or _same_span_set(net_parent, net_child, 'process_span_set'):
                    continue
                if net_parent_l7_protocol in [L7_PROTOCOL_HTTP2, L7_PROTOCOL_GRPC] \
                    and net_parent_l7_protocol == net_child.flow['l7_protocol'] \
                        and net_child.get_response_duration() <= net_parent_response_duration:
                    net_child.set_parent(
                        net_parent, "net_span mounted due to grpc request_id",
                        host_clock_correct_callback)

    for child, parent in network_match_parent.items():
        # FIXME: 生成一个 pseudo net span，待前端修改后再开放此代码，注意处理时延计算
        # fake_pss = _generate_pseudo_process_span_set(flow_index_to_span[child],
        #                                              flow_index_to_span[parent])
        # process_span_list.append(fake_pss)
        # flows.extend(fake_pss.spans)
        flow_index_to_span[child].set_parent(
            flow_index_to_span[parent],
            "net_span mounted due to x_request_id or span_id passed",
            host_clock_correct_callback)


def format_trace(services: List[ProcessSpanSet],
                 networks: List[NetworkSpanSet]) -> dict:
    """
    重新组织数据格式，并给 trace 排序
    """
    response = {'tracing': []}
    id_map = {-1: ""}
    for service in services:
        for span in service.spans:
            if span.signal_source == L7_FLOW_SIGNAL_SOURCE_EBPF:
                span_id = span.get_span_id()
                direct_flow_span_id = generate_span_id() if not span_id or len(
                    str(span_id)) < 16 else span_id
                index_of_span = span.get_flow_index()
                id_map[
                    index_of_span] = f"{direct_flow_span_id}.{span.tap_side}.{index_of_span}"
                response["tracing"].append(_get_flow_dict(span.flow))
            elif span.signal_source == L7_FLOW_SIGNAL_SOURCE_OTEL:
                id_map[span.get_flow_index()] = span.get_span_id()
                response["tracing"].append(_get_flow_dict(span.flow))

    for network in networks:
        for span in network.spans:
            if span.signal_source == L7_FLOW_SIGNAL_SOURCE_EBPF:
                continue
            id_map[span.get_flow_index(
            )] = f"{network.span_id}.{span.tap_side}.{span.get_flow_index()}"
            response["tracing"].append(_get_flow_dict(span.flow))

    for trace in response["tracing"]:
        trace["deepflow_span_id"] = id_map[trace["id"]]
        trace["deepflow_parent_span_id"] = id_map.get(trace["parent_id"], -1)
    response["tracing"] = TraceSort(response["tracing"]).sort_tracing()
    return response


def format_selftime(traces: list, parent_trace: dict, child_ids: list,
                    uid_index_map: Dict[int, int]):
    """
    计算每个服务的真实执行时间
    这里要求按从上而下（父->子）的层级顺序来计算
    """
    parent_self_time = parent_trace["end_time_us"] - parent_trace[
        "start_time_us"]
    if parent_self_time == 0:
        return
    for child_id in child_ids:
        trace_index = uid_index_map.get(child_id, -1)
        if trace_index == -1:
            log.warning(f"The sub-span cannot be found: {child_id}")
            continue
        child_trace = traces[trace_index]
        child_self_time = child_trace["end_time_us"] - child_trace[
            "start_time_us"]
        if child_self_time > 0 and child_self_time <= parent_trace["selftime"]:
            # parent_trace 的处理时间减去 child 的处理时间才是 parent 本身的时延
            parent_trace["selftime"] -= child_self_time
        elif child_self_time > parent_trace["selftime"]:
            # 如果 child_self_time > parent_self_time，很大可能是请求返回了但应用还要执行后续动作或异步场景
            # 应要用 child start time 减去 parent start time 来计算 parent selftime
            # 但由于可能存在时间差，这里无法用 starttime 来计算
            # XXX: 认为 child_self_time 已包含了 parent_self_time，避免重复统计同一段时间
            parent_trace["selftime"] = 0
        else:
            return


def _range_overlap(start_1: int, end_1: int, start_2: int, end_2: int,
                   deviation: int) -> bool:
    return end_1 + deviation >= start_2 and end_2 + deviation >= start_1


# Obtain traces after pruning
def pruning_flows(_id, flows, host_clock_offset_us):
    _FLOW_INDEX_KEY = 'id'  # after _get_flow_dict(), _index change to id
    _FLOW_TRACE_ID_KEY = 'trace_id'

    # 构建一个并查集，用来将所有的 Trace 划分为一个个 Tree
    disjoint_set = DisjointSet()
    for flow in flows:
        index = flow[_FLOW_INDEX_KEY]
        disjoint_set.put(index, flow['parent_id'])
        disjoint_set.get(index)  # compress tree

    # 记录所有 Trace Tree 的最小、最大时间和 trace_id 集合
    # root_index => {min_start_time_us, max_end_time_us, set(trace_id)}
    tree_infos: Dict[int, dict] = {}
    root_of_initial_flow = -1
    for flow in flows:
        index = flow[_FLOW_INDEX_KEY]
        root = disjoint_set.get(index)
        # 找到入口查询的 _id 所在的树
        if _id in flow['_ids']:
            root_of_initial_flow = root
        if root not in tree_infos:
            tree_infos[root] = {
                'min_start_time_us': flow['start_time_us'],
                'max_end_time_us': flow['end_time_us'],
            }
        else:
            tree_info = tree_infos[root]
            if tree_info['min_start_time_us'] > flow['start_time_us']:
                tree_info['min_start_time_us'] = flow['start_time_us']
            if tree_info['max_end_time_us'] < flow['end_time_us']:
                tree_info['max_end_time_us'] = flow['end_time_us']

    if len(tree_infos) == 1:
        return flows

    # 计算每棵树里面的 trace_ids
    trace_id_index_map = {}
    for flow in flows:
        if not flow[_FLOW_TRACE_ID_KEY] or len(flow[_FLOW_TRACE_ID_KEY]) == 0:
            continue
        index = flow[_FLOW_INDEX_KEY]
        root = disjoint_set.get(index)
        if 'trace_ids' not in tree_infos[root]:
            tree_infos[root]['trace_ids'] = set(flow[_FLOW_TRACE_ID_KEY])
        else:
            tree_infos[root]['trace_ids'].update(flow[_FLOW_TRACE_ID_KEY])
        for trace_id in flow[_FLOW_TRACE_ID_KEY]:
            trace_id_index_map.setdefault(trace_id, len(trace_id_index_map))

    # 一般而言，多 trace_id 的场景通常如下：
    # 1. 一定有 trace_id 交叠
    # trace_id    _trace_id_2
    #   aaa[root]    bbb
    #   ccc          bbb
    # 2. 需要先基于 trace_id 找到所有与 root_of_initial_flow 有交叠的 trace_id，这一类 trace_id 都不被剪枝
    # trace_id    _trace_id_2
    #   aaa[root]    bbb
    #   bbb          ccc
    #   ccc          ddd

    trace_id_set = DisjointSet()
    trace_id_set.disjoint_set = [-1] * (len(trace_id_index_map) + 1)
    for flow in flows:
        trace_ids = flow[_FLOW_TRACE_ID_KEY]
        if len(trace_ids) == 0:
            continue
        parent_index = trace_id_index_map[trace_ids[0]]
        parent_root = trace_id_set.get(parent_index)
        for trace_id in trace_ids[1:]:
            child_index = trace_id_index_map[trace_id]
            child_root = trace_id_set.get(child_index)
            if child_root != parent_root:
                trace_id_set.put(child_root, parent_root)
                trace_id_set.get(child_index)

    # avoid unknown exceptions
    if root_of_initial_flow < 0:
        log.warning(f"cannot find the root of initial flow: [{_id}]")
        return flows

    # 保留与 root_of_initial_flow 所在 Trace Tree 时间有交叠的 Trace Tree
    final_flows = []
    initial_tree_info = tree_infos[root_of_initial_flow]
    initial_tree_start_time_us = initial_tree_info['min_start_time_us']
    initial_tree_end_time_us = initial_tree_info['max_end_time_us']
    initial_tree_trace_ids = initial_tree_info.get('trace_ids', set())
    initial_tree_trace_roots = set(
        trace_id_set.get(trace_id_index_map[trace_id])
        for trace_id in initial_tree_trace_ids)
    for root, tree_info in tree_infos.items():
        if not _range_overlap(
                tree_info['min_start_time_us'],
                tree_info['max_end_time_us'],
                initial_tree_start_time_us,
                initial_tree_end_time_us,
                host_clock_offset_us,
        ):
            # 如果时间范围无交叠，但属于同一个 trace_id root 也应该追踪出来
            tree_trace_roots = set(
                trace_id_set.get(trace_id_index_map[trace_id])
                for trace_id in tree_info.get('trace_ids', set()))
            if initial_tree_trace_roots and initial_tree_trace_roots & tree_trace_roots:
                pass
            else:
                # 时间与原始树不交迭、trace_id 与原始树不共享，则进行剪枝
                continue

        # 过了剪枝逻辑的 flow append 到最终结果
        for flow in flows:
            if disjoint_set.get(flow[_FLOW_INDEX_KEY]) == root:
                final_flows.append(flow)

    return final_flows


def pruning_trace(response, _id, host_clock_offset_us):
    """
    剪枝
    response: {'tracing': [flow]}
    """
    flows = response.get('tracing', [])
    response['tracing'] = pruning_flows(_id, flows, host_clock_offset_us)


def calculate_related_ids(
    response, flow_index_to_id0: list, pruning_uid_index_map: dict,
    related_flow_index_map: defaultdict(inner_defaultdict_int)):
    """
    计算 flow 的 related_ids 字段。
    当 related_ids 很多时，构造这些字符串非常耗时，因此这一步放在 pruning_trace 之后进行。

    response: {'tracing': [flow]}
    flow_index_to_id0: flow_index => _id
    pruning_uid_index_map: flow_index => index of reponse.tracing
    related_flow_index_map: flow_index => [{flow_index => related_type}]
    """
    _FLOW_INDEX_KEY = 'id'  # after _get_flow_dict(), _index change to id

    return_flows = response.get('tracing', [])
    for flow in return_flows:
        flow['related_ids'] = []
        for _index, related_types in related_flow_index_map[
                flow[_FLOW_INDEX_KEY]].items():
            if pruning_uid_index_map.get(_index, -1) < 0:
                continue
            _id = flow_index_to_id0[_index]
            flow['related_ids'].append(
                f"{_index}-{L7_FLOW_RELATIONSHIP_MAP[related_types]}-{_id}")


def merge_service(services: List[ProcessSpanSet], traces: list,
                  uid_to_trace_index: Dict[int, int]) -> list:
    """
    按 service 对 flow 分组并统计时延指标，先基于剪枝后的 trace span 过滤服务，对剩下的服务统计时延

    服务分组的依据是：「保持一定的抽象粒度的情况下，尽量找到最小粒度的应用服务」
    通常情况下，service 直接按 auto_service/app_service 分组做合并
    当同一个 auto_service_id 下有多个进程时，执行进程分组逻辑
    同一个 auto_service_id 下有多个进程的场景指的是：
    - k8s: pod 下有多个进程，这些进程互相请求，即为「多个进程」（例如 sidecar 场景）
           否则，即使 k8s service 下匹配多个 pod，只要是同一个进程名(process_kname)，都属于「同一进程」
    - host: 开启「gprocess 同步」的情况下，同一个机器上，有多个不同的进程互相发请求，即为「多个进程」
            否则，如果没有开启 「gprocess 同步」，而刚好他们的 process_kname 一样（比如都叫 python/java）
            那也会认为是「同一个进程」被聚合到一起
            也即虚拟机部署情况下想要看到最优效果必须开启「gprocess 同步」

    在以上逻辑基础上，当有 gprocess 时，使用 (auto_service + gprocess) 作为分组维度
    否则，使用 (auto_service + process_kname) 作为分组维度

    注: gprocess 有值的前提是：
    1. 仅 eBPF 的一侧有
    2. 采集器开启 inputs.proc.enabled
    3. 采集器通过 inputs.proc.process_mathcer 规则匹配到进程

    这里 2+3 步骤称为「gprocess 同步」
    """
    metrics_map = {}
    services_from_process_span_set = set()
    services_from_pruning_traces = set()
    service_to_subprocess = {}
    # 先获取剪枝后的所有 auto_service + app_service
    for res in traces:
        # res: dict after _get_flow_dict()
        if res.get('auto_service'):
            services_from_pruning_traces.add(
                (res.get('auto_service_id'), res.get('auto_service')))
        if res.get('app_service'):
            services_from_pruning_traces.add(res.get('app_service'))

    # 对服务剪枝
    # 在 `sort_all_flows` 函数中分组的 process_span_set 与 services_from_pruning_traces 做匹配，找出最终需要保留的 `service`
    for service in services:
        if (service.auto_service_id, service.auto_service) in services_from_pruning_traces \
                or service.app_service in services_from_pruning_traces:
            services_from_process_span_set.add(service)
            service_to_subprocess.setdefault(service.auto_service_id, set())
            # 优先级：gprocess > process_kname
            if service.gprocess:
                service_to_subprocess[service.auto_service_id].add(
                    service.gprocess)
            elif service.process_kname:
                service_to_subprocess[service.auto_service_id].add(
                    service.process_kname)
        else:
            log.warning(
                f"service: {service.app_service}/{service.auto_service} dropped"
            )

    # 前两者取交集，对剩下的 `auto_service` 做统计
    for service in services_from_process_span_set:
        service_uid, service_uname = "", ""
        process_kname = service.process_kname
        gprocess = service.gprocess
        if service.auto_service_id:
            service_uid = f"{service.auto_service_id}-"
            service_uname = service.auto_service if service.auto_service else service.ip
        elif service.app_service:
            service_uid = f"-{service.app_service}"
            service_uname = service.app_service
        elif service.ip:
            service_uid = f"{service.ip}-"
            service_uname = service.ip
        else:
            service_uid = 'unknown-'
            service_uname = "unknown service"
            log.warning(
                f"service has no auto_service_id or app_service, group_index: {service.group_key}, subnet: {service.subnet}, process: {service.process_kname}, gprocess: {service.gprocess}, ip: {service.ip}"
            )

        # 只对这几种类型按 process 划分进程，否则直接聚合为同一个服务
        # 仅当同一个 auto_service_id 下有多个进程，才会执行此逻辑，否则会直接显示 auto_service
        if len(service_to_subprocess.get(
                service.auto_service_id,
                set())) > 1 and service.auto_instance_type in (
                    const.AUTO_INSTANCE_CHOST, const.AUTO_INSTANCE_POD_NODE,
                    const.AUTO_INSTANCE_POD):
            if gprocess:
                service_uid = f'{service_uid}{gprocess}'
                service_uname = f'{service_uname}:{gprocess}'
            else:
                service_uid = f'{service_uid}{process_kname}'
                service_uname = f'{service_uname}:{process_kname}'

        if service_uid not in metrics_map:
            metrics_map[service_uid] = {
                "service_uid": service_uid,
                "service_uname": service_uname,
                "duration": 0,
            }
        else:
            if metrics_map[service_uid].get('service_uname', '') == '':
                metrics_map[service_uid]['service_uname'] = service_uname

        # 分组之后对 service 底下的所有 flow 设置对应的服务名称，并统计时延
        for span in service.spans:
            span.flow['service_uid'] = service_uid
            span.flow['service_uname'] = service_uname
            trace_index = uid_to_trace_index.get(span.get_flow_index(), -1)
            if trace_index >= 0:
                trace = traces[trace_index]
                trace["service_uid"] = service_uid
                trace["service_uname"] = service_uname
                metrics_map[service_uid]["duration"] += trace["selftime"]

    service_duration_metrics = _call_metrics(metrics_map)
    return service_duration_metrics


def correct_span_time(flows: dict, host_clock_correction: dict,
                      instance_to_agent: dict):
    """
    基于 host_clock_correction 调整 span 的时间误差
    """
    for flow in flows:
        if flow['signal_source'] != L7_FLOW_SIGNAL_SOURCE_OTEL:
            agent_id = flow['vtap_id']
        else:
            # OTel data maybe sent to different host and tag by different agent
            # should verify `agent` by instance_to_agent record by Ebpf/Packet signal source
            agent_id = instance_to_agent.get(flow['auto_instance'],
                                             flow['vtap_id'])
        if host_clock_correction.get(agent_id, 0) != 0:
            flow['start_time_us'] += host_clock_correction[agent_id]
            flow['end_time_us'] += host_clock_correction[agent_id]


def format_final_result(
        services: List[ProcessSpanSet], networks: List[NetworkSpanSet], _id,
        host_clock_offset_us: int, flow_index_to_id0: list,
        related_flow_index_map: defaultdict(inner_defaultdict_int),
        host_clock_correction: dict, instance_to_agent: dict):
    """
    格式化返回结果
    """
    response = format_trace(services, networks)
    # after `format_trace`, _get_flow_dict convert flow to flow_dict
    pruning_trace(response, _id, host_clock_offset_us)  # XXX: slow function
    traces = response.get('tracing', [])
    uid_index_map = {trace["id"]: i for i, trace in enumerate(traces)}
    calculate_related_ids(response, flow_index_to_id0, uid_index_map,
                          related_flow_index_map)  # XXX: slow function
    for trace in traces:
        format_selftime(traces, trace, trace.get("childs", []), uid_index_map)
    response['services'] = merge_service(services, traces, uid_index_map)
    if host_clock_correction is not None:
        correct_span_time(traces, host_clock_correction, instance_to_agent)
        response['host_clock_correction'] = host_clock_correction
    deepflow_span_ids = {
        trace.get('deepflow_span_id')
        for trace in response.get('tracing', [])
    }
    for trace in response.get('tracing', []):
        if trace.get('deepflow_parent_span_id') and trace[
                'deepflow_parent_span_id'] not in deepflow_span_ids:
            trace['deepflow_parent_span_id'] = ''
            trace['parent_id'] = -1
        # 在整个计算过程中，trace_id 都转换为 list(string) 方便计算
        # 最后返回的时候转回原来的字符串用以界面显示
        # 理论上只要经过了 _get_flow_dict 的数据一定有这个 key，但还是必须做防护避免报错
        trace['trace_id'] = trace.get('origin_trace_id', '')
        trace.pop('origin_trace_id', None)
    return response


class TraceSort:

    def __init__(self, traces):
        self.traces = traces

    def sort_tracing(self):
        self.traces = sorted(self.traces, key=lambda x: x["start_time_us"])
        self.uid_index_map = {
            trace["id"]: i
            for i, trace in enumerate(self.traces)
        }

        if len(self.traces) == 0:
            return []

        stack = [trace for trace in self.traces if trace['parent_id'] == -1]
        result = []
        not_found_childs_count = 0
        while stack:
            trace = stack.pop()
            for child_ids in trace.get("childs", []):
                if child_ids not in self.uid_index_map:
                    not_found_childs_count += 1
                    continue
                stack.append(self.traces[self.uid_index_map[child_ids]])
            result.append(trace)

        if not_found_childs_count > 0:
            # 这里还没发生剪枝，此情况不符合期望，记录异常
            log.error(
                f"childs index not found in sort_tracing, try to find trace from: {self.traces[0]['_ids']}"
            )
        elif len(result) < len(self.traces):
            # 这里只会因为环路而被 dropped(所有 parent_id > -1)，不需要额外加检测环
            log.warning(
                f"result tracing were dropped due to rings, try to find trace from: {self.traces[0]['_ids']}"
            )
        return result


def _call_metrics(services: dict):
    """
    计算时延占比
    """
    sum_duration = 0
    response = []
    for _, service in services.items():
        sum_duration += service["duration"]
    for _, service in services.items():
        service["duration_ratio"] = service["duration_ratio"] = '%.2f' % (
            service["duration"] / sum_duration *
            100) if sum_duration > 0 else 0
        response.append(service)
    response = sorted(response, key=lambda x: x.get("duration"), reverse=True)
    return response


def _get_flow_dict(flow: DataFrame):
    flow_dict = {
        "id":
        flow["_index"],  # 注意：字段名修改
        "_ids":
        list(map(str, flow["_id"])),  # 数据库中的 l7_flow_log._id，由于发生了聚合这里是一个数组
        "related_ids":
        None,  # 对标返回结果中的 _ids 字段，即程序逻辑中的 _id 字段，此时原 flow 中还没有这个字段
        "signal_source":
        flow["signal_source"],
        "type":
        flow["type"],
        "start_time_us":
        flow["start_time_us"],
        "end_time_us":
        flow["end_time_us"],
        "duration":
        flow["response_duration"],  # 注意：字段名修改
        "selftime":
        flow["selftime"],
        "tap_side":
        flow["tap_side"],
        "Enum(tap_side)":
        flow.get("Enum(tap_side)"),
        "l7_protocol":
        flow["l7_protocol"],
        "Enum(l7_protocol)":
        flow.get("Enum(l7_protocol)"),
        "l7_protocol_str":
        flow["l7_protocol_str"],
        "endpoint":
        flow["endpoint"],
        "request_type":
        flow["request_type"],
        "request_resource":
        flow["request_resource"],
        "response_status":
        flow["response_status"],
        "flow_id":
        str(flow["flow_id"]),
        "request_id":
        _get_df_key(flow, "request_id"),
        "x_request_id_0":
        flow["x_request_id_0"],
        "x_request_id_1":
        flow["x_request_id_1"],
        "trace_id":
        flow["trace_id"],
        "span_id":
        flow["span_id"],
        "parent_span_id":
        flow["parent_span_id"],
        "req_tcp_seq":
        flow["req_tcp_seq"],
        "resp_tcp_seq":
        flow["resp_tcp_seq"],
        "syscall_trace_id_request":
        str(flow["syscall_trace_id_request"]),
        "syscall_trace_id_response":
        str(flow["syscall_trace_id_response"]),
        "syscall_cap_seq_0":
        flow["syscall_cap_seq_0"],
        "syscall_cap_seq_1":
        flow["syscall_cap_seq_1"],
        "attribute":
        flow.get("attribute", None),
        "parent_id":
        flow.get("parent_id", -1),
        "childs":
        flow.get("childs", []),
        "process_id":
        flow.get("process_id", None),
        "vtap_id":
        flow.get("vtap_id", None),
        "service_uid":
        flow.get("service_uid", None),
        "service_uname":
        flow.get("service_uname", None),
        "app_service":
        flow.get("app_service", None),
        "app_instance":
        flow.get("app_instance", None),
        "tap_port":
        flow["tap_port"],
        "tap_port_name":
        flow["tap_port_name"],
        "resource_from_vtap":
        flow["resource_from_vtap"][2] if len(flow["resource_from_vtap"]) >= 3
        and flow["resource_from_vtap"][0] else None,
        "set_parent_info":
        flow.get("set_parent_info"),
        "auto_instance":
        flow["auto_instance_0"] if flow["tap_side"].startswith('c')
        and flow["tap_side"] != "app" else flow["auto_instance_1"],
        "auto_instance_id":
        flow["auto_instance_id_0"] if flow["tap_side"].startswith('c')
        and flow["tap_side"] != "app" else flow["auto_instance_id_1"],
        "auto_instance_type":
        flow["auto_instance_type_0"] if flow["tap_side"].startswith('c')
        and flow["tap_side"] != "app" else flow["auto_instance_type_1"],
        "tap_id":
        flow.get("tap_id", None),
        "tap":
        flow.get("tap", None),
        "_querier_region":
        flow.get("_querier_region", None),
        "origin_trace_id":
        flow.get("origin_trace_id", None)
    }
    # 0909: 之前的设计逻辑，要求仅 eBPF 返回这些 tag
    # 取消此逻辑，允许所有 span 返回下列数据，支持前端获取 net span 的 auto_service 等 tag 信息，用于在仅有 net span 场景下计算拓扑图
    # if flow["signal_source"] == L7_FLOW_SIGNAL_SOURCE_EBPF:
    flow_dict["subnet"] = flow.get("subnet")
    flow_dict["ip"] = flow.get("ip")
    flow_dict["auto_service"] = flow.get("auto_service")
    flow_dict["auto_service_id"] = flow.get("auto_service_id")
    flow_dict["auto_service_type"] = flow.get("auto_service_type")
    flow_dict["process_kname"] = flow.get("process_kname")
    flow_dict["gprocess"] = flow.get("gprocess")
    return flow_dict


def _get_df_key(df: DataFrame, key: str):  # XXX: 待删除，nan 在最源头进行处理
    if type(df[key]) == float:
        if math.isnan(df[key]):
            return None
    return df[key]


def _set_parent_mount_info(flow: dict, flow_parent: dict, info: str = None):
    flow['parent_id'] = flow_parent['_index']
    if flow_parent.get('childs'):
        flow_parent['childs'].append(flow['_index'])
    else:
        flow_parent['childs'] = [flow['_index']]
    flow['set_parent_info'] = info


def _remove_parent_relate_info(flow: dict, flow_parent: dict):
    flow_parent['childs'].remove(flow['_index'])


def generate_span_id():
    return hex(RandomIdGenerator().generate_span_id())


def _get_epochsecond(id: int):
    """
    `id` encode with (second<<32 | extra flag)
    so we can get epoch second from id with right shift 32 bits
    """
    return id >> 32


class HostClockCorrector:
    """
    计算 [host1][host2] 之间的时间差，并为每一个 host 生成一个唯一的修正值
    hostX 实际上取自 agent_id，也就是以 agent 作为调整对象
    """

    def __init__(self):
        # parent_host(agent_id) => [child_host(agent_id)]
        self.host_relations: Dict[int, Set[int]] = {}
        # child_host(agent_id) => { min_allow_correction, max_allow_correction, avg_allow_correction}
        self.host_clock_correction: Dict[int, Dict[str, float]] = {}

    def calculate_host_clock_correction(self, child: SpanNode,
                                        parent: SpanNode):
        if child.agent_id == parent.agent_id:
            return

        start_time_diff = parent.flow['start_time_us'] - child.flow[
            'start_time_us']
        end_time_diff = parent.flow['end_time_us'] - child.flow['end_time_us']

        if child.signal_source != parent.signal_source and (
                child.signal_source == L7_FLOW_SIGNAL_SOURCE_OTEL
                or parent.signal_source == L7_FLOW_SIGNAL_SOURCE_OTEL):
            # 其中一边是 App，不计算
            if child.tap_side == TAP_SIDE_APP or parent.tap_side == TAP_SIDE_APP:
                return
            # App & Sys Span 即使 agent_id 不一样，也可能是来自同一个 Pod(非本机 agent 接收数据)，这种情况下时延差异纯粹来自于统计，而不是主机误差
            # 对这种情况不应该计算误差，但仅对 App Span 有此逻辑，其他类型的数据时差一定来自主机误差
            if parent.auto_instance != '' and parent.auto_instance != '0' \
                and parent.auto_instance == child.auto_instance:
                return
            # 如果其中一边是 App Span，则只计算毫秒级别的误差
            # 正数向下取整，负数向上取整
            start_time_diff = math.floor(start_time_diff / 1000) * 1000 \
                if start_time_diff > 0 else math.ceil(start_time_diff / 1000) * 1000
            end_time_diff = math.floor(end_time_diff / 1000) * 1000 \
                if end_time_diff > 0 else math.ceil(end_time_diff / 1000) * 1000

        # 如果 start_time_diff < 0 and end_time_diff > 0，说明 parent cover child
        # 但即使是这样，也要写入 host_clock_correction 中，因为 parent 可能与 parent 的 parent 有误差，此时 child 要做重新计算
        self._set_host_clock_correction(parent.agent_id, child.agent_id,
                                        start_time_diff, end_time_diff)

    def _set_host_clock_correction(self, host_parent: int, host_child: int,
                                   start_time_diff: int, end_time_diff: int):
        """
        agent 所在主机的时间差调整以 {agent_id_1, agent_id_2} 作为一对调整对象，校准两两主机之间的时差
        """

        # 由于调整之后，子 span 应要落在父 span 的时间范围内，所以需要根据 start_time/end_time 获取最大/最小允许的调整值，避免过调整
        min_allow_correction = min(start_time_diff, end_time_diff)
        max_allow_correction = max(start_time_diff, end_time_diff)
        avg_correction = (min_allow_correction + max_allow_correction) / 2

        # 避免有环（即同时存在 self.host_relations[parent][child] 与 self.host_relations[child][parent]），需要反转关系
        parent = host_parent
        child = host_child
        if host_parent in self.host_relations.get(host_child, set()):
            parent = host_child
            child = host_parent
            start_time_diff *= -1
            end_time_diff *= -1
            min_allow_correction = min(start_time_diff, end_time_diff)
            max_allow_correction = max(start_time_diff, end_time_diff)
            avg_correction *= -1

        self.host_relations.setdefault(parent, set()).add(child)
        if self.host_clock_correction.get(child) is None:
            # 使用时目前只用到了 min(abs(correction))，即这三个值中最小的一个，但仍然保留其他两个值做 debug 与检查
            self.host_clock_correction[child] = {
                'min_allow_correction': min_allow_correction,
                'max_allow_correction': max_allow_correction,
                'avg_correction': avg_correction
            }
        else:
            # 注意这里不是扩大范围，而是取交集
            correction_info = dict.copy(self.host_clock_correction[child])
            if correction_info['min_allow_correction'] < min_allow_correction:
                correction_info['min_allow_correction'] = min_allow_correction
            if correction_info['max_allow_correction'] > max_allow_correction:
                correction_info['max_allow_correction'] = max_allow_correction

            # 异常情况，意味着有的 parent 要求往右调，有的 parent 要求往左调
            # 此类情况一般出现在 child 时延 > parent 时延时
            # 如果发生这种情况，意味着这个 host 无论怎么调整都会超出 parent 的时间覆盖，无法修正
            # 这里只能记录此异常，且不要更新，以上一次可用的修正信息为准
            if correction_info['min_allow_correction'] > correction_info[
                    'max_allow_correction']:
                log.warning(
                    f"correction for [{host_parent},{host_child}] get invalid value: [{correction_info['min_allow_correction']},{correction_info['max_allow_correction']}]"
                )
                return

            correction_info['avg_correction'] = (
                correction_info['min_allow_correction'] +
                correction_info['max_allow_correction']) / 2
            self.host_clock_correction[child] = correction_info

    def tidy_host_clock_correction(self) -> dict:
        """
        基于收集到的主机间时间差，对每个主机(agent_id)计算出一个调整参数

        调整前提：
        1. 基于一个 hostX 作为基准做统一调整，所有 host 对齐到该 hostX
        2. 理论上要以 rootSpan 的 host 作为基准，这里等价于"没有成为 child"的 host
        3. 注意可能出现多个基准 host，比如存在如下情况：[hostX, hostY], [hostY, hostZ], [hostA, hostB], [hostA, hostC], 此时应该存在 hostX/hostA 两个基准

        调整逻辑：
        1. 基准 host 不做调整，仅对基准 host 以下的 host 做调整（准确地说是只对 child host 调整）
        2. 对一组 [hostA, hostB]，如果存在 [hostX, hostA] 且 hostA 已被调整，则 hostB 的调整值需要加上 hostA 的调整值，以对齐到 hostX
        3. 每一组 host 的调整值都是 min(abs(max, min))，即只做“最小调整”，但要注意保持正负
        """
        # host => time (microseconds)
        host_clock_correction_dict = dict()
        base_host = set()

        for host in self.host_relations.keys():
            if host not in self.host_clock_correction.keys():
                base_host.add(host)

        for host in base_host:
            # base_host 不需要调整，它就是基准，调整值为0
            host_clock_correction_dict.setdefault(host, 0)
            stack = []
            for child in self.host_relations.get(host, set()):
                stack.append((child, 0))
            while stack:
                child, parent_value = stack.pop()
                # 默认取 min
                child_clock_correction = self.host_clock_correction.get(child)
                correction_value = min(
                    child_clock_correction['max_allow_correction'],
                    child_clock_correction['min_allow_correction'])
                # 如果都是负数，取 max (min(abs(value)))
                if child_clock_correction[
                        'max_allow_correction'] < 0 and child_clock_correction[
                            'min_allow_correction'] < 0:
                    correction_value = child_clock_correction[
                        'max_allow_correction']
                # 如果一正一负或其中一个是0，说明这个 host 一定被 parent 时间完全覆盖，不需要调整
                if child_clock_correction[
                        'max_allow_correction'] * child_clock_correction[
                            'min_allow_correction'] <= 0:
                    correction_value = 0
                # 递归调整，即: 如果存在 [HostX, hostA][hostA, hostB]，在调整 hostB 时，需要加上 hostA 相对于 hostX 的调整值
                # 这里有可能 hostB 调整后时间接近 0，说明 hostB 与 hostX 几乎不存在时差，时差仅由 hostA 产生
                # 所以这里不能加绝对值，要加计算值，这样才能使正负抵消
                correction_value += parent_value
                if host_clock_correction_dict.get(child) is None:
                    host_clock_correction_dict[child] = correction_value
                else:
                    exists_value = host_clock_correction_dict[child]
                    if correction_value < 0 and exists_value < 0:
                        correction_value = max(correction_value, exists_value)
                    elif correction_value > 0 and exists_value > 0:
                        correction_value = min(correction_value, exists_value)
                    elif correction_value * exists_value <= 0:
                        correction_value = 0
                    host_clock_correction_dict[child] = correction_value
                for sub in self.host_relations.get(child, set()):
                    # XXX: 暂时只修正一次，避免 host 成环无法 escape loop
                    if sub not in host_clock_correction_dict.keys():
                        stack.append((sub, correction_value))

        # remove 0 value
        non_zero_host_clock_correction = dict()
        for host, correction in host_clock_correction_dict.items():
            if correction != 0:
                non_zero_host_clock_correction[host] = correction
        return non_zero_host_clock_correction
