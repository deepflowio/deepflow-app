import math
import pandas as pd
from log import logger

from ast import Tuple
from pandas import DataFrame
from collections import defaultdict
from data.querier_client import Querier
from config import config
from .base import Base
from common import const
from common.utils import curl_perform, inner_defaultdict_set
from common.const import (HTTP_OK, L7_FLOW_SIGNAL_SOURCE_PACKET, L7_FLOW_SIGNAL_SOURCE_EBPF, L7_FLOW_SIGNAL_SOURCE_OTEL)
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

L7_FLOW_RELATIONSHIP_TCP_SEQ = 'network'
L7_FLOW_RELATIONSHIP_X_REQUEST_ID = 'xrequestid'
L7_FLOW_RELATIONSHIP_SYSCALL_TRACE_ID = 'syscall'
L7_FLOW_RELATIONSHIP_SPAN_ID = 'app'

CAPTURE_CLOUD_NETWORK_TYPE = 3
IP_AUTO_SERVICE = 255
INTERNET_IP_AUTO_SERVICE = 0

RETURN_FIELDS = list(
    set([
        # 追踪Meta信息
        "signal_source",
        "l7_protocol",
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
        "auto_instance_0_node_type",
        "auto_instance_0_icon_id",
        "process_kname_0",
        "subnet_id_1",
        "subnet_1",
        "ip_1",
        "app_service",
        "app_instance",
        "auto_instance_type_1",
        "auto_instance_id_1",
        "auto_instance_1",
        "auto_instance_1_node_type",
        "auto_instance_1_icon_id",
        "process_kname_1",
        "auto_service_type_0",
        "auto_service_id_0",
        "auto_service_0",
        "auto_service_type_1",
        "auto_service_id_1",
        "auto_service_1",
        "tap_id",
        "tap",
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
    "auto_instance_0_node_type":
    "node_type(auto_instance_0) as auto_instance_0_node_type",
    "auto_instance_0_icon_id":
    "icon_id(auto_instance_0) as auto_instance_0_icon_id",
    "auto_instance_1_node_type":
    "node_type(auto_instance_1) as auto_instance_1_node_type",
    "auto_instance_1_icon_id":
    "icon_id(auto_instance_1) as auto_instance_1_icon_id",
    "_id": "toString(_id) as `_id_str`"
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


class L7FlowTracing(Base):

    async def query(self):
        max_iteration = self.args.get("max_iteration", config.max_iteration)
        network_delay_us = self.args.get("network_delay_us")
        ntp_delay_us = self.args.get("ntp_delay_us", 10000)
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
        rst = await self.trace_l7_flow(time_filter=time_filter,
                                       base_filter=base_filter,
                                       max_iteration=max_iteration,
                                       network_delay_us=network_delay_us,
                                       ntp_delay_us=ntp_delay_us)
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
            network_delay_us: int = config.network_delay_us
    ) -> Tuple(list, list):
        """多次迭代，查询可追踪到的所有 l7_flow_log 的摘要
        参数说明：
        time_filter: 查询的时间范围过滤条件，SQL表达式
            当使用四元组进行追踪时，time_filter置为希望搜索的一段时间范围，
            当使用五元组进行追踪时，time_filter置为五元组对应流日志的start_time前后一小段时间，以提升精度
        base_filter: 查询的基础过滤条件，用于限定一个四元组或五元组
        max_iteration: 使用Flowmeta信息搜索的次数，每次搜索可认为大约能够扩充一级调用关系
        network_delay_us: 使用Flowmeta进行流日志匹配的时间偏差容忍度，越大漏报率越低但误报率越高，一般设置为网络时延的最大可能值
        """
        only_query_app_spans = self.signal_sources == ['otel']

        req_tcp_seqs = set()  # set(str(req_tcp_seq))
        resp_tcp_seqs = set()  # set(str(resp_tcp_seq))
        syscall_trace_ids = set()  # set(str(syscall_trace_id))
        x_request_ids = set()  # set(x_request_id)
        allowed_trace_ids = set()  # 所有被允许的 trace_id 集合
        app_spans_from_apm = []

        new_trace_ids_in_prev_iteration = set()  # 上一轮迭代过程中发现的新 trace_id 集合

        # Query1: 先获取 _id 对应的数据
        dataframe_flowmetas = await self.query_flowmetas(
            time_filter, base_filter)
        if type(dataframe_flowmetas) != DataFrame or dataframe_flowmetas.empty:
            return [], []
        dataframe_flowmetas.rename(columns={'_id_str': '_id'}, inplace=True)
        l7_flow_ids = set(dataframe_flowmetas['_id'])  # set(flow._id)

        # 用于下一轮迭代，记录元信息
        new_trace_infos = TraceInfo.construct_from_dataframe(
            dataframe_flowmetas)

        # remember the initial trace_id
        initial_trace_id = self.args.get("trace_id")  # For Tempo API
        if not initial_trace_id:  # For normal query using _id
            initial_trace_id = dataframe_flowmetas.at[0, 'trace_id']
        if initial_trace_id:
            allowed_trace_ids.add(initial_trace_id)
            new_trace_ids_in_prev_iteration.add(initial_trace_id)

        # 进行迭代查询，上限为 config.spec.max_iteration
        for i in range(max_iteration):
            # 1. 使用 trace_id 查询
            if new_trace_ids_in_prev_iteration:
                # 1.1. Call external APM API
                if config.call_apm_api_to_supplement_trace:
                    new_app_spans_from_apm = []
                    for trace_id in new_trace_ids_in_prev_iteration:
                        app_spans = await self.query_apm_for_app_span_completion(
                            trace_id)
                        new_app_spans_from_apm.extend(app_spans)
                    # 此处不需要将 new_app_spans_from_apm 合入 dataframe_flowmetas
                    # app_flow 对迭代查询过程没有更多的帮助
                    app_spans_from_apm.extend(new_app_spans_from_apm)

                # 1.2. Query database by trace_id
                new_trace_ids_str = set(
                    [f"'{nti}'" for nti in new_trace_ids_in_prev_iteration])
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
                if type(new_trace_id_flows
                        ) == DataFrame and not new_trace_id_flows.empty:
                    new_trace_id_flows.rename(columns={'_id_str': '_id'},
                                              inplace=True)

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
                        # 因此要去掉不在 new_trace_ids_in_prev_iteration 中的 trace_id，否则会有误报。
                        new_trace_id = new_trace_id_flows.at[index, 'trace_id']
                        if new_trace_id not in new_trace_ids_in_prev_iteration:
                            new_trace_id_flow_delete_index.append(index)
                            deleted_trace_ids.add(new_trace_id)
                            continue
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
                    new_trace_infos += TraceInfo.construct_from_dataframe(
                        new_trace_id_flows)

                # remove used trace_ids
                new_trace_ids_in_prev_iteration = set()

            else:  # no new_trace_ids_in_prev_iteration
                pass

            if only_query_app_spans:  # no more iterations needed
                break

            # 2. Query by tcp_seq / syscall_trace_id / x_request_id
            new_filters = []
            # 2.1. new tcp_seqs
            new_req_tcp_seqs = set()  # set(str(req_tcp_seq))
            new_resp_tcp_seqs = set()  # set(str(resp_tcp_seq))
            for nti in new_trace_infos:
                if nti.req_tcp_seq and nti.req_tcp_seq not in req_tcp_seqs:
                    req_tcp_seqs.add(nti.req_tcp_seq)
                    new_req_tcp_seqs.add(str(nti.req_tcp_seq))
                if nti.resp_tcp_seq and nti.resp_tcp_seq not in resp_tcp_seqs:
                    resp_tcp_seqs.add(nti.resp_tcp_seq)
                    new_resp_tcp_seqs.add(str(nti.resp_tcp_seq))
            # 2.1. Condition 1: 以 req_tcp_seq & resp_tcp_seq 作为条件查询关联 flow
            tcp_seq_filters = []
            if new_req_tcp_seqs:
                tcp_seq_filters.append(
                    f"req_tcp_seq IN ({','.join(new_req_tcp_seqs)})")
            if new_resp_tcp_seqs:
                tcp_seq_filters.append(
                    f"resp_tcp_seq IN ({','.join(new_resp_tcp_seqs)})")
            if tcp_seq_filters:
                new_filters.append(f"({' OR '.join(tcp_seq_filters)})")
            # 2.2. new syscall_trace_ids
            new_syscall_trace_ids = set()  # set(str(syscall_trace_id))
            for nti in new_trace_infos:
                if nti.syscall_trace_id_request and nti.syscall_trace_id_request not in syscall_trace_ids:
                    syscall_trace_ids.add(nti.syscall_trace_id_request)
                    new_syscall_trace_ids.add(str(
                        nti.syscall_trace_id_request))
                if nti.syscall_trace_id_response and nti.syscall_trace_id_response not in syscall_trace_ids:
                    syscall_trace_ids.add(nti.syscall_trace_id_response)
                    new_syscall_trace_ids.add(
                        str(nti.syscall_trace_id_response))
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
            # 2.3. new x_request_ids
            new_x_request_ids = set()  # set(x_request_id)
            for nti in new_trace_infos:
                if nti.x_request_id_0 and nti.x_request_id_0 not in x_request_ids:
                    x_request_ids.add(nti.x_request_id_0)
                    new_x_request_ids.add(nti.x_request_id_0)
                if nti.x_request_id_1 and nti.x_request_id_1 not in x_request_ids:
                    x_request_ids.add(nti.x_request_id_1)
                    new_x_request_ids.add(nti.x_request_id_1)
            # 2.3. Condition 3: 以 x_request_id_0 & x_request_id_1 作为条件查询关联 flow
            x_request_id_filters = []
            if new_x_request_ids:
                new_x_request_ids_str = [
                    f"'{xri}'" for xri in new_x_request_ids
                ]
                x_request_id_filters.append(
                    f"x_request_id_0 IN ({','.join(new_x_request_ids_str)})")
                x_request_id_filters.append(
                    f"x_request_id_1 IN ({','.join(new_x_request_ids_str)})")
                new_filters.append(f"({' OR '.join(x_request_id_filters)})")

            if not new_filters:  # no more iterations needed
                break

            # Query3: 查询上述基于 Condition[123] 构建出的条件，即与【第一层迭代】关联的所有 flow，此处构建【第二层迭代】查询
            new_flows = pd.DataFrame()
            new_flows = await self.query_flowmetas(time_filter,
                                                   ' OR '.join(new_filters))
            if type(new_flows
                    ) != DataFrame or new_flows.empty:  # no more new flows
                break
            new_flows.rename(columns={'_id_str': '_id'}, inplace=True)

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
                new_trace_id = new_flows.at[index, 'trace_id']
                if new_trace_id and new_trace_id not in allowed_trace_ids:
                    if not allowed_trace_ids or config.allow_multiple_trace_ids_in_tracing_result:
                        allowed_trace_ids.add(new_trace_id)
                        new_trace_ids_in_prev_iteration.add(new_trace_id)
                    else:  # remove conflict trace_id data
                        new_flow_remove_indices.append(index)
                        deleted_trace_ids.add(new_trace_id)
                        continue
            if new_flow_remove_indices:
                new_flows = new_flows.drop(
                    new_flow_remove_indices).reset_index(drop=True)
            if deleted_trace_ids:
                log.debug(f"删除的 trace_id 为：{deleted_trace_ids}")

            # check relationship, and remove unrelated data
            # 先标记可能存在的关联关系，在 related_flow_id_map 中通过多次迭代标记上有关联的 _id
            # 如果一个 _id 没有标记到 related_flow_id_map 中，flow 会被删掉，后续逻辑不再处理
            related_flow_id_map = defaultdict(inner_defaultdict_set)
            trace_infos = TraceInfo.construct_from_dataframe(
                dataframe_flowmetas) + TraceInfo.construct_from_dataframe(
                    new_flows)
            set_all_relate(trace_infos,
                           related_flow_id_map,
                           network_delay_us,
                           fast_check=True,
                           skip_first_n_trace_infos=len(dataframe_flowmetas))
            # 注意上面的 new_flow_remove_indices append 了多次，此处可能去掉的数据有:
            # 通过 tcp_seq / syscall_trace_id / x_request_id / span_id 关联不上任何关系的数据。
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
                new_trace_infos = TraceInfo.construct_from_dataframe(new_flows)

            else:  # no new_flows, no more iterations needed
                break

            # end of `for i in range(max_iteration)`

        return l7_flow_ids, app_spans_from_apm

    async def trace_l7_flow(self,
                            time_filter: str,
                            base_filter: str,
                            max_iteration: int = config.max_iteration,
                            network_delay_us: int = config.network_delay_us,
                            ntp_delay_us: int = 10000) -> dict:
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
        l7_flow_ids, app_spans_from_apm = await self.query_and_trace_flowmetas(
            time_filter, base_filter, max_iteration, network_delay_us)

        if len(l7_flow_ids) == 0:
            return {}

        # 查询会获取这些 _id 对应的完整 l7_flow_log 信息。
        # 通过 RETURN_FIELDS 确定需要返回哪些字段（精简有用的返回信息）
        return_fields = RETURN_FIELDS
        if self.has_attributes:
            return_fields.append("attribute")
        l7_flows = await self.query_all_flows(time_filter, l7_flow_ids,
                                              return_fields)
        if type(l7_flows) != DataFrame or l7_flows.empty:
            # 几乎不可能发生没有 l7_flows 但有 app_spans_from_apm 的情况
            # 实际上几乎不可能发生没有 l7_flows 的情况，因为至少包含初始 flow
            return {}
        l7_flows.rename(columns={'_id_str': '_id'}, inplace=True)

        # 将外部 APM 查询到的 Span 与数据库中的 Span 结果进行合并
        l7_flows = self.concat_l7_flow_log_dataframe(
            [l7_flows, pd.DataFrame(app_spans_from_apm)])

        # 将 null 转化为 None
        l7_flows = l7_flows.where(l7_flows.notnull(), None)

        # 对所有调用日志排序，包含几个动作：排序+合并+分组+设置父子关系
        l7_flows_merged, networks, flow_index_to_id0, related_flow_index_map = sort_all_flows(
            l7_flows, network_delay_us, return_fields, ntp_delay_us)

        return format_final_result(l7_flows_merged, networks,
                                   self.args.get('_id'), network_delay_us,
                                   flow_index_to_id0, related_flow_index_map)

    async def query_ck(self, sql: str):
        querier = Querier(to_dataframe=True,
                          debug=self.args.debug,
                          headers=self.headers)
        response = await querier.exec_all_clusters(DATABASE, sql)
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
        toUnixTimestamp64Micro(end_time) AS end_time_us, vtap_id, syscall_trace_id_request,
        syscall_trace_id_response, span_id, parent_span_id, l7_protocol, trace_id, x_request_id_0,
        x_request_id_1, toString(_id) AS `_id_str`, tap_side, auto_instance_0, auto_instance_1
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

    async def query_apm_for_app_span_completion(self, trace_id: str) -> list:
        get_third_app_span_url = f"http://{config.querier_server}:{config.querier_port}/api/v1/adapter/tracing?traceid={trace_id}"
        app_spans_res, app_spans_code = await curl_perform(
            'get', get_third_app_span_url)
        if app_spans_code != HTTP_OK:
            log.warning(f"Get app spans failed! url: {get_third_app_span_url}")
        app_spans = app_spans_res.get('data', {}).get('spans', [])
        self.complete_app_span(app_spans)
        return app_spans

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
        for flow_id in l7_flow_ids:
            ids.append(f"_id={flow_id}")
        fields = []
        for field in return_fields:
            if field in FIELDS_MAP:
                fields.append(FIELDS_MAP[field])
            else:
                fields.append(field)
        sql = """
        SELECT {fields} FROM `l7_flow_log` WHERE (({time_filter}) AND ({l7_flow_ids})) ORDER BY start_time_us asc
        """.format(time_filter=time_filter,
                   l7_flow_ids=' OR '.join(ids),
                   fields=",".join(fields))
        response = await self.query_ck(sql)
        self.status.append("Query All Flows", response)
        return response["data"]


def set_all_relate(trace_infos: list,
                   related_map: defaultdict(inner_defaultdict_set),
                   network_delay_us: int,
                   fast_check: bool = False,
                   skip_first_n_trace_infos: int = 0):
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

    for ti in trace_infos:
        # tcp_seq
        if ti.signal_source != L7_FLOW_SIGNAL_SOURCE_OTEL:
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
            find_related = L7NetworkMeta.set_relate(ti, related_trace_infos,
                                                    related_map,
                                                    network_delay_us,
                                                    fast_check)
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


class TraceInfo:

    def __init__(self, _id, signal_source, vtap_id, _type, start_time_us,
                 end_time_us, req_tcp_seq, resp_tcp_seq, trace_id, span_id,
                 parent_span_id, x_request_id_0, x_request_id_1,
                 syscall_trace_id_request, syscall_trace_id_response,
                 origin_flow_list, index_in_origin_flow_list):
        self._id = _id
        self.signal_source = signal_source
        self.vtap_id = vtap_id
        self.type = _type
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
        for index in dataframe_flowmetas.index:
            trace_infos.append(
                TraceInfo(
                    dataframe_flowmetas.at[index, '_id'],
                    dataframe_flowmetas.at[index, 'signal_source'],
                    dataframe_flowmetas.at[index, 'vtap_id'],
                    dataframe_flowmetas.at[index, 'type'],
                    # time
                    dataframe_flowmetas.at[index, 'start_time_us'],
                    dataframe_flowmetas.at[index, 'end_time_us'],
                    # tcp_seq
                    dataframe_flowmetas.at[index, 'req_tcp_seq'],
                    dataframe_flowmetas.at[index, 'resp_tcp_seq'],
                    # span_id
                    dataframe_flowmetas.at[index, 'trace_id'],
                    dataframe_flowmetas.at[index, 'span_id'],
                    dataframe_flowmetas.at[index, 'parent_span_id'],
                    # x_request_id
                    dataframe_flowmetas.at[index, 'x_request_id_0'],
                    dataframe_flowmetas.at[index, 'x_request_id_1'],
                    # syscall_trace_id
                    dataframe_flowmetas.at[index, 'syscall_trace_id_request'],
                    dataframe_flowmetas.at[index, 'syscall_trace_id_response'],
                    # origin_flow_list
                    dataframe_flowmetas,
                    index))
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
                    # origin_flow_list
                    flow_dicts,
                    index))
        return trace_infos


class L7XrequestMeta:

    @classmethod
    def set_relate(cls,
                   trace_info: TraceInfo,
                   related_trace_infos: set,
                   related_map: defaultdict(inner_defaultdict_set),
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
                related_map[trace_info._id][rti._id].add(
                    L7_FLOW_RELATIONSHIP_X_REQUEST_ID)
                find_related = True
                if fast_check: return True
                continue
            # x_request_id_1
            if trace_info.x_request_id_1 and trace_info.x_request_id_1 == rti.x_request_id_0:
                related_map[trace_info._id][rti._id].add(
                    L7_FLOW_RELATIONSHIP_X_REQUEST_ID)
                find_related = True
                if fast_check: return True
                continue

        return find_related


class L7NetworkMeta:

    @classmethod
    def flow_field_conflict(cls, lhs: TraceInfo, rhs: TraceInfo) -> bool:
        # span_id
        if lhs.trace_id and lhs.span_id and rhs.trace_id and rhs.span_id and (
                lhs.trace_id != rhs.trace_id or lhs.span_id != rhs.span_id):
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
                'request_resource',
                'response_code',
                'response_exception',
                'response_result',
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

            # Agent 有可能协议识别有误差，没将 HTTP2 识别为 gRPC。
            # 此处忽略这个差异，虽然 HTTP2 不一定都是 gRPC。
            if key == 'l7_protocol' and lhs_value in [
                    L7_PROTOCOL_HTTP2, L7_PROTOCOL_GRPC
            ] and rhs_value in [L7_PROTOCOL_HTTP2, L7_PROTOCOL_GRPC]:
                if lhs_value != rhs_value:
                    is_http2_grpc_and_differ = True
                continue

            if key == 'request_resource' and is_http2_grpc_and_differ:
                # 某些情况下同一股流量在不同位置可能会被 Agent 分别解析为 HTTP2 和 gRPC
                # 目前这两种协议的 request_resource 取自不同的协议字段，详见下面的文档：
                # https://deepflow.io/docs/zh/features/universal-map/l7-protocols/#http2
                # 于是，当一个协议是 HTTP2、另一个是 gRPC 时，不用比较这些差异字段
                continue

            if lhs_value != rhs_value:
                return True
        return False

    @classmethod
    def set_relate(cls,
                   trace_info: TraceInfo,
                   related_trace_infos: set,
                   related_map: defaultdict(inner_defaultdict_set),
                   network_delay_us: int,
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
            # network_delay_us 用于判断网络流两两之间的时差不应大于【一定值】，
            # 否则认为超出追踪范围，在后续逻辑中会无法加入 related_map 而被丢弃。
            # 注意：两个 Span 都是会话时，要求两侧 TCP Seq 必须都相等，即使有一侧 TCP Seq 为 0，
            #       例如 MySQL Close、RabbitMQ Connection.Blocked 等单向 SESSION 的场景。
            #       否则，只需要一侧 TCP Seq 相等即可。
            if trace_info.type == rti.type == L7_FLOW_TYPE_SESSION:  # req & resp
                if abs(trace_info.start_time_us -
                       rti.start_time_us) <= network_delay_us and abs(
                           trace_info.end_time_us -
                           rti.end_time_us) <= network_delay_us:
                    if trace_info.req_tcp_seq == rti.req_tcp_seq and trace_info.resp_tcp_seq == rti.resp_tcp_seq:
                        if not cls.flow_field_conflict(trace_info, rti):
                            related_map[trace_info._id][rti._id].add(
                                L7_FLOW_RELATIONSHIP_TCP_SEQ)
                            find_related = True
            elif trace_info.type != L7_FLOW_TYPE_RESPONSE and rti.type != L7_FLOW_TYPE_RESPONSE:  # req
                if abs(trace_info.start_time_us -
                       rti.start_time_us) <= network_delay_us:
                    if trace_info.req_tcp_seq == rti.req_tcp_seq:
                        if not cls.flow_field_conflict(trace_info, rti):
                            related_map[trace_info._id][rti._id].add(
                                L7_FLOW_RELATIONSHIP_TCP_SEQ)
                            find_related = True
            elif trace_info.type != L7_FLOW_TYPE_REQUEST and rti.type != L7_FLOW_TYPE_REQUEST:  # resp
                if abs(trace_info.end_time_us -
                       rti.end_time_us) <= network_delay_us:
                    if trace_info.resp_tcp_seq == rti.resp_tcp_seq:
                        if not cls.flow_field_conflict(trace_info, rti):
                            related_map[trace_info._id][rti._id].add(
                                L7_FLOW_RELATIONSHIP_TCP_SEQ)
                            find_related = True
            if fast_check and find_related: return
            # XXX: vtap_id 相同时应该能有更好的判断，例如 duration 大的 Span 时间范围必须覆盖 duration 小的 Span

        return find_related


class L7SyscallMeta:

    @classmethod
    def set_relate(cls,
                   trace_info: TraceInfo,
                   related_trace_infos: set,
                   related_map: defaultdict(inner_defaultdict_set),
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
            # syscall_trace_id_request
            if trace_info.syscall_trace_id_request:
                if trace_info.syscall_trace_id_request in [
                        rti.syscall_trace_id_request,
                        rti.syscall_trace_id_response
                ]:
                    related_map[trace_info._id][rti._id].add(
                        L7_FLOW_RELATIONSHIP_SYSCALL_TRACE_ID)
                    find_related = True
                    if fast_check: return True
                    continue
            # syscall_trace_id_response
            if trace_info.syscall_trace_id_response:
                if trace_info.syscall_trace_id_response in [
                        rti.syscall_trace_id_request,
                        rti.syscall_trace_id_response
                ]:
                    related_map[trace_info._id][rti._id].add(
                        L7_FLOW_RELATIONSHIP_SYSCALL_TRACE_ID)
                    find_related = True
                    if fast_check: return True
                    continue

        return find_related


class L7AppMeta:

    @classmethod
    def set_relate(cls,
                   trace_info: TraceInfo,
                   related_trace_infos: set,
                   related_map: defaultdict(inner_defaultdict_set),
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
                related_map[trace_info._id][rti._id].add(
                    L7_FLOW_RELATIONSHIP_SPAN_ID)
                find_related = True
                if fast_check: return True
                continue
            # parent_span_id
            if trace_info.parent_span_id:
                if trace_info.parent_span_id == rti.span_id:
                    related_map[trace_info._id][rti._id].add(
                        L7_FLOW_RELATIONSHIP_SPAN_ID)
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
        self.flows: list[dict] = []
        self.sys_flow_index: list[int] = []

    def append_network_flow(self, flow: dict):
        """
        将 net-span 与 sys-span 按 tcp_seq 分组
        """
        if not self.span_id and flow["span_id"]:
            self.span_id = flow["span_id"]
        self.flows.append(flow)
        if flow["signal_source"] == L7_FLOW_SIGNAL_SOURCE_EBPF:
            # 做个标记，方便更新 sys-flow 的 response_status
            self.sys_flow_index.append(len(self.flows) - 1)

    def unify_response_status(self):
        """
        更新 sys-flow 的 response_status
        """
        # 如果状态不一致，可能是子级发生异常，而父级收不到信息被标记为未知
        # response_status: {0: success}{2: unknown}{3: server error}{4: client error}
        max_response_status = max(
            self.flows, key=lambda x: x['response_status'])['response_status']
        # 更新 sys-span's response_status
        for i in self.sys_flow_index:
            self.flows[i]['response_status'] = max(
                self.flows[i]['response_status'], max_response_status)

    def set_parent_relation(self):
        """
        对组内 span 设置父子关系，执行此方法前需用 `sort_network_spans` 先排序
        """
        for i in range(1, len(self.flows), 1):
            if self.flows[i]['signal_source'] == self.flows[
                    i - 1]['signal_source'] == L7_FLOW_SIGNAL_SOURCE_EBPF:
                if self.flows[i][
                        "tap_side"] == TAP_SIDE_SERVER_PROCESS and self.flows[
                            i - 1]["tap_side"] == TAP_SIDE_CLIENT_PROCESS:
                    # 当顺序为 [c-p, s-p] 说明中间没有 net-span，构成父子关系
                    _set_parent(self.flows[i], self.flows[i - 1],
                                "trace mounted due to tcp_seq")
                else:
                    # 某些情况下，可能会有两个 SYS Span 拥有同样的 TCP Seq，此类情况一般是由于 eBPF 内核适配不完善导致。
                    # 例如：self.flows 数组中可能包含两个 c-p Span（拥有同样的 TCP Seq）、多个 net Span、一个 s-p Span，开头两个 c-p Span 实际上没有父子关系。
                    # 这里做一个简单的处理，当相邻两个 Span 都是 SYS Span 时不要按照 TCP Seq 来设置他们的 Parent 关系。
                    continue
            else:
                _set_parent(self.flows[i], self.flows[i - 1],
                            "trace mounted due to tcp_seq")

    def sort_network_spans(self):
        """
        对网络span进行排序，排序规则：
        1. 按照TAP_SIDE_RANKS进行排序
        2. 按采集器分组排序，与入口 span 同一个采集器的前移，出口 span 同一个采集器的后移，组内按 start_time 排序
        """
        # 先根据 tap_side 排序，方便找 client-side 和 server-side span
        sorted_traces = sorted(
            self.flows,
            key=lambda x:
            (const.TAP_SIDE_RANKS.get(x['tap_side']), x['tap_side']))

        # 获取入口 agent，顺序向后扫，找遇到的第一个 c-span
        ingress_agent = ''
        for i in range(len(sorted_traces)):
            if sorted_traces[i]['tap_side'] in (
                    const.TAP_SIDE_CLIENT_PROCESS, const.TAP_SIDE_CLIENT_NIC,
                    const.TAP_SIDE_CLIENT_POD_NODE):
                ingress_agent = sorted_traces[i]['vtap_id']
                break

        # 获取出口 agent，逆序向前扫，找遇到的第一个 s-span（也就是最后一个 child）
        egress_agent = ''
        for i in range(len(sorted_traces) - 1, -1, -1):
            if sorted_traces[i]['tap_side'] in (
                    const.TAP_SIDE_SERVER_PROCESS, const.TAP_SIDE_SERVER_NIC,
                    const.TAP_SIDE_SERVER_POD_NODE):
                egress_agent = sorted_traces[i]['vtap_id']
                break

        for i in range(len(sorted_traces)):
            if sorted_traces[i]['vtap_id'] == ingress_agent:
                sorted_traces[i]['agent_rank'] = 0
            elif sorted_traces[i]['vtap_id'] == egress_agent:
                sorted_traces[i]['agent_rank'] = 2
            else:
                sorted_traces[i]['agent_rank'] = 1

        sorted_traces = sorted(sorted_traces,
                               key=lambda x: (x['agent_rank'], x['vtap_id'], x[
                                   'start_time_us'], -x['end_time_us']))

        # 当 ingress_agent=egress_agent 时
        # 如果中间穿过了其他节点数据，需要将所有 server-side span 排序到末尾
        if ingress_agent == egress_agent:
            first_serverside_index = -1
            for i in range(len(sorted_traces)):
                if sorted_traces[i]['tap_side'] in (
                        const.TAP_SIDE_SERVER_GATEWAY,
                        const.TAP_SIDE_SERVER_GATEWAY_HAPERVISOR,
                        const.TAP_SIDE_SERVER_HYPERVISOR,
                        const.TAP_SIDE_SERVER_POD_NODE,
                        const.TAP_SIDE_SERVER_NIC,
                        const.TAP_SIDE_SERVER_PROCESS):
                    first_serverside_index = i
                    break

            diff_agent_index = -1
            for i in range(first_serverside_index, len(sorted_traces)):
                if sorted_traces[i]['agent_rank'] != 0:
                    diff_agent_index = i
                    break

            if diff_agent_index > 0:
                sorted_traces = sorted_traces[:first_serverside_index] + sorted_traces[
                    diff_agent_index:] + sorted_traces[
                        first_serverside_index:diff_agent_index]

        self.flows = sorted_traces


class SpanNode:

    def __init__(self, flow: dict):
        self.flow: dict = flow
        self.signal_source: int = -1  # overwrite by Child Class
        self.parent: SpanNode = None

    def append_child(self, child, mounted_info: str = None):
        # child is typeof(SpanNode)
        child.parent = self
        _set_parent(child.flow, self.flow, mounted_info)

    def iterate_childs(self, spans: list) -> tuple[list, list]:
        source: list[SpanNode] = spans[:]
        stack: list[SpanNode] = [self]
        childs: list[SpanNode] = [self]  # including self & self's childs
        while stack:
            node = stack.pop()
            for span in source:
                if span.parent == node:
                    childs.append(span)
                    stack.append(span)
        source = [span for span in source if span not in childs]
        return childs, source

    def get_tap_side(self) -> str:
        return self.flow.get('tap_side', '')

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


class AppSpanNode(SpanNode):

    def __init__(self, flow_info: dict):
        super().__init__(flow_info)
        self.signal_source = L7_FLOW_SIGNAL_SOURCE_OTEL


class SysCallSpanNode(SpanNode):

    def __init__(self, flow_info: dict):
        super().__init__(flow_info)
        self.signal_source = L7_FLOW_SIGNAL_SOURCE_EBPF


class ProcessSpanSet:
    """
    一个 ProcessSpanSet 由如下 Span 组成：
    - 零个或一个 s-p SysSpan
    - 零个或多个 s-app、app、c-app，他们之间根据 span_id 和 parent_span_id 关系形成一棵树
    - 且树根的 parent_span_id 指向 s-p 的 span_id
    - 当 s-p 没有 span_id 时，AppSpan 的叶子 Span 指向 c-p，c-p 和 s-p 构成应用同一个线程的 Syscall
    """

    def __init__(self, group_index: str):
        self.group_index = group_index
        # 构建一个以列表形式访问 span 的树结构
        self.spans: list[SpanNode] = []
        # app_span_trees，用于存放 app-span 的树结构
        self.app_span_roots: list[SpanNode] = None
        self.leaf_syscall_trace_id_request: set[int] = set[int]()
        self.leaf_syscall_trace_id_response: set[int] = set[int]()
        # 用于显示调用拓扑使用
        self.subnet_id = None
        self.subnet = None
        # 用于关联 event
        self.process_id = None
        self.process_kname = None
        # 用于聚合包含 sys-span 的服务的时延
        self.auto_service = None  # 在结果集中作为 service_uname
        self.auto_service_id = None  # 在结果集中作为 service_uid
        self.ip = None  # service_uname 的第二优先级
        self.auto_service_type = None
        # 当只有 app-span 数据时，避免被剪枝，记录 app_service
        self.app_service = None

    def __set_app_service(self, span: SpanNode):
        if self.app_service is None:
            self.app_service = span.flow.get('app_service', None)

    def __set_value_for_sys_span(self, span: SpanNode):
        """
        此方法统一 sys-span 的统计字段并为 flow 生成一个无方向的 key
        `pruning_trace` 剪枝之后，需要根据剩下的 trace 按 auto_service 分组统计时延消耗
        为了避免同一进程的 sys-span 分组统计错误，这里统一校准字段
        """
        span_tap_side = span.get_tap_side()
        for key in [
                'subnet_id',
                'subnet',
                'ip',
                'process_kname',
                'process_id',
        ]:
            direction_key = f'{key}_0' if span_tap_side == TAP_SIDE_CLIENT_PROCESS else f'{key}_1'
            if getattr(self, key):
                span.flow[key] = getattr(self, key)
            else:
                setattr(self, key, span.flow[direction_key])
                span.flow[key] = span.flow[direction_key]

        # for auto_service_xx
        for key in [
                'auto_service_id',
                'auto_service',
                'auto_service_type',
        ]:
            direction_key = f'{key}_0' if span_tap_side == TAP_SIDE_CLIENT_PROCESS else f'{key}_1'
            if getattr(self, key):
                if self.auto_service_type in [
                        IP_AUTO_SERVICE, INTERNET_IP_AUTO_SERVICE
                ]:
                    setattr(self, key, span.flow[direction_key])
                span.flow[key] = getattr(self, key)
            else:
                setattr(self, key, span.flow[direction_key])
                span.flow[key] = span.flow[direction_key]

    def append_app_span(self, app_flow: dict) -> SpanNode:
        app_flow['process_span_set'] = self
        span_node = AppSpanNode(app_flow)
        self.spans.append(span_node)
        self.__set_app_service(span_node)
        return span_node

    def append_sys_span(self, sys_flow: dict, tap_side: str) -> SpanNode:
        sys_flow['process_span_set'] = self
        span_node = SysCallSpanNode(sys_flow)
        self.spans.append(span_node)
        if tap_side == TAP_SIDE_CLIENT_PROCESS:
            self.leaf_syscall_trace_id_request.add(
                span_node.get_syscall_trace_id_request())
            self.leaf_syscall_trace_id_response.add(
                span_node.get_syscall_trace_id_response())
        self.__set_value_for_sys_span(span_node)
        return span_node

    def get_app_span_roots(self) -> list[SpanNode]:
        return self.app_span_roots

    def get_roots(self) -> list[SpanNode]:
        return [span for span in self.spans if span.parent is None]

    def get_leafs(self, roots: list[SpanNode]) -> list[SpanNode]:
        queue: list[SpanNode] = self.spans[:]
        stack: list[SpanNode] = roots[:]
        leafs: list[SpanNode] = []
        while stack:
            node = stack.pop()
            child_count = 0
            for span in queue:
                if span.parent == node:
                    stack.append(span)
                    child_count += 1
            if child_count == 0:
                leafs.append(node)
        return leafs

    def __build_app_span_tree(self):
        queue: list[SpanNode] = self.spans[:]
        while queue:
            node = queue.pop(0)
            if node.signal_source != L7_FLOW_SIGNAL_SOURCE_OTEL:
                continue
            for app_span in self.spans:
                if app_span.signal_source != L7_FLOW_SIGNAL_SOURCE_OTEL:
                    continue
                if app_span.get_parent_id() > 0:
                    continue
                if app_span.get_parent_span_id() == node.get_span_id():
                    node.append_child(
                        app_span, "app-span mounted due to parent_span_id")
                    queue.append(app_span)

    # return: list[ProcessSpanSet]
    def split_to_multiple_process_span_set(self) -> list:
        # 先构建树、app-span 内部的父子关系，确认 app-span 的结构
        self.__build_app_span_tree()

        # 构建一个 root 列表，以检测是否存在多个 root
        app_span_roots = [
            span for span in self.spans if span.get_parent_id() == -1
            and span.signal_source == L7_FLOW_SIGNAL_SOURCE_OTEL
        ]
        unique_root_parent_id = set(span.get_parent_span_id()
                                    for span in app_span_roots)

        # 出现多个 root，则分裂为多个 ProcessSpanSet
        if len(unique_root_parent_id) > 1:
            # 复制一份 spans 用于寻找 root 的 child，每执行一次 iterate_childs 都会减少数据，减少重复遍历
            left_spans = self.spans[:]
            # 分裂过程中，同一个 parent_span_id 的 app-span root 仍然要放到同一个 ProcessSpanSet 中
            split_result: dict[str, ProcessSpanSet] = {}
            for root in app_span_roots:
                if root.get_parent_span_id() not in split_result:
                    newSet = ProcessSpanSet(root.get_parent_span_id())
                    newSet.app_service = self.app_service
                    newSet.app_span_roots = [root]
                    newSet.spans, left_spans = root.iterate_childs(left_spans)
                    split_result[root.get_parent_span_id()] = newSet
                else:
                    split_result[
                        root.get_parent_span_id()].app_span_roots.append(root)
                    childs, left_spans = root.iterate_childs(left_spans)
                    split_result[root.get_parent_span_id()].spans.extend(
                        childs)
            return split_result.values()
        else:
            root_parent_id = unique_root_parent_id.pop()
            # 如果 parent_span_id 为空说明这里是入口，即 root
            # 极端情况下可能会有多个 root，这里没法分辨 app-span 多个 root 的关系，不做拆分
            if root_parent_id == '':
                root_parent_id = "root"  # 只是标记 group_index，没有实际作用
            self.group_index = root_parent_id
            self.app_span_roots = app_span_roots
            # spans 不需要再 append 一次，保留原 span list
            return [self]

    def app_attach_syscall(self, syscall: dict, tap_side: str,
                           roots: list[SpanNode],
                           leafs: list[SpanNode]) -> bool:
        '''
        将 sys_span 按规则附加到 app_span 的头/尾:
        s-p: 按 app_span.parent_span_id = sys_span.span_id, 作为 app_span 的 parent
        c-p: 按 app_span.span_id = sys_span.span_id, 作为 app_span 的 child
        '''
        if tap_side == TAP_SIDE_SERVER_PROCESS:
            return self.__attach_service_process(syscall, tap_side, roots)
        elif tap_side == TAP_SIDE_CLIENT_PROCESS:
            return self.__attach_client_process(syscall, tap_side, leafs)

    def __attach_service_process(self, syscall: dict, tap_side: str,
                                 app_span_roots: list[SpanNode]) -> bool:
        syscall_span_id = syscall['span_id']
        for app_root in app_span_roots:
            if syscall_span_id and syscall_span_id == app_root.get_parent_span_id() \
                and app_root.get_parent_id() < 0:
                # 如果 span_id 匹配成功，s-p 作为 app-span 的 parent
                sp_span_node = self.append_sys_span(syscall, tap_side)
                sp_span_node.append_child(
                    app_root,
                    "s-p sys_span mounted due to same span_id as parent")
                return True
            elif not syscall_span_id and (
                    syscall['syscall_trace_id_request'] in self.leaf_syscall_trace_id_request \
                    or syscall['syscall_trace_id_response'] in self.leaf_syscall_trace_id_response) \
                    and app_root.get_parent_id() < 0:
                # and syscall['start_time_us'] < app_root.get_start_time_us() \
                # and syscall['end_time_us'] > app_root.get_end_time_us() \
                # 如果 span_id 不存在，说明可能是入口 span，上游没有注入 span_id，此时根据叶子节点 c-p 的 syscall_trace_id 匹配即可
                # 这里匹配可以严格点，s-p 和 c-p 只会同侧(req-req / res-res)相等，避免误关联一个独立的 c-p
                sp_span_node = self.append_sys_span(syscall, tap_side)
                sp_span_node.append_child(
                    app_root,
                    "s-p sys_span mounted due to syscall_trace_id matched c-p")
                return True
        return False

    def __attach_client_process(self, syscall: dict, tap_side: str,
                                app_span_leafs: list[SpanNode]) -> bool:
        syscall_span_id = syscall['span_id']
        for app_leaf in app_span_leafs:
            if syscall_span_id and syscall_span_id == app_leaf.get_span_id():
                # app_span 作为 sys_span 的 parent
                cp_span_node = self.append_sys_span(syscall, tap_side)
                app_leaf.append_child(
                    cp_span_node,
                    "c-p sys_span mounted due to same span_id as child")
                return True
        return False

    def try_attach_client_syscall(self, client_sys_flow: dict,
                                  client_tap_side: str) -> bool:
        '''
        检查 client_sys_span 是否能被加入本 ProcessSpanSet 中
        如果 self 有 s-p: s-p 时间必须覆盖 c-p ，且通过 syscall_trace_id 或 x_request_id 关联
        如果 self 只有 c-p: 如果能通过 syscall_trace_id 关联，允许追加，但不能设置父子关系，仅仅是兄弟关系
        '''
        only_contains_cp = True
        for span in self.spans:
            if span.signal_source == L7_FLOW_SIGNAL_SOURCE_EBPF:
                if span.get_tap_side() == TAP_SIDE_SERVER_PROCESS:
                    only_contains_cp = False
                    # 做个防错，避免 auto_instance 匹配到 host 但实际进程不同的情况
                    if span.flow['vtap_id'] != client_sys_flow['vtap_id'] \
                        or _get_process_id(span.flow, TAP_SIDE_SERVER_PROCESS) != _get_process_id(client_sys_flow, client_tap_side):
                        return False

                    if span.flow['start_time_us'] > client_sys_flow['start_time_us'] \
                        or span.flow['end_time_us'] < client_sys_flow['end_time_us']:
                        # 不落入时间范围，由于一个 ProcessSpanSet 内只有 0/1 个 s-p，所以直接返回
                        return False
                    else:
                        # syscall_trace_id 判断
                        # 对 s-p 与 c-p，只能同侧相等（s-p 接收请求后作为 c-p 发出请求）/（c-p 接收响应后作为 s-p 回应请求）
                        syscall_match = span.get_syscall_trace_id_request() == client_sys_flow['syscall_trace_id_request'] \
                            or span.get_syscall_trace_id_response() == client_sys_flow['syscall_trace_id_response']

                        # 对 c-p 与 c-p 之间，只能异侧相等（一个 c-p 接收响应后在同一线程发出另一个请求）
                        # 这种情况下，尝试匹配 s-p 下的所有叶子节点 c-p 的 syscall_trace_id
                        # 这里包含了兄弟 c-p 的关联关系
                        client_syscall_match = client_sys_flow['syscall_trace_id_request'] in self.leaf_syscall_trace_id_response \
                            or client_sys_flow['syscall_trace_id_response'] in self.leaf_syscall_trace_id_request

                        # x_request_id 判断
                        # s-p.x_req_id_1 = c-p.x_req_id_0: 注入 x_req_id
                        # s-p.x_req_id_1 = c-p.x_req_id_1: 透传 x_req_id (x_req_id_0 同理)
                        x_request_id_match = span.get_x_request_id_1() and \
                            (span.get_x_request_id_1() == client_sys_flow['x_request_id_1'] \
                            or span.get_x_request_id_0() == client_sys_flow['x_request_id_0'] \
                            or span.get_x_request_id_1() == client_sys_flow['x_request_id_0'])

                        mounted_info = ""
                        if syscall_match:
                            mounted_info = "syscall_trace_id matched to s-p root"
                        elif x_request_id_match:
                            mounted_info = "x_request_id matched to s-p root"
                        elif client_syscall_match:
                            mounted_info = "syscall_trace_id matched to c-p child"

                        if syscall_match or x_request_id_match or client_syscall_match:
                            # 任意一个条件满足，直接追加
                            cp_span_node = self.append_sys_span(
                                client_sys_flow, client_tap_side)
                            span.append_child(
                                cp_span_node,
                                f"c-p sys-span mounted due to {mounted_info}")
                            return True
        # end of s-p match

        if only_contains_cp:
            if client_sys_flow['syscall_trace_id_request'] in self.leaf_syscall_trace_id_response \
                or client_sys_flow['syscall_trace_id_response'] in self.leaf_syscall_trace_id_request:
                cp_span_node = self.append_sys_span(client_sys_flow,
                                                    client_tap_side)
                return True

        return False


def _get_auto_instance(flow: dict, tap_side: str) -> str:
    server_side_key = 'auto_instance_id_1'
    client_side_key = 'auto_instance_id_0'
    # 对 x-app 位置的 flow，有可能 auto_instance_id=0，说明是外部资源
    # 外部资源不要分到同一组，改为使用 auto_instance （显示为 IP）分组
    if tap_side == TAP_SIDE_SERVER_APP:
        return flow[server_side_key] if flow[server_side_key] else flow[
            'auto_instance_1']
    elif tap_side == TAP_SIDE_CLIENT_APP:
        return flow[client_side_key] if flow[client_side_key] else flow[
            'auto_instance_0']
    # 对 x-p 位置的 flow 一定能获取到 auto_instance_id
    elif tap_side == TAP_SIDE_SERVER_PROCESS:
        return flow[server_side_key]
    elif tap_side == TAP_SIDE_CLIENT_PROCESS:
        return flow[client_side_key]
    elif tap_side == TAP_SIDE_APP:
        auto_instance = flow[server_side_key] if flow[
            server_side_key] else flow['auto_instance_1']
        if not auto_instance:
            return flow[client_side_key] if flow[client_side_key] else flow[
                'auto_instance_0']
        return auto_instance


def _get_process_id(flow: dict, tap_side: str) -> str:
    if tap_side == TAP_SIDE_SERVER_PROCESS:
        return flow['process_id_1']
    elif tap_side == TAP_SIDE_CLIENT_PROCESS:
        return flow['process_id_0']


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
    """
    # flows 是按照时间顺序从小到大插入的，因此合并过程中只可能出现 RESPONSE 合并到 REQUEST 或 SESSION 中的情况，
    # 而且其中 RESPONSE 合并到 SESSION 的情况只出现在 is_dns_sys_span 的场景。
    if flow['type'] != L7_FLOW_TYPE_RESPONSE:
        return False

    # for special case: DNS sys span
    is_sys_span = flow['tap_side'] in [
        TAP_SIDE_SERVER_PROCESS, TAP_SIDE_CLIENT_PROCESS
    ]
    is_dns_sys_span = flow['l7_protocol'] == L7_PROTOCOL_DNS and is_sys_span

    # 当存在 request_id 时，一般意味着同一个 L4 Flow 中的请求是并发的（不会等待响应返回就发下一个请求）
    # 但有一个特殊是 MySQL，参考：https://deepflow.io/docs/zh/features/universal-map/l7-protocols/#mysql
    need_compare_request_id = flow['request_id'] and flow[
        'l7_protocol'] != L7_PROTOCOL_MYSQL

    for i in range(len(flows) - 1, -1, -1):
        if not is_dns_sys_span:  # 仅需要合并至 REQUEST
            if flows[i]['type'] != L7_FLOW_TYPE_REQUEST:
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

        if flows[i]['l7_protocol'] != flow['l7_protocol']:
            # 一个 L4 Flow 中的前序 flow 是异种协议时，暂不考虑合并，避免误匹配
            # 可能出现多种协议的情况：HTTP2 和 gRPC、TLS 和应用协议、Service Mesh Sidecar 所有流量
            return False

        if need_compare_request_id:
            # request_id 匹配成功即可合并，下面主要排除一些（不可能发生）的异常场景
            if not is_dns_sys_span and flows[i]['type'] != L7_FLOW_TYPE_REQUEST:
                # 前序 flow 不是 REQUEST：不可合并，并停止合并以避免误匹配
                return False
        else:
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
        flows[i]['end_time_us'] = flow['end_time_us']
        flows[i]['response_duration'] = flows[i]['end_time_us'] - flows[i][
            'start_time_us']
        flows[i]['resp_tcp_seq'] = flow['resp_tcp_seq']
        flows[i]['syscall_cap_seq_1'] = flow['syscall_cap_seq_1']
        return True

    return False


def sort_all_flows(dataframe_flows: DataFrame, network_delay_us: int,
                   return_fields: list, ntp_delay_us: int) -> list:
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
        flows.append(flow)
    # 注意：不要对 flows 再做排序，下面的代码会通过 flows[flow_index] 来反查 flow

    # flow 合并之后，添加一个 selftime，后续要用到
    # XXX: 这个字段应该不用添加，考虑直接使用 response_duration
    for flow in flows:
        flow['selftime'] = flow['response_duration']

    # 对合并后的 flow 计算 related_flow_index_map，用于后续操作的加速
    related_flow_index_map = defaultdict(inner_defaultdict_set)
    trace_infos = TraceInfo.construct_from_dict_list(flows)
    set_all_relate(trace_infos, related_flow_index_map,
                   network_delay_us)  # XXX: slow function
    # 构建一个 flow._index 到 flow._id(s) 的映射，方便后续 related_flow_index_map 的使用
    flow_index_to_id0 = [0] * len(flows)
    for flow in flows:
        flow_index_to_id0[flow['_index']] = flow['_id'][0]

    network_flows = []
    app_flows = []
    syscall_flows = []
    # 对 flow 分类，而后分别做排序，方便做层级处理
    # 对 network_flows: net-span 的排序按固定的顺序（TAP_SIDE_RANKS），然后根据 span_id 挂 app-span，根据 tcp_seq 挂 sys-span
    # 对 app_flows: app-span 按固定的规则设置层级（span_id/parent_span_id），按 span_id 挂 sys-span 以及挂到 sys-span 构建的 <service> 上
    # 对 syscall_flows: sys-span 需要提取<vtap_id, local_process_id>分组定义为<service> ，并以此为主体构建火焰图骨架
    for flow in flows:
        if flow['signal_source'] == L7_FLOW_SIGNAL_SOURCE_EBPF:
            syscall_flows.append(flow)
        elif flow['signal_source'] == L7_FLOW_SIGNAL_SOURCE_PACKET:
            network_flows.append(flow)
        elif flow['signal_source'] == L7_FLOW_SIGNAL_SOURCE_OTEL:
            app_flows.append(flow)

    # 构建 Process Span Set
    # 对 app_span 按 auto_instance_id/auto_instance 进行分组
    process_span_map: dict[str, list[ProcessSpanSet]] = defaultdict(
        list[ProcessSpanSet])
    for flow in app_flows:
        auto_instance = _get_auto_instance(flow, flow['tap_side'])
        if auto_instance not in process_span_map:
            sp_span_pss = ProcessSpanSet(auto_instance)
            process_span_map[auto_instance] = [sp_span_pss]
        process_span_map[auto_instance][0].append_app_span(flow)

    # 一个 app-span 构成的 ProcessSpanSet 可能会有多个 root
    # 如果这些 root 有同一个 parent_span_id: 说明只是还没关联 s-p 作为 parent，不需处理，后续逻辑会关联
    # 如果这些 root 有不同的 parent_span_id: 说明这个服务被穿越了多次，要拆分为多个 ProcessSpanSet
    for key, process_span_set_list in process_span_map.items():
        split_process_span_set: list[ProcessSpanSet] = []
        for sp_span_pss in process_span_set_list:
            split_result = sp_span_pss.split_to_multiple_process_span_set()
            split_process_span_set.extend(split_result)
        process_span_map[key] = split_process_span_set

    # s-p 按两种方式挂：同一 span_id 关联或 span_id 等于空但 s-p 与 c-p 有 syscall_trace_id 关联
    # [x['tap_side'] != TAP_SIDE_CLIENT_PROCESS] 排序确定先挂 c-p 再挂 s-p，当无法找到 s-p 的 span_id 时，根据 c-p 的 syscall_trace_id 关联，确保 s-p 一定会关联上
    # start_time_us 降序是为了让`left_syscall_flows`少做一次排序，不影响这里的 attach
    syscall_flows = sorted(
        syscall_flows,
        key=lambda x:
        (x['tap_side'] != TAP_SIDE_CLIENT_PROCESS, -x['start_time_us']))
    # 如果没有 app-span 时，不要做无效扫描
    if len(process_span_map) > 0:
        # 临时变量，用于查找一个 `parent_span_id` 对应的所有叶子节点
        leafs_map: dict[str, list[SpanNode]] = {}
        for flow in syscall_flows:
            if flow.get('process_span_set', None) is not None:
                continue
            # 多次用到 tap_side，提前获取减少访问
            flow_tap_side = flow['tap_side']
            auto_instance = _get_auto_instance(flow, flow_tap_side)
            if auto_instance in process_span_map:
                for sp_span_pss in process_span_map[auto_instance]:
                    app_span_tree_roots = sp_span_pss.get_app_span_roots()
                    if sp_span_pss.group_index not in leafs_map.keys():
                        # 提前获取叶子节点，确保叶子节点都是 app-span
                        leafs = sp_span_pss.get_leafs(app_span_tree_roots)
                        leafs_map[sp_span_pss.group_index] = leafs
                    leafs = leafs_map[sp_span_pss.group_index]
                    if not sp_span_pss.app_attach_syscall(
                            flow, flow_tap_side, app_span_tree_roots, leafs):
                        # 这里 attach 失败，但可能关联关系在同一进程其他的 app_span 内，继续尝试
                        continue

    # 剩余的 sys_span 单独成 process_span_set
    # 如果本次追踪没有 app_span，这里应是全部 syscall_flows
    # 按 s-p/c-p 的顺序执行扫描，确保先通过 s-p 建立 process_span_set，再往上挂 c-p
    # 由于上面已经排序过按c-p/s-p 顺序加start_time_us 降序，这里直接反序即可
    # 这里要求 start_time_us 升序，是因为有如下场景：
    # 当 s-p 内发起多个 c-p 请求，c-p 构成兄弟关系，此时 s-p 只和头尾两个 c-p 有 syscall_trace_id 关联（最坏情况下无关联，只能通过 app-span 关联）
    # 如果先扫描中间的 c-p，再扫描头尾，会导致中间的 c-p 无法关联，所以这里 start_time_us 升序确保头 c-p 先被关联，再让头 c-p 关联出它的兄弟 c-p
    left_syscall_flows = [
        flow for flow in syscall_flows
        if flow.get('process_span_set', None) is None
    ]
    left_syscall_flows.reverse()
    # 标记同一进程的 s-p 数量，同一个 process_span_set 内只允许存在最多一个 s-p
    same_process_sp: dict[str, int] = dict.fromkeys(process_span_map.keys(), 1)
    for flow in left_syscall_flows:
        if flow.get('process_span_set', None) is not None:
            continue
        flow_tap_side = flow['tap_side']
        # 使用 auto_instance 标记同一进程，用于在第一轮`app_attach_syscall`时没有 attach 到的 c-p 匹配同一进程的 s-p
        auto_instance = _get_auto_instance(flow, flow_tap_side)
        if flow_tap_side == TAP_SIDE_SERVER_PROCESS:
            if auto_instance not in process_span_map:
                sp_span_pss = ProcessSpanSet(auto_instance)
                sp_span_pss.append_sys_span(flow, flow_tap_side)
                process_span_map[auto_instance] = [sp_span_pss]
                same_process_sp[auto_instance] = 1
            else:
                # s-p 在每个 ProcessSpanSet 中如果大于1个，说明这个进程被穿越多次，需要单独构建一个 ProcessSpanSet
                index = same_process_sp[auto_instance] + 1
                sp_span_pss = ProcessSpanSet(f'{auto_instance}-{index}')
                sp_span_pss.append_sys_span(flow, flow_tap_side)
                process_span_map[auto_instance].append(sp_span_pss)
                same_process_sp[auto_instance] = index
        elif flow_tap_side == TAP_SIDE_CLIENT_PROCESS:
            cp_matched_sp = False
            # 这里可以认为所有 s-p 已经构建了 ProcessSpanSet
            if auto_instance in process_span_map:
                # 检查 c-p 是否在同一进程的 s-p 覆盖范围内，若不在，它应是独立的 ProcessSpanSet
                # 若 ProcessSpanSet 内仅有 c-p，也会尝试添加 c-p
                for sp_process_span_set in process_span_map[auto_instance]:
                    if sp_process_span_set.try_attach_client_syscall(
                            flow, flow_tap_side):
                        cp_matched_sp = True
                        break
            if auto_instance not in process_span_map:
                # 如果找不到 key，说明没有 s-p，c-p 应作为独立的 ProcessSpanSet
                cp_span_pss = ProcessSpanSet(auto_instance)
                cp_span_pss.append_sys_span(flow, flow_tap_side)
                process_span_map[auto_instance] = [cp_span_pss]
                same_process_sp[auto_instance] = 1
            elif not cp_matched_sp:
                # 这里 cp_matched_sp False 可能包含两种情况：
                # 1. c-p 不在同一个进程的 s-p 时间范围内，或无关联关系
                # 2. c-p 同进程的 ProcessSpanSet 内无 s-p，且无法与 c-p 匹配为兄弟
                # 这两种情况都作为一个独立的 ProcessSpanSet
                index = same_process_sp[auto_instance] + 1
                cp_span_pss = ProcessSpanSet(f'{auto_instance}-{index}')
                cp_span_pss.append_sys_span(flow, flow_tap_side)
                process_span_map[auto_instance].append(cp_span_pss)
                same_process_sp[auto_instance] = index

    # 构建 Network Span Set，每个 Network Span Set 里包含具有同一组 tcp_seq 的 net-span & sys-span
    # 有两个作用：1. 将 net-span 按 tcp_seq 分组，2. 提前找到与 net-span 关联的 sys-span
    networks: list[NetworkSpanSet] = []
    network_flows = sorted(network_flows + syscall_flows,
                           key=lambda x: x.get("type"),
                           reverse=True)
    flow_aggregated = set()  # set(flow._index)
    for flow in network_flows:
        if flow['_index'] in flow_aggregated:
            continue
        # construct a network
        network = NetworkSpanSet()
        networks.append(network)
        # aggregate self to this network
        network.append_network_flow(flow)
        flow_aggregated.add(flow['_index'])
        # aggregate other spans to this network
        for _index, related_types in related_flow_index_map[
                flow['_index']].items():
            if L7_FLOW_RELATIONSHIP_TCP_SEQ not in related_types:
                continue
            if _index in flow_aggregated:
                continue
            network.append_network_flow(flows[_index])
            flow_aggregated.add(_index)

    ## 排序

    ### 网络span排序
    # 网络 span 按照 tap_side_rank 排序，顺序始终为：c -> 其他 -> s，并按采集器分组排序，同一采集器内按 start_time 排序
    for network in networks:
        network.sort_network_spans()
        network.set_parent_relation()
        network.unify_response_status()

    ### Process Span Set 分离
    process_span_list: list[ProcessSpanSet] = [
        pss for _, process_span_sets in process_span_map.items()
        for pss in process_span_sets
    ]

    ### 连接 process span set 与 network span set
    ### 注意这里连接顺序按如下优先级连接：
    ### 1. process <-> net, 2. process <-> process 3. net <-> net

    ### 准备数据，从所有 process 和 network 中获取 root 和 leaf
    process_root_list = [pss.get_roots()
                         for pss in process_span_list]  # list of list
    process_roots = [item for roots in process_root_list
                     for item in roots]  # flat list
    process_leafs = [
        item for i in range(len(process_span_list))
        for item in process_span_list[i].get_leafs(process_root_list[i])
    ]

    network_leafs = [network.flows[-1] for network in networks]
    network_roots = [network.flows[0] for network in networks]

    #### 1. process span set 的 leaf 作为 network span set root 的 parent
    for ps_parent in process_leafs:
        # 避免子循环多次访问字典
        ps_index = ps_parent.get_flow_index()
        ps_span_id = ps_parent.get_span_id()
        for net_child in network_roots:
            if net_child.get('parent_id', -1) >= 0:
                continue
            if ps_index == net_child['_index']:
                # 共享一个 c-p, net_child parent == ps_parent 的 parent
                continue
            elif ps_span_id and ps_span_id == net_child['span_id']:
                # net_child 一定是 net-span 且没有 c-p, ps_parent 一定是 app-span，共享一个 span_id，则 ps_parent 是 parent
                _set_parent(net_child, ps_parent.flow,
                            "net-span mounted due to same span_id")

    #### 2. network span 的 leaf 作为 process span set root 的 parent
    for ps_child in process_roots:
        if ps_child.flow.get('parent_id', -1) >= 0:
            continue
        ps_index = ps_child.get_flow_index()
        ps_span_id = ps_child.get_span_id()
        for net_parent in network_leafs:
            if ps_index == net_parent['_index']:
                # 共享一个 s-p，则 ps_child 的 parent == net_parent 的 parent
                continue
            elif ps_span_id and ps_span_id == net_parent['span_id']:
                # ps_child 一定是 app-span 且没有 s-p, net_parent 一定是 net-span 且没有 s-p，则 net_parent 是 parent
                _set_parent(
                    ps_child.flow, net_parent,
                    f"{ps_child.get_tap_side()} mounted due to same span_id")

    #### 3. process span set 互相连接
    for ps_child in process_roots:
        if ps_child.flow.get('parent_id', -1) >= 0:
            continue
        ps_child_index = ps_child.get_flow_index()
        ps_child_span_id = ps_child.get_span_id()
        for ps_parent in process_leafs:
            if ps_child_index == ps_parent.get_flow_index():
                # 共享一个 c-p，则 ps_child 的 parent == ps_parent 的 parent
                continue
            elif ps_child_span_id and ps_child_span_id == ps_parent.get_span_id(
            ):
                # ps_child 可能是 app-span/s-p，ps_leaf 一定是 app-span，都没有 c-p, 共享一个 span_id
                _set_parent(
                    ps_child.flow, ps_parent.flow,
                    f"{ps_child.get_tap_side()} mounted due to same span_id")

    #### 4. network span set 互相连接
    #### relations: child.x_request_id_0 == parent.x_request_id_1/child.span_id = parent.span_id
    network_match_parent: dict[int, int] = {}
    for net_child in network_roots:
        if net_child.get('parent_id', -1) >= 0:
            continue
        net_child_index = net_child['_index']
        net_child_span_id = net_child['span_id']
        net_child_req_tcp_seq = net_child['req_tcp_seq']
        net_child_resp_tcp_seq = net_child['resp_tcp_seq']
        net_child_x_request_id_0 = net_child['x_request_id_0']
        net_child_x_request_id_1 = net_child['x_request_id_1']
        net_child_response_duration = net_child['response_duration']
        for net_parent in network_leafs:
            # 避免同一个 tcp_seq 组内首尾相连
            if net_parent['req_tcp_seq'] == net_child_req_tcp_seq \
                or net_parent['resp_tcp_seq'] == net_child_resp_tcp_seq:
                continue
            if net_child_x_request_id_0 and net_child_x_request_id_0 == net_parent[
                    'x_request_id_1']:
                # 网关注入 x_request_id 的场景
                # FIXME: 生成一个 pseudo net span，待前端修改后再开放此代码，注意处理时延计算
                # fake_pss = _generate_pseudo_process_span_set(
                #     net_child, net_parent)
                # process_span_list.append(fake_pss)
                # flows.extend(fake_pss.spans)
                _set_parent(
                    net_child, net_parent,
                    "net-span mounted due to x_request_id_0 match to x_request_id_1"
                )
            elif (net_child_x_request_id_0 and net_child_x_request_id_0 == net_parent['x_request_id_0']) \
                    or (net_child_x_request_id_1 and net_child_x_request_id_1 == net_parent['x_request_id_1']) \
                    or (net_child_span_id and net_child_span_id == net_parent['span_id']):
                # 网关透传 x_request_id 或透传 http header 中的 span_id
                # 要求 parent 的所有 response_duration > child 最大的 response_duration
                # 由于一个 net-span 内是按 c 端 agent 在前+start_time 排序的，可以认为 net_child(root) 就是一组内时延最大的
                if net_parent[
                        'response_duration'] < net_child_response_duration:
                    continue
                else:
                    # 这里不要直接设置 parent，如果找到了时延+id 满足条件的情况，都加入列表待处理
                    if net_child_index not in network_match_parent:
                        network_match_parent[net_child_index] = net_parent[
                            '_index']
                    else:
                        # 根据 `时延最接近` 原则找 parent
                        # 即在满足条件的 parent 里找到时延最接近最小的 net_parent，它更有可能是直接的 `上一跳`
                        # network_match_parent[net_child_index] 指向 net_parent 的 _index，从 flows 中取 response_duration
                        if flows[network_match_parent[net_child_index]][
                                'response_duration'] > net_parent[
                                    'response_duration']:
                            network_match_parent[net_child_index] = net_parent[
                                '_index']

    for child, parent in network_match_parent.items():
        # FIXME: 生成一个 pseudo net span，待前端修改后再开放此代码，注意处理时延计算
        # fake_pss = _generate_pseudo_process_span_set(flows[child],
        #                                              flows[parent])
        # process_span_list.append(fake_pss)
        # flows.extend(fake_pss.spans)
        _set_parent(flows[child], flows[parent],
                    "net-span mounted due to x_request_id or span_id passed")

    return process_span_list, networks, flow_index_to_id0, related_flow_index_map


def format_trace(services: list[ProcessSpanSet],
                 networks: list[NetworkSpanSet]) -> dict:
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
                    index_of_span] = f"{direct_flow_span_id}.{span.get_tap_side()}.{index_of_span}"
                response["tracing"].append(_get_flow_dict(span.flow))
            elif span.signal_source == L7_FLOW_SIGNAL_SOURCE_OTEL:
                id_map[span.get_flow_index()] = span.get_span_id()
                response["tracing"].append(_get_flow_dict(span.flow))

    for network in networks:
        for flow in network.flows:
            if flow["signal_source"] == L7_FLOW_SIGNAL_SOURCE_EBPF:
                continue
            id_map[flow[
                '_index']] = f"{network.span_id}.{flow['tap_side']}.{flow['_index']}"
            response["tracing"].append(_get_flow_dict(flow))

    for trace in response["tracing"]:
        trace["deepflow_span_id"] = id_map[trace["id"]]
        trace["deepflow_parent_span_id"] = id_map.get(trace["parent_id"], -1)
    response["tracing"] = TraceSort(response["tracing"]).sort_tracing()
    return response


def format_selftime(traces: list, parent_trace: dict, child_ids: list,
                    uid_index_map: dict[int, int]):
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
def pruning_flows(_id, flows, network_delay_us):
    _FLOW_INDEX_KEY = 'id'  # after _get_flow_dict(), _index change to id

    # 构建一个并查集，用来将所有的 Trace 划分为一个个 Tree
    disjoint_set = DisjointSet()
    for flow in flows:
        index = flow[_FLOW_INDEX_KEY]
        disjoint_set.put(index, flow['parent_id'])
        disjoint_set.get(index)  # compress tree

    # 记录所有 Trace Tree 的最小、最大时间和 trace_id 集合
    # root_index => {min_start_time_us, max_end_time_us, set(trace_id)}
    tree_infos: dict[int, dict] = {}
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
    for flow in flows:
        if not flow['trace_id']:
            continue
        index = flow[_FLOW_INDEX_KEY]
        root = disjoint_set.get(index)
        if 'trace_ids' not in tree_infos[root]:
            tree_infos[root]['trace_ids'] = set([flow['trace_id']])
        else:
            tree_infos[root]['trace_ids'].add(flow['trace_id'])

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
    for root, tree_info in tree_infos.items():
        if not _range_overlap(
                tree_info['min_start_time_us'],
                tree_info['max_end_time_us'],
                initial_tree_start_time_us,
                initial_tree_end_time_us,
                network_delay_us,
        ):
            # 如果时间范围无交叠，但属于同一个 trace_id 也应该追踪出来
            if initial_tree_trace_ids and initial_tree_trace_ids & tree_infos[
                    root].get('trace_ids', set()):
                pass
            else:
                # 时间与原始树不交迭、trace_id 与原始树不共享，则进行剪枝
                continue
        # 过了剪枝逻辑的 flow append 到最终结果
        for flow in flows:
            if disjoint_set.get(flow[_FLOW_INDEX_KEY]) == root:
                final_flows.append(flow)

    return final_flows


def pruning_trace(response, _id, network_delay_us):
    """
    剪枝
    response: {'tracing': [flow]}
    """
    flows = response.get('tracing', [])
    response['tracing'] = pruning_flows(_id, flows, network_delay_us)


def calculate_related_ids(
    response, flow_index_to_id0: list,
    related_flow_index_map: defaultdict(inner_defaultdict_set)):
    """
    计算 flow 的 related_ids 字段。
    当 related_ids 很多时，构造这些字符串非常耗时，因此这一步放在 pruning_trace 之后进行。

    response: {'tracing': [flow]}
    """
    _FLOW_INDEX_KEY = 'id'  # after _get_flow_dict(), _index change to id

    return_flows = response.get('tracing', [])
    for flow in return_flows:
        flow['related_ids'] = []
        for _index, related_types in related_flow_index_map[
                flow[_FLOW_INDEX_KEY]].items():
            _id = flow_index_to_id0[_index]
            flow['related_ids'].append(
                f"{_index}-{','.join(related_types)}-{_id}")


def merge_service(services: list[ProcessSpanSet], traces: list,
                  uid_to_trace_index: dict[int, int]) -> list:
    """
    按 service 对 flow 分组并统计时延指标
    """
    metrics_map = {}
    services_from_process_span_set = set[ProcessSpanSet]()
    services_from_pruning_traces = set()
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
        else:
            log.warning(
                f"service: {service.app_service}/{service.auto_service} dropped"
            )

    # 前两者取交集，对剩下的 `auto_service` 做统计
    for service in services_from_process_span_set:
        service_uid = ""
        service_uname = ""
        if service.auto_service_id is not None:
            service_uid = f"{service.auto_service_id}-"
            service_uname = service.auto_service if service.auto_service else service.ip
        elif service.app_service is not None:
            service_uid = f"-{service.app_service}"
            service_uname = service.app_service
        else:
            service_uid = 'unknown-'
            service_uname = "unknown service"
            log.warning(
                f"service has no auto_service_id or app_service, group_index: {service.group_index}, subnet: {service.subnet}, process: {service.process_id}"
            )

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


def format_final_result(
    services: list[ProcessSpanSet], networks: list[NetworkSpanSet], _id,
    network_delay_us: int, flow_index_to_id0: list,
    related_flow_index_map: defaultdict(inner_defaultdict_set)):
    """
    格式化返回结果
    """
    response = format_trace(services, networks)
    pruning_trace(response, _id, network_delay_us)  # XXX: slow function
    calculate_related_ids(response, flow_index_to_id0,
                          related_flow_index_map)  # XXX: slow function
    traces = response.get('tracing', [])
    uid_index_map = {trace["id"]: i for i, trace in enumerate(traces)}
    for trace in traces:
        format_selftime(traces, trace, trace.get("childs", []), uid_index_map)
    response['services'] = merge_service(services, traces, uid_index_map)
    deepflow_span_ids = {
        trace.get('deepflow_span_id')
        for trace in response.get('tracing', [])
    }
    for trace in response.get('tracing', []):
        if trace.get('deepflow_parent_span_id') and trace[
                'deepflow_parent_span_id'] not in deepflow_span_ids:
            trace['deepflow_parent_span_id'] = ''
            trace['parent_id'] = -1
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
            return [], []

        if self.rings_detection():
            log.warning(
                f"There are rings in the result tracing, try to find trace from: {self.traces[0]['_ids']}"
            )

        stack = [trace for trace in self.traces if trace['parent_id'] == -1]
        result = []
        while stack:
            trace = stack.pop()
            if trace.get('childs'):
                for child_ids in trace['childs']:
                    if child_ids not in self.uid_index_map:
                        continue
                    stack.append(self.traces[self.uid_index_map[child_ids]])
            result.append(trace)
        return result

    def rings_detection(self) -> bool:
        slow = self.traces[0]
        fast = self.traces[0]
        while fast and fast['parent_id'] >= 0:
            slow = self.traces[slow['parent_id']]
            fast = self.traces[self.traces[fast['parent_id']]['parent_id']]
            if slow == fast:
                return True
        return False


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
        "tap_id":
        flow.get("tap_id", None),
        "tap":
        flow.get("tap", None)
    }
    if flow["signal_source"] == L7_FLOW_SIGNAL_SOURCE_EBPF:
        flow_dict["subnet"] = flow.get("subnet")
        flow_dict["ip"] = flow.get("ip")
        flow_dict["auto_service"] = flow.get("auto_service")
        flow_dict["auto_service_id"] = flow.get("auto_service_id")
        flow_dict["process_kname"] = flow.get("process_kname")
    return flow_dict


def _get_df_key(df: DataFrame, key: str):  # XXX: 待删除，nan 在最源头进行处理
    if type(df[key]) == float:
        if math.isnan(df[key]):
            return None
    return df[key]


def _set_parent(flow: dict, flow_parent: dict, info: str = None):
    flow['parent_id'] = flow_parent['_index']
    if flow_parent.get('childs'):
        flow_parent['childs'].append(flow['_index'])
    else:
        flow_parent['childs'] = [flow['_index']]
    flow['set_parent_info'] = info


def generate_span_id():
    return hex(RandomIdGenerator().generate_span_id())
