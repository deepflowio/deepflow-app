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
from common.const import HTTP_OK
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

L7_FLOW_SIGNAL_SOURCE_PACKET = 0
L7_FLOW_SIGNAL_SOURCE_EBPF = 3
L7_FLOW_SIGNAL_SOURCE_OTEL = 4

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
        l7_flows_merged, app_flows, networks, flow_index_to_id0, related_flow_index_map = sort_all_flows(
            l7_flows, network_delay_us, return_fields, ntp_delay_us)

        return format_final_result(l7_flows_merged, networks, app_flows,
                                   self.args.get('_id'), network_delay_us,
                                   flow_index_to_id0, related_flow_index_map)

    async def query_ck(self, sql: str):
        querier = Querier(to_dataframe=True, debug=self.args.debug)
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
                'requset_type',
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


class Network:

    def __init__(self):
        # 标识 span_id 用于匹配 app-span
        self.span_id = None
        # 标识是否已找到了 sys-span，如果有则不需要关联 app-span，优先设置为 sys-span 的 parent/child
        self.has_sys_span = False
        # 分组聚合所有 tcp_seq 相同的 flow
        self.flows = []

    def add_flow(self, flow):
        """
        将 net-span 与 sys-span 按 tcp_seq 分组
        """
        if not self.span_id and flow["span_id"]:
            self.span_id = flow["span_id"]
        self.flows.append(flow)
        if flow["signal_source"] == L7_FLOW_SIGNAL_SOURCE_EBPF:
            # 标识 self 根据 tcp_seq 找到了对应的 sys-span
            # 对 s/s-nd，需要找 s-p，对 c/c-nd 需要找 c-p
            self.has_sys_span = True
            # self 不一定是 net-span，外层的调用是 net-span + sys-span 组成的列表
            flow["networks"] = self

    def sort_and_set_parent(self):
        self.flows = network_flow_sort(self.flows)
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


class Service:

    def __init__(self, vtap_id: int, process_id: int):
        self.vtap_id = vtap_id
        self.process_id = process_id

        self.direct_flows = []
        self.app_flow_of_direct_flows = []
        self.unattached_flows = dict()
        self.subnet_id = None
        self.subnet = None
        self.ip = None
        self.auto_service_type = None
        self.auto_service_id = None
        self.auto_service = None
        self.process_kname = None
        self.start_time_us = 0
        self.end_time_us = 0
        self.level = -1

    def parent_set(self):
        self.app_flow_of_direct_flows = sorted(
            self.app_flow_of_direct_flows,
            key=lambda x: x.get("start_time_us"))
        # 如果有s-p，s-p 不需要找父级 span，且所有找不到父级 span 的 c-p 都要挂靠到 s-p 下
        if self.direct_flows[0]['tap_side'] == TAP_SIDE_SERVER_PROCESS:
            for i, direct_flow in enumerate(self.direct_flows[1:]):
                if not direct_flow.get('parent_id'):
                    if direct_flow.get('parent_app_flow', None):
                        # 1. 存在span_id相同的应用span，将该系统span的parent设置为该span_id相同的应用span
                        _set_parent(direct_flow,
                                    direct_flow['parent_app_flow'],
                                    "c-p mounted on parent_app_flow")
                    else:
                        # 2. 所属service中存在应用span，将该系统span的parent设置为service中最后一条应用span
                        # 对应顺序：[app, c-app] <- c-p
                        if self.app_flow_of_direct_flows:
                            _set_parent(direct_flow,
                                        self.app_flow_of_direct_flows[-1],
                                        "c-p mounted on latest app_flow")
                        else:
                            # 3. 存在syscalltraceid相同且tap_side=s-p的系统span，该系统span的parent设置为该flow(syscalltraceid相同且tap_side=s-p)
                            # 这里只是把找不到上级 net-span/app-span 的 c-p 挂靠到 s-p 下
                            # FIXME: 注意这里 c-p 的 flow 加入 direct_flow 的时候用的是 <vtap_id, local_process_id> 匹配，这里关联之前缺了对 syscall_trace_id 关系的判断
                            # 对此场景：一个服务在一个请求内被穿越多次，可能就有 <vtap_id, local_process_id> 相同而 syscall_trace_id 不同的情况
                            # 这种情况下如果直接挂到首个 s-p 下，有可能父子关系排序错误
                            _set_parent(direct_flow, self.direct_flows[0],
                                        "c-p mounted on s-p")
            if self.direct_flows[0].get('parent_id', -1) < 0:
                self.direct_flows[0]['parent_id'] = -1
        else:
            # 只有c-p
            for i, direct_flow in enumerate(self.direct_flows):
                if not direct_flow.get('parent_id'):
                    # 1. 存在span_id相同的应用span，将该系统span的parent设置为该span_id相同的应用span
                    if direct_flow.get('parent_app_flow', None):
                        _set_parent(self.direct_flows[i],
                                    self.direct_flows[i]['parent_app_flow'],
                                    "c-p mounted on own app_flow")
                    else:
                        self.direct_flows[i]['parent_id'] = -1

    def check_client_process_flow(self, flow: dict) -> bool:
        """检查该flow是否与service有关联关系，s-p的时间范围需要覆盖c-p，否则拆分为两个service"""
        if self.process_id != flow["process_id_0"] \
            or self.vtap_id != flow["vtap_id"]:
            return False
        if self.start_time_us > flow["start_time_us"] \
            or self.end_time_us < flow["end_time_us"]:
            return False
        return True

    def add_direct_flow(self, flow: dict):
        """direct_flow是指该服务直接接收到的，或直接发出的flow"""
        #assert (
        #    self.vtap_id == flow.get('vtap_id')
        #    and self.process_id == flow.get('process_id')
        #)
        if flow['tap_side'] == TAP_SIDE_SERVER_PROCESS:
            self.start_time_us = flow["start_time_us"]
            self.end_time_us = flow["end_time_us"]
        for key in [
                'subnet_id',
                'subnet',
                'ip',
                'auto_service_id',
                'auto_service',
                'auto_service_type',
                'process_kname',
        ]:
            if flow['tap_side'] == TAP_SIDE_CLIENT_PROCESS:
                direction_key = key + "_0"
            else:
                direction_key = key + "_1"
            if getattr(self, key) and 'auto_service' not in key:
                flow[key] = getattr(self, key)
                continue
            elif not getattr(self, key):
                setattr(self, key, flow[direction_key])
                flow[key] = flow[direction_key]
            else:
                if self.auto_service_type in [0, 255]:
                    setattr(self, key, flow[direction_key])
                flow[key] = getattr(self, key)
        self.direct_flows.append(flow)

    def attach_app_flow(self, flow: dict):
        if flow["tap_side"] not in [
                TAP_SIDE_CLIENT_APP, TAP_SIDE_SERVER_APP, TAP_SIDE_APP
        ]:
            return
        for direct_flow in self.direct_flows:
            # span_id相同 x-p的parent一定是x-app
            if direct_flow["span_id"]:
                if direct_flow["span_id"] == flow["span_id"]:
                    direct_flow["parent_app_flow"] = flow
                    # 只有c-p和x-app的span_id相同时，属于同一个service
                    if direct_flow['tap_side'] == TAP_SIDE_CLIENT_PROCESS:
                        flow["service"] = self
                        self.app_flow_of_direct_flows.append(flow)
                        return True
        # x-app的parent是s-p时，一定属于同一个service
        if flow['parent_span_id'] and self.direct_flows[0]['span_id'] and flow[
                'parent_span_id'] == self.direct_flows[0][
                    'span_id'] and self.direct_flows[0][
                        'tap_side'] == TAP_SIDE_SERVER_PROCESS:
            # x-app的parent是c-p时，一定不属于同一个service
            # 逻辑顺序是：[s-nd, s, s-p s-app, app, c-app, c-p, c, c-nd]，所以 x-app 的 parent 不会是 c-p，一定跨了 Service
            # 如果能找到这种关系说明可能 s-nd/s/s-p 少了
            for client_process_flow in self.direct_flows[1:]:
                if flow['parent_span_id'] == client_process_flow['span_id']:
                    # 标记一下关系，但不要 append 到 service 中
                    flow["parent_syscall_flow"] = client_process_flow
                    return False
            flow["parent_syscall_flow"] = self.direct_flows[0]
            flow["service"] = self
            self.app_flow_of_direct_flows.append(flow)
            return True


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
    # 对 network_flows local/rest/xx_gw 位置或非虚拟网络的 net-span，需要按照响应时延倒序，见 `network_flow_sort` 中 response_duration_sort 逻辑
    # 对 app_flows: app-span 按固定的规则设置层级（span_id/parent_span_id），按 span_id 挂 sys-span 以及挂到 sys-span 构建的 <service> 上
    # 对 syscall_flows: sys-span 需要提取<vtap_id, local_process_id>分组定义为<service> ，并以此为主体构建火焰图骨架
    for flow in flows:
        if flow['signal_source'] == L7_FLOW_SIGNAL_SOURCE_EBPF:
            syscall_flows.append(flow)
        elif flow['signal_source'] == L7_FLOW_SIGNAL_SOURCE_PACKET:
            network_flows.append(flow)
        elif flow['signal_source'] == L7_FLOW_SIGNAL_SOURCE_OTEL:
            app_flows.append(flow)

    # 从Flow中提取Service：一个<vtap_id, local_process_id>二元组认为是一个Service。
    # 所有的追踪先从 s-p 开始构建，至少找到一个 s-p 才能开始构建<Service>
    # 先构建出所有的 Services
    service_map = defaultdict(Service)
    for flow in syscall_flows:
        if flow['tap_side'] != TAP_SIDE_SERVER_PROCESS:
            continue
        local_process_id = flow['process_id_1']
        vtap_id = flow['vtap_id']
        if (vtap_id, local_process_id, 0) not in service_map:
            service = Service(vtap_id, local_process_id)
            service_map[(vtap_id, local_process_id, 0)] = service
            # Service直接接收或发送的Flows
            service.add_direct_flow(flow)
        else:
            index = 0
            for key in service_map.keys():
                if key[0] == vtap_id and key[1] == local_process_id:
                    index += 1
            service = Service(vtap_id, local_process_id)
            service_map[(vtap_id, local_process_id, index)] = service
            service.add_direct_flow(flow)

    # 根据构建出的 Service 找到直接关联的 c-p
    # 如果无法找到 s-p，会从 c-p 构建一个新的 <Service>
    for flow in syscall_flows:
        if flow['tap_side'] != TAP_SIDE_CLIENT_PROCESS:
            continue
        local_process_id = flow['process_id_0']
        vtap_id = flow['vtap_id']
        index = 0
        max_start_time_service = None  # 没有任何地方用到，仅仅用于 continue 循环或 debug
        if (vtap_id, local_process_id, 0) in service_map:
            for key, service in service_map.items():
                if key[0] == vtap_id and key[1] == local_process_id:
                    index += 1
                    if service.check_client_process_flow(flow):
                        if not max_start_time_service:
                            max_start_time_service = service
                        else:
                            if service.start_time_us > max_start_time_service.start_time_us:
                                max_start_time_service = service
            if max_start_time_service:
                max_start_time_service.add_direct_flow(flow)
                continue
        # 没有attach到service上的flow生成一个新的service
        service = Service(vtap_id, local_process_id)
        service_map[(vtap_id, local_process_id, index)] = service
        # Service直接接收或发送的Flow
        service.add_direct_flow(flow)

    # 网络span及系统span按照tcp_seq进行分组
    # 有两个作用：1. 将 net-span 按 tcp_seq 分组，2. 提前找到与 net-span 关联的 sys-span
    networks = []
    network_flows = sorted(network_flows + syscall_flows,
                           key=lambda x: x.get("type"),
                           reverse=True)
    flow_aggregated = set()  # set(flow._index)
    for flow in network_flows:
        if flow['_index'] in flow_aggregated:
            continue
        # construct a network
        network = Network()
        networks.append(network)
        # aggregate self to this network
        network.add_flow(flow)
        flow_aggregated.add(flow['_index'])
        # aggregate other spans to this network
        for _index, related_types in related_flow_index_map[
                flow['_index']].items():
            if L7_FLOW_RELATIONSHIP_TCP_SEQ not in related_types:
                continue
            if _index in flow_aggregated:
                continue
            network.add_flow(flows[_index])
            flow_aggregated.add(_index)

    # 将应用span挂到Service上
    for index, app_flow in enumerate(app_flows):
        for service_key, service in service_map.items():
            if service.attach_app_flow(app_flow):
                break
    app_flow_set_service(app_flows)
    # 获取没有系统span存在的networks分组
    net_spanid_flows = defaultdict(list)  # flow.span_id => Network()
    for network in networks:
        if not network.has_sys_span and network.span_id:
            net_spanid_flows[network.span_id] = network

    ## 排序

    ### 网络span排序
    # 1.网络span按照tap_side_rank或response_duration进行排序，系统span始终在网络span的两头
    for network in networks:
        network.sort_and_set_parent()
    # 2. 存在span_id相同的应用span，将该网络span的parent设置为该span_id相同的应用span
    networks_set_to_app_fow(app_flows, net_spanid_flows)

    ### 应用span排序
    app_flow_sort(app_flows)

    ### 系统span排序
    for _, service in service_map.items():
        # c-p排序
        service.parent_set()
    services = list(service_map.values())
    # s-p排序
    service_sort(services, app_flows)
    sort_by_x_request_id(network_flows)
    return services, app_flows, networks, flow_index_to_id0, related_flow_index_map


def app_flow_set_service(array):
    """
    将 app-span 挂到 Service 下
    FIXME: 240328: 这里相同的逻辑执行了两次，需要找到原因修正
    """
    for flow_0 in array:
        if flow_0.get('parent_id', -1) >= 0:
            continue
        for flow_1 in array:
            if flow_0["parent_span_id"] == flow_1["span_id"]:
                if flow_0["app_service"] == flow_1["app_service"]:
                    if flow_0.get("service",
                                  None) and not flow_1.get("service", None):
                        flow_1["service"] = flow_0["service"]
                        flow_0["service"].app_flow_of_direct_flows.append(
                            flow_1)
                    elif not flow_0.get("service", None) and flow_1.get(
                            "service", None):
                        flow_0["service"] = flow_1["service"]
                        flow_1["service"].app_flow_of_direct_flows.append(
                            flow_0)
                break
    array.reverse()
    for flow_0 in array:
        if flow_0.get('parent_id', -1) >= 0:
            continue
        for flow_1 in array:
            if flow_0["parent_span_id"] == flow_1["span_id"]:
                if flow_0["app_service"] == flow_1["app_service"]:
                    if flow_0.get("service",
                                  None) and not flow_1.get("service", None):
                        flow_1["service"] = flow_0["service"]
                        flow_0["service"].app_flow_of_direct_flows.append(
                            flow_1)
                    elif not flow_0.get("service", None) and flow_1.get(
                            "service", None):
                        flow_0["service"] = flow_1["service"]
                        flow_1["service"].app_flow_of_direct_flows.append(
                            flow_0)
                break
    array.reverse()


def networks_set_to_app_fow(app_flows, network_flows):
    """
    设置 net-span 与 app-span 的层级关系
    app_flows: app_flows
    network_flows: dict{flow.span_id: Network()}
    """
    app_flows.reverse()
    for flow in app_flows:
        # 2. 存在span_id相同的应用span，将该网络span的parent设置为该span_id相同的应用span
        if flow["span_id"] in network_flows:
            _set_parent(network_flows[flow["span_id"]].flows[0], flow,
                        "network mounted duo to span_id")
            flow["network_flows"] = network_flows[flow["span_id"]]
    app_flows.reverse()


def app_flow_sort(array):

    for flow_0 in array:
        # 1. 若存在parent_span_id，且存在flow的span_id等于该parent_span_id,则将该应用span的parent设置为该flow
        if flow_0.get("parent_syscall_flow"):
            _set_parent(flow_0, flow_0["parent_syscall_flow"],
                        "app_flow mounted on syscall due to parent_span_id")
            continue
        for flow_1 in array:
            if flow_0["parent_span_id"] == flow_1["span_id"]:
                # 2. 若存在parent_span_id，且span_id等于该parent_span_id的flow存在span_id相同的网络span，则将该应用span的parent设置为该网络span
                if flow_1.get("network_flows"):
                    _set_parent(flow_0, flow_1["network_flows"].flows[-1],
                                "app_flow mounted due to parent_network")
                else:
                    # 3. 若存在parent_span_id, 将该应用span的parent设置为span_id等于该parent_span_id的flow
                    _set_parent(flow_0, flow_1,
                                "app_flow mounted due to parent_span_id")
        if flow_0.get('parent_id', -1) >= 0:
            continue
        if flow_0.get("service"):
            # 4. 若有所属service，将该应用span的parent设置为该service的s-p的flow
            if flow_0["service"].direct_flows[0][
                    "tap_side"] == TAP_SIDE_SERVER_PROCESS:
                _set_parent(flow_0, flow_0["service"].direct_flows[0],
                            "app_flow mouted on s-p in service")
                continue


def service_sort(services, app_flows):
    """
    设置不同的 service 之间的关系
    由于一个 service 的起点定义为 s-p，所以这里只需要找到 s-p 的 parent
    如果 s-p 的 parent 为 net-span，则找到 net-span 的 parent
    """
    app_flows_map = {app_flow["span_id"]: app_flow for app_flow in app_flows}
    for i in range(len(services)):
        if services[i].direct_flows[0]['tap_side'] == TAP_SIDE_SERVER_PROCESS:
            # 1. 存在span_id相同的应用span，将该系统span的parent设置为该span_id相同的应用span
            # 对应顺序：[... app, c-app, c-p, c, c-nd, |跨越服务|, s-nd, s, s-p, s-app, app ...]
            # 将 s-p 的 parent 设置为 c-app 或 s-p 的 s/s-nd 的 parent 设置为 c-app
            if services[i].direct_flows[0].get("parent_app_flow"):
                if services[i].direct_flows[0].get("networks") and \
                    services[i].direct_flows[0]["networks"].flows[0].get('parent_id', -1) < 0:
                    # 存在networks,且networks没有parent
                    _set_parent(
                        services[i].direct_flows[0]["networks"].flows[0],
                        services[i].direct_flows[0]["parent_app_flow"],
                        "trace mounted on app_flow due to parent_app_flow of s-p"
                    )
                    continue
                elif services[i].direct_flows[0].get('parent_id', -1) < 0:
                    _set_parent(
                        services[i].direct_flows[0],
                        services[i].direct_flows[0]["parent_app_flow"],
                        "s-p mounted on app_flow due to parent_app_flow(has the same span_id)"
                    )
                    continue

            server_process_parent_span_id = services[i].direct_flows[0].get(
                "parent_span_id", None)
            if server_process_parent_span_id not in app_flows_map:
                continue
            # s-p没有c-app的parent
            if server_process_parent_span_id is None or server_process_parent_span_id == '':
                continue
            # 2. 存在span_id相同且存在parent_span_id的flow，将该系统span的parent设置为span_id等于该parent_span_id的flow
            # 对应顺序：[... app, c-app, ~~ , s-p, s-app, app ...]
            # 如果 s-p 找到了 parent_span_id，说明来自于 s-p 后面的 s-app，它的父 span 为 上一个 c-app
            if services[i].direct_flows[0].get("networks") and \
                services[i].direct_flows[0]["networks"].flows[0].get('parent_id', -1) < 0:
                _set_parent(services[i].direct_flows[0]["networks"].flows[0],
                            app_flows_map[server_process_parent_span_id],
                            "trace mounted on parent_span of s-p(from s-app)")
                continue
            elif services[i].direct_flows[0].get('parent_id', -1) < 0:
                _set_parent(services[i].direct_flows[0],
                            app_flows_map[server_process_parent_span_id],
                            "parent fill s-p mounted on parent_span of s-app")
                continue


def format_trace(services: list, networks: list, app_flows: list) -> dict:
    """
    重新组织数据格式，并给 trace 排序
    """
    response = {'tracing': []}
    tracing = set()
    id_map = {-1: ""}
    for service in services:
        for index, flow in enumerate(service.direct_flows):
            flow['process_id'] = service.process_id
            direct_flow_span_id = generate_span_id(
            ) if not flow.get('span_id') or len(str(
                flow['span_id'])) < 16 else flow['span_id']
            id_map[flow[
                '_index']] = f"{direct_flow_span_id}.{flow['tap_side']}.{flow['_index']}"
            if flow['_index'] not in tracing:
                response["tracing"].append(_get_flow_dict(flow))
                tracing.add(flow['_index'])
            if flow.get("networks"):
                for indirect_flow in flow["networks"].flows:
                    if indirect_flow["response_status"] > flow[
                            "response_status"]:
                        flow["response_status"] = indirect_flow[
                            "response_status"]

    for network in networks:
        for flow in network.flows:
            if flow["tap_side"] in [
                    TAP_SIDE_SERVER_PROCESS, TAP_SIDE_CLIENT_PROCESS
            ]:
                continue
            id_map[flow[
                '_index']] = f"{network.span_id}.{flow['tap_side']}.{flow['_index']}"
            if flow['_index'] not in tracing:
                response["tracing"].append(_get_flow_dict(flow))
                tracing.add(flow['_index'])

    for flow in app_flows:
        id_map[flow["_index"]] = flow["span_id"]
        response["tracing"].append(_get_flow_dict(flow))
    for trace in response["tracing"]:
        trace["deepflow_span_id"] = id_map[trace["id"]]
        trace["deepflow_parent_span_id"] = id_map.get(trace["parent_id"], -1)
    response["tracing"] = TraceSort(response["tracing"]).sort_tracing()
    return response


def format_selftime(traces, parent_trace, child_ids, uid_index_map):
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
    tree_infos = {}
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


def merge_service(services, app_flows, response):
    """
    按 service 对 flow 分组并统计时延指标
    FIXME: 粗看代码有点冗余，本质上就是按 auto_service/app_service/service 对所有 trace 分组匹配之后求时延，可能出于性能考虑
    """
    metrics_map = {}
    prun_services = set()
    auto_services = set()
    ids = set()
    id_to_trace_map = {}
    # 先获取所有 auto_service
    for res in response.get('tracing', []):
        id_to_trace_map[res.get('id')] = res
        if res.get('auto_service'):
            auto_services.add(
                (res.get('auto_service_id'), res.get('auto_service')))
        ids.add(res.get('id'))
    # 在 `sort_all_flows` 函数中按 s-p 分组的 service 与 auto_service 做匹配，找出最终需要保留的 `service`
    for service in services:
        if (service.auto_service_id, service.auto_service) in auto_services:
            prun_services.add(service)
    # 前两者取交集，对剩下的 `auto_service` 做统计
    for service in prun_services:
        service_uid = f"{service.auto_service_id}-"
        service_uname = service.auto_service if service.auto_service else service.ip
        if service_uid not in metrics_map:
            metrics_map[service_uid] = {
                "service_uid": service_uid,
                "service_uname": service_uname,
                "duration": 0,
            }
        else:
            if metrics_map[service_uid].get('service_uname'):
                pass
            elif service_uname:
                metrics_map[service_uid]['service_uname'] = service_uname
        # 分组之后对 service 底下的所有 flow 设置对应的服务名称
        for index, flow in enumerate(service.direct_flows):
            flow['service_uid'] = service_uid
            flow['service_uname'] = service_uname
            trace = id_to_trace_map.get(flow.get('_index'))
            if trace:
                trace["service_uid"] = service_uid
                trace["service_uname"] = service_uname
                metrics_map[service_uid]["duration"] += trace["selftime"]
            flow['process_id'] = service.process_id
    serivce_name_to_service_uid = {}
    # 先对 app_flows 所属的 service 做索引
    for flow in app_flows:
        if flow.get("service"):
            service_uid = f"{flow['service'].auto_service_id}-"
            serivce_name_to_service_uid[flow['app_service']] = service_uid
    # 对 app_flows 进行分类统计
    for flow in app_flows:
        if flow.get('_index') not in ids:
            continue
        trace = id_to_trace_map.get(flow.get('_index'))
        if not flow.get("service") and flow[
                'app_service'] not in serivce_name_to_service_uid:
            # 如果没有匹配到任何被学习到的资源，可能是外部导入的 app-span，需要根据 span 自带的 app_service 进行统计
            service_uid = f"-{flow['app_service']}"
            if service_uid not in metrics_map:
                metrics_map[service_uid] = {
                    "service_uid": service_uid,
                    "service_uname": flow["app_service"],
                    "duration": 0,
                }
            flow["service_uid"] = service_uid
            flow["service_uname"] = flow["app_service"]
            if trace:
                trace["service_uid"] = service_uid
                trace["service_uname"] = flow["app_service"]
                metrics_map[service_uid]["duration"] += trace["selftime"]
        elif flow['app_service'] in serivce_name_to_service_uid:
            # 匹配第一次遍历已提前分类好的 app_service
            service_uid = serivce_name_to_service_uid[flow['app_service']]
            if service_uid not in metrics_map:
                metrics_map[service_uid] = {
                    "service_uid": service_uid,
                    "service_uname": flow["app_service"],
                    "duration": 0,
                }
            flow["service_uid"] = service_uid
            flow["service_uname"] = metrics_map[service_uid]["service_uname"]
            if trace:
                trace["service_uid"] = service_uid
                trace["service_uname"] = metrics_map[service_uid][
                    "service_uname"]
                metrics_map[service_uid]["duration"] += trace["selftime"]
        elif flow.get("service"):
            # 这里做补偿，实际和第一次循环构建 serivce_name_to_service_uid 功能一样
            service_uid = f"{flow['service'].auto_service_id}-"
            if service_uid not in metrics_map:
                metrics_map[service_uid] = {
                    "service_uid": service_uid,
                    "service_uname": flow["app_service"],
                    "duration": 0,
                }
            flow["service_uid"] = service_uid
            flow["service_uname"] = metrics_map[service_uid]["service_uname"]
            if trace:
                trace["service_uid"] = service_uid
                trace["service_uname"] = metrics_map[service_uid][
                    "service_uname"]
                metrics_map[service_uid]["duration"] += trace["selftime"]
    response["services"] = _call_metrics(metrics_map)


def format_final_result(
    services, networks, app_flows, _id, network_delay_us: int,
    flow_index_to_id0: list,
    related_flow_index_map: defaultdict(inner_defaultdict_set)):
    """
    格式化返回结果
    """
    response = format_trace(services, networks, app_flows)
    pruning_trace(response, _id, network_delay_us)  # XXX: slow function
    calculate_related_ids(response, flow_index_to_id0,
                          related_flow_index_map)  # XXX: slow function
    traces = response.get('tracing', [])
    uid_index_map = {trace["id"]: i for i, trace in enumerate(traces)}
    for trace in traces:
        format_selftime(traces, trace, trace.get("childs", []), uid_index_map)
    merge_service(services, app_flows, response)
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
        spans = []
        finded_child_ids = []
        # 找到 parent_id = -1 的 span，意味着它是一个 service 的起点
        # FIXME: 这里仍然有可能丢弃 span，考虑增加一个环检测，避免所有 span 的 parent_id > -1
        for trace in self.traces:
            if trace["parent_id"] == -1:
                spans.append(trace)
                spans.extend(self.find_child(trace["childs"],
                                             finded_child_ids))
        return spans

    def find_child(self, child_ids, finded_child_ids):
        spans = []
        for _id in child_ids:
            if _id not in self.uid_index_map:
                continue
            # Avoid ring
            if _id in finded_child_ids:
                continue
            trace = self.traces[self.uid_index_map[_id]]
            spans.append(trace)
            finded_child_ids.append(_id)
            spans.extend(self.find_child(trace["childs"], finded_child_ids))
        return spans


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


def _set_parent(flow, flow_parent, info=None):
    flow['parent_id'] = flow_parent['_index']
    if flow_parent.get("childs"):
        flow_parent["childs"].append(flow['_index'])
    else:
        flow_parent["childs"] = [flow['_index']]
    flow['set_parent_info'] = info


def generate_span_id():
    return hex(RandomIdGenerator().generate_span_id())


def network_flow_sort(traces):
    """
    对网络span进行排序，排序规则：
    1. 按照TAP_SIDE_RANKS进行排序
    2. 对Local和rest就近（比较采集器）排到其他位置附近（按时间排）
    3. 网络 Span 中如 tap_side = local 或 rest 或 xx_gw 或者 tap!= 虚拟网络，则取消 tap_side 排序逻辑，改为响应时延长度倒排，TAP_SIDE_RANKS正排
    """
    local_rest_traces = []
    sorted_traces = []
    sys_traces = []
    response_duration_sort = False
    for trace in traces:
        if trace['tap_side'] in [
                const.TAP_SIDE_LOCAL, const.TAP_SIDE_REST,
                const.TAP_SIDE_CLIENT_GATEWAY, const.TAP_SIDE_SERVER_GATEWAY,
                const.TAP_SIDE_CLIENT_GATEWAY_HAPERVISOR,
                const.TAP_SIDE_SERVER_GATEWAY_HAPERVISOR
        ] or trace['tap'] != "虚拟网络":  # FIXME: 确认虚拟网络是否已改名，以及这里要兼容多版本、多语言
            response_duration_sort = True

        if trace['tap_side'] in [const.TAP_SIDE_LOCAL, const.TAP_SIDE_REST]:
            local_rest_traces.append(trace)
        elif trace['tap_side'] in [
                const.TAP_SIDE_CLIENT_PROCESS, const.TAP_SIDE_SERVER_PROCESS
        ]:
            sys_traces.append(trace)
        else:
            sorted_traces.append(trace)

    # 对非虚拟网络的 flow 按响应时延排序（认为火焰图应是倒三角结构）
    if response_duration_sort:
        sorted_traces = sorted(
            sorted_traces + local_rest_traces,
            key=lambda x:
            (-x['response_duration'], const.TAP_SIDE_RANKS.get(x['tap_side']),
             x['tap_side']))
        for sys_trace in sys_traces:
            if sys_trace['tap_side'] == const.TAP_SIDE_CLIENT_PROCESS:
                sorted_traces.insert(0, sys_trace)
            else:
                sorted_traces.append(sys_trace)
        return sorted_traces

    # 对非 local/rest 的 span 按 tap_side rank 排序
    sorted_traces = sorted(
        sorted_traces + sys_traces,
        key=lambda x: (const.TAP_SIDE_RANKS.get(x['tap_side']), x['tap_side']))
    if not sorted_traces:
        sorted_traces += local_rest_traces
    else:
        # 对 local/rest 位置的 span 排到 start_time 最接近的 span 位置
        # 这里为了找到时间最接近的 span，经过两种搜索:
        # 1. 先找 agent 相同，时间最接近的 span
        # 2. 如果没有相同 agent，直接找时间最接近的 span
        for trace in local_rest_traces:
            vtap_index = -1
            for i, sorted_trace in enumerate(sorted_traces):
                if vtap_index > 0 and sorted_trace['vtap_id'] != trace[
                        'vtap_id']:
                    break
                if sorted_trace['vtap_id'] == trace['vtap_id']:
                    if sorted_trace['start_time_us'] < trace['start_time_us']:
                        vtap_index = i + 1
                    elif vtap_index == -1:
                        vtap_index = i
            if vtap_index >= 0:
                sorted_traces.insert(vtap_index, trace)
            else:
                # FIXME: 这里需要改二分
                for i, sorted_trace in enumerate(sorted_traces):
                    if trace['start_time_us'] < sorted_trace['start_time_us']:
                        sorted_traces.insert(i, trace)
                        break
    return sorted_traces


def get_parent_trace(parent_trace, traces):
    """
    `traces` 来源于 network_flows，迭代直到找到 parent_trace 最下级的 flow
    FIXME: 由于这里寻父逻辑与前面`基于观测点的寻父`与`基于 span_id 的寻父`逻辑不同，有可能成环，考虑让前两种寻父逻辑作为校验
    """
    if not traces:
        return parent_trace
    for trace in traces:
        if trace.get('_index') == parent_trace.get('_index'):
            continue
        if trace.get('x_request_id_0') == parent_trace.get('x_request_id_1'):
            # Avoid ring
            new_traces = [
                i for i in traces if i.get('_index') != trace.get('_index')
            ]
            # 递归，继续在 `traces` 里找到 `trace` 的子节点
            return get_parent_trace(trace, new_traces)
    else:
        return parent_trace


def sort_by_x_request_id(traces):
    for trace_0 in traces:
        if not trace_0.get('x_request_id_0'):
            continue

        if trace_0.get('parent_id', -1) < 0:
            parent_traces = []
            for trace_1 in traces:
                if trace_0.get('_index') == trace_1.get('_index'):
                    continue
                if not trace_1.get('x_request_id_1'):
                    continue
                # 这里确定父子关系
                # 逻辑顺序是 [前端，网关1，网关2，后端]
                # 对前端：c 位置的 flow 只有 x_request_id_x_1
                # 对网关1：s 位置的 flow 只有 x_request_id_x_1，c 位置的 flow 有 x_request_id_x_0/x_request_id_y_1
                # 对网关2：s 位置的 flow 有 x_request_id_x_0/x_request_id_y_1，c 位置的 flow 有 x_request_id_y_0
                # 对后端：s 位置的 flow 有 x_request_id_y_0
                # 综上，当 x_request_id_0 == x_request_id_1 时，x_request_id_1 一定是父节点
                # 注意需要考虑网关无法部署 agent 的场景
                if trace_1.get('x_request_id_1') == trace_0.get(
                        'x_request_id_0'):
                    parent_traces.append(trace_1)
            # 如果span有多个父span，选父span的叶子span作为parent
            if parent_traces:
                parent_trace = get_parent_trace(parent_traces[0],
                                                parent_traces)
                _set_parent(trace_0, parent_trace,
                            "trace mounted due to x_request_id")
