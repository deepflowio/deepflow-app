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
from common.utils import curl_perform
from common.const import HTTP_OK
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
L7_FLOW_TYPE_OTEL = 4
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
RETURN_FIELDS = list(
    set([
        # 追踪Meta信息
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

L7_PROTOCOL_DNS = 120
L7_PROTOCOL_HTTP2 = 21
L7_PROTOCOL_GRPC = 41


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
            base_filter += f" and signal_source={L7_FLOW_TYPE_OTEL}"
            max_iteration = 1
        rst = await self.trace_l7_flow(time_filter=time_filter,
                                       base_filter=base_filter,
                                       return_fields=["related_ids"],
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

    async def trace_l7_flow(self,
                            time_filter: str,
                            base_filter: str,
                            return_fields: list,
                            max_iteration: int = config.max_iteration,
                            network_delay_us: int = config.network_delay_us,
                            ntp_delay_us: int = 10000) -> list:
        """L7 FlowLog 追踪入口

        参数说明：
        time_filter: 查询的时间范围过滤条件，SQL表达式
            当使用四元组进行追踪时，time_filter置为希望搜索的一段时间范围，
            当使用五元组进行追踪时，time_filter置为五元组对应流日志的start_time前后一小段时间，以提升精度
        base_filter: 查询的基础过滤条件，用于限定一个四元组或五元组
        return_fields: 返回l7_flow_log的哪些字段
        max_iteration: 使用Flowmeta信息搜索的次数，每次搜索可认为大约能够扩充一级调用关系
        network_delay_us: 使用Flowmeta进行流日志匹配的时间偏差容忍度，越大漏报率越低但误报率越高，一般设置为网络时延的最大可能值
        """
        network_metas = set()
        syscall_metas = set()
        trace_ids = set()
        app_metas = set()
        x_request_metas = set()
        l7_flow_ids = set()
        xrequests = []
        related_map = defaultdict(dict)  # 标记 span 之间的关系
        third_app_spans_all = []

        # Q1: 先获取 _id 对应的数据
        dataframe_flowmetas = await self.query_flowmetas(
            time_filter, base_filter)
        if type(dataframe_flowmetas) != DataFrame:
            return {}
        dataframe_flowmetas.rename(columns={'_id_str': '_id'}, inplace=True)
        # 先确定以此 _id 对应的行数据作为 root（不一定是 root span，仅标记为追踪起点）
        related_map[dataframe_flowmetas['_id'][0]] = {
            dataframe_flowmetas['_id'][0]: {'base'}
        }
        # tempo api
        trace_id = self.args.get("trace_id") if self.args.get(
            "trace_id") else ''
        # 是否允许多个 trace_id 被串联到一个追踪中
        allow_multiple_trace_ids_in_tracing_result = config.allow_multiple_trace_ids_in_tracing_result
        # 调用外部 apm api 补充 trace 数据
        call_apm_api_to_supplement_trace = config.call_apm_api_to_supplement_trace
        multi_trace_ids = set()
        query_simple_trace_id = False  # 真实语义为：在单 trace_id 场景下对同一个 trace_id 只需要查询一次，避免重复查询
        # 进行迭代查询，上限为 config.spec.max_iteration
        # 除了 max_iteration 之外，跳出条件为：
        # 1. 通过 trace_id 与 tcp_seq / syscall_trace_id / x_request_id 无法关联到新的数据
        # 2. 获取到新的数据之后 DataFrame 合并，当合并前后的数据量相等，说明没有新的数据，可直接跳出循环（避免循环里多次加载合并同一份数据）
        for i in range(max_iteration):
            if type(dataframe_flowmetas) != DataFrame:
                break
            filters = []
            # 对 new_trace_id_flows 集合：
            # 单 trace_id：移除 trace_id 不同的数据
            # 多 trace_id：允许通过 tcp_seq/syscall/x_request_id 查询出的 trace_id，需要移除通过 FastFilter IN 逻辑查出的不在上述集合内的 trace_id
            new_trace_id_flows = pd.DataFrame()
            new_trace_id_filters = []
            new_trace_ids = set()
            # 主动注入的追踪信息
            if not allow_multiple_trace_ids_in_tracing_result:
                # 1. 基于 trace_id 获取所有相关数据
                if trace_id:
                    new_trace_ids.add(trace_id)
                delete_index = []
                deleted_trace_ids = set()
                for index in range(len(dataframe_flowmetas.index)):
                    flow_trace_id = dataframe_flowmetas['trace_id'][index]
                    if flow_trace_id in [0, '']:
                        continue
                    # C1: 如果 Q1 初次查询的数据包含 trace_id，但与查询参数的 trace_id 不同，说明查出来的数据是被误关联的，需要清理掉
                    if trace_id and trace_id != flow_trace_id:
                        delete_index.append(index)
                        deleted_trace_ids.add(flow_trace_id)
                    # C1: 以 Q1 初次查询获取到的 trace_id 作为查询条件
                    if not trace_id:
                        trace_id = flow_trace_id
                        new_trace_ids.add(trace_id)
                if trace_id and not query_simple_trace_id:
                    # 构建 trace_id 作为第二次查询迭代的条件
                    # 注意 FastFilter 是一个特殊的 feature，见 #deepflow-server:/querier/engine/clickhouse/filter.go
                    # 当启用了 #deepflow-server:/config.trace-id-with-index 时，FastFilter 会转换成对 trace_id_index 的查询
                    new_trace_id_filters.append(
                        f"FastFilter(trace_id)='{trace_id}'")
                    # Trace id query separately
                    query_trace_filters = []
                    query_trace_filters.append(
                        ' OR '.join(new_trace_id_filters))
                    if self.signal_sources == ['otel']:
                        query_trace_filters.append(
                            f"signal_source={L7_FLOW_TYPE_OTEL}")
                    # Q2: 获取 trace_id 相关数据，第一层迭代
                    new_trace_id_flows = await self.query_flowmetas(
                        time_filter, ' AND '.join(query_trace_filters))
                    query_simple_trace_id = True
                if delete_index:
                    dataframe_flowmetas = dataframe_flowmetas.drop(
                        delete_index).reset_index(drop=True)
                    log.debug(f"删除的trace id为：{deleted_trace_ids}")
                if call_apm_api_to_supplement_trace and trace_id not in multi_trace_ids:
                    # 获取外部 apm 存储的 app-span
                    get_third_app_span_url = f"http://{config.querier_server}:{config.querier_port}/api/v1/adapter/tracing?traceid={trace_id}"
                    app_spans_res, app_spans_code = await curl_perform(
                        'get', get_third_app_span_url)
                    if app_spans_code != HTTP_OK:
                        log.warning(
                            f"Get app spans failed! url: {get_third_app_span_url}"
                        )
                    app_spans = app_spans_res.get('data', {}).get('spans', [])
                    self.complete_app_span(app_spans)
                    third_app_spans_all.extend(app_spans)
                    multi_trace_ids.add(trace_id)
                    if app_spans:
                        dataframe_flowmetas = pd.concat(
                            [dataframe_flowmetas,
                             pd.DataFrame(app_spans)],
                            join="outer",
                            ignore_index=True).drop_duplicates(
                                ["_id"]).reset_index(drop=True)
            else:
                # 在允许多个 trace_id 的情况下，补充这一部分 trace_id 并尝试从外部 apm 补充 app-span
                third_app_spans = []
                for index in range(len(dataframe_flowmetas.index)):
                    if dataframe_flowmetas['trace_id'][index] in [0, '']:
                        continue
                    apm_trace_id = dataframe_flowmetas['trace_id'][index]
                    # 这里 dataframe_flowmetas 在多次迭代中可能会获取到与入参 flow 不相等的 trace_id，当允许多个 trace_id 时在此处合并到完整的 new_trace_ids 列表且不被移除
                    new_trace_ids.add(
                        (dataframe_flowmetas['_id'][index], apm_trace_id))
                    if call_apm_api_to_supplement_trace and apm_trace_id not in multi_trace_ids:
                        get_third_app_span_url = f"http://{config.querier_server}:{config.querier_port}/api/v1/adapter/tracing?traceid={apm_trace_id}"
                        app_spans_res, app_spans_code = await curl_perform(
                            'get', get_third_app_span_url)
                        if app_spans_code != HTTP_OK:
                            log.warning(
                                f"Get app spans failed! url: {get_third_app_span_url}"
                            )
                        app_spans = app_spans_res.get('data',
                                                      {}).get('spans', [])
                        third_app_spans.extend(app_spans)
                        multi_trace_ids.add(apm_trace_id)
                self.complete_app_span(third_app_spans)
                third_app_spans_all.extend(third_app_spans)
                if third_app_spans:
                    dataframe_flowmetas = pd.concat(
                        [dataframe_flowmetas,
                         pd.DataFrame(third_app_spans)],
                        join="outer",
                        ignore_index=True).drop_duplicates(
                            ["_id"]).reset_index(drop=True)
                # 以 `trace_ids` 记录所有被迭代过的 `trace_id`，在每次迭代中去掉上一次迭代的 trace_id，避免重复查询
                new_trace_ids -= trace_ids
                trace_ids |= new_trace_ids
                if new_trace_ids:
                    new_trace_ids_set = set(
                        [f"'{nxrid[1]}'" for nxrid in new_trace_ids])
                    # 如果启用了多 trace_id 与 #deepflow-server:/config.trace-id-with-index
                    # 由于 trace_id_index 是 hash，所以这里的 IN 查询后可能获取到相同的 trace_id_index 但实际上是不同的 trace_id
                    # 此时仍然要去掉非 new_trace_ids_set 中的 trace_id，避免查出不相关的数据
                    new_trace_id_filters.append(
                        f"FastFilter(trace_id) IN ({','.join(new_trace_ids_set)})"
                    )
                    # Trace id query separately
                    query_trace_filters = []
                    query_trace_filters.append(
                        ' OR '.join(new_trace_id_filters))
                    if self.signal_sources == ['otel']:
                        query_trace_filters.append(
                            f"signal_source={L7_FLOW_TYPE_OTEL}")
                    # Q3: <=> Q2 基于 trace_id 获取相关数据，第一层迭代
                    new_trace_id_flows = await self.query_flowmetas(
                        time_filter, ' AND '.join(query_trace_filters))

            if type(new_trace_id_flows) != DataFrame:
                break
            # Delete different trace id data
            new_trace_id_flow_delete_index = []
            deleted_trace_ids = set()
            for index in range(len(new_trace_id_flows.index)):
                flow_trace_id = new_trace_id_flows['trace_id'][index]
                if flow_trace_id not in new_trace_ids:
                    new_trace_id_flow_delete_index.append(index)
                    deleted_trace_ids.add(flow_trace_id)
            if new_trace_id_flow_delete_index:
                new_trace_id_flows = new_trace_id_flows.drop(
                    new_trace_id_flow_delete_index).reset_index(drop=True)
            new_trace_id_flows.rename(columns={'_id_str': '_id'}, inplace=True)

            # only otel data
            new_flows = pd.DataFrame()
            if self.signal_sources != ['otel']:
                # 新的网络追踪信息
                new_network_metas = set()
                req_tcp_seqs = set()
                resp_tcp_seqs = set()
                # net-span 追踪: 基于 req_tcp_seq/resp_tcp_seq 获取所有关联的有意义的 flow
                for index in range(len(dataframe_flowmetas.index)):
                    req_tcp_seq = dataframe_flowmetas['req_tcp_seq'][index]
                    resp_tcp_seq = dataframe_flowmetas['resp_tcp_seq'][index]
                    tap_side = dataframe_flowmetas['tap_side'][index]
                    if req_tcp_seq == 0 and resp_tcp_seq == 0:
                        continue
                    if tap_side not in [
                            TAP_SIDE_CLIENT_PROCESS, TAP_SIDE_SERVER_PROCESS
                    ] and tap_side not in const.TAP_SIDE_RANKS:
                        continue
                    new_network_metas.add((
                        dataframe_flowmetas['_id'][index],
                        dataframe_flowmetas['type'][index],
                        dataframe_flowmetas['req_tcp_seq'][index],
                        dataframe_flowmetas['resp_tcp_seq'][index],
                        dataframe_flowmetas['start_time_us'][index],
                        dataframe_flowmetas['end_time_us'][index],
                        dataframe_flowmetas['span_id'][index],
                        dataframe_flowmetas['x_request_id_0'][index],
                        dataframe_flowmetas['x_request_id_1'][index],
                    ))
                new_network_metas -= network_metas
                network_metas |= new_network_metas
                networks = [
                    L7NetworkMeta(nnm, network_delay_us)
                    for nnm in new_network_metas
                ]
                for nnm in new_network_metas:
                    req_tcp_seq = nnm[2]
                    resp_tcp_seq = nnm[3]
                    if req_tcp_seq:
                        req_tcp_seqs.add(str(req_tcp_seq))
                    if resp_tcp_seq:
                        resp_tcp_seqs.add(str(resp_tcp_seq))
                # Network span relational query
                # C2: 以 req_tcp_seq & resp_tcp_seq 作为条件查询关联 flow
                network_filters = []
                if req_tcp_seqs:
                    network_filters.append(
                        f"req_tcp_seq IN ({','.join(req_tcp_seqs)})")
                if resp_tcp_seqs:
                    network_filters.append(
                        f"resp_tcp_seq IN ({','.join(resp_tcp_seqs)})")
                if network_filters:
                    filters.append(f"({' OR '.join(network_filters)})")

                # 新的系统调用追踪信息
                new_syscall_metas = set()
                syscall_trace_id_requests = set()
                syscall_trace_id_responses = set()
                for index in range(len(dataframe_flowmetas.index)):
                    syscall_trace_id_request = dataframe_flowmetas[
                        'syscall_trace_id_request'][index]
                    syscall_trace_id_response = dataframe_flowmetas[
                        'syscall_trace_id_response'][index]
                    if syscall_trace_id_request > 0 or syscall_trace_id_response > 0:
                        new_syscall_metas.add((
                            dataframe_flowmetas['_id'][index],
                            dataframe_flowmetas['vtap_id'][index],
                            dataframe_flowmetas['syscall_trace_id_request']
                            [index],
                            dataframe_flowmetas['syscall_trace_id_response']
                            [index],
                            dataframe_flowmetas['tap_side'][index],
                            dataframe_flowmetas['start_time_us'][index],
                            dataframe_flowmetas['end_time_us'][index],
                        ))
                new_syscall_metas -= syscall_metas
                syscall_metas |= new_syscall_metas
                syscalls = [L7SyscallMeta(nsm) for nsm in new_syscall_metas]
                for nsm in new_syscall_metas:
                    syscall_trace_id_request = nsm[2]
                    syscall_trace_id_response = nsm[3]
                    if syscall_trace_id_request > 0:
                        syscall_trace_id_requests.add(
                            str(syscall_trace_id_request))
                    if syscall_trace_id_response > 0:
                        syscall_trace_id_responses.add(
                            str(syscall_trace_id_response))
                # System span relational query
                # C3: 以 syscall_trace_id_request & syscall_trace_id_response 作为条件查询关联 flow
                syscall_filters = []
                if syscall_trace_id_requests or syscall_trace_id_responses:
                    syscall_filters.append(
                        f"syscall_trace_id_request IN ({','.join(list(syscall_trace_id_requests) + list(syscall_trace_id_responses))})"
                    )
                    syscall_filters.append(
                        f"syscall_trace_id_response IN ({','.join(list(syscall_trace_id_requests) + list(syscall_trace_id_responses))})"
                    )
                if syscall_filters:
                    filters.append(f"({' OR '.join(syscall_filters)})")

                new_x_request_metas = set()
                x_request_id_0s = set()
                x_request_id_1s = set()
                for index in range(len(dataframe_flowmetas.index)):
                    x_request_id_0 = dataframe_flowmetas['x_request_id_0'][
                        index]
                    x_request_id_1 = dataframe_flowmetas['x_request_id_1'][
                        index]
                    if x_request_id_0 in [0, ''] and x_request_id_1 in [0, '']:
                        continue
                    new_x_request_metas.add(
                        (dataframe_flowmetas['_id'][index],
                         dataframe_flowmetas['x_request_id_0'][index],
                         dataframe_flowmetas['x_request_id_1'][index]))
                new_x_request_metas -= x_request_metas
                x_request_metas |= new_x_request_metas
                xrequests = [
                    L7XrequestMeta(nxr) for nxr in new_x_request_metas
                ]
                for nxr in new_x_request_metas:
                    x_request_id_0 = nxr[1]
                    x_request_id_1 = nxr[2]
                    if x_request_id_0:
                        x_request_id_0s.add(f"'{x_request_id_0}'")
                    if x_request_id_1:
                        x_request_id_1s.add(f"'{x_request_id_1}'")

                # x_request_id related query
                # 根据 x_request_id 构建查询条件关联 flow
                # 当启用了 x_request_id 时，可关联穿越 nginx 类网关的 flow
                # C4: 以 x_request_id_0 & x_request_id_1 作为条件查询关联 flow
                x_request_filters = []
                if x_request_id_0s:
                    x_request_filters.append(
                        f"x_request_id_1 IN ({','.join(x_request_id_0s)})")
                if x_request_id_1s:
                    x_request_filters.append(
                        f"x_request_id_0 IN ({','.join(x_request_id_1s)})")
                if x_request_filters:
                    filters.append(f"({' OR '.join(x_request_filters)})")

                new_flows = pd.DataFrame()
                if filters:
                    # Non-trace_id relational queries
                    # Q4: 查询上述基于 C[1234] 构建出的条件，即与【第一层迭代】关联的所有 flow，构建【第二层迭代】做查询
                    new_flows = await self.query_flowmetas(
                        time_filter, ' OR '.join(filters))
                    if type(new_flows) != DataFrame:
                        break
                    new_flow_delete_index = []
                    deleted_trace_ids = set()
                    old_ids = set(dataframe_flowmetas['_id'])
                    id_to_related_tag = dict()
                    for index in new_flows.index:
                        _id = new_flows.at[index, '_id_str']
                        vtap_id = new_flows.at[index, 'vtap_id']
                        req_tcp_seq = new_flows.at[index, 'req_tcp_seq']
                        resp_tcp_seq = new_flows.at[index, 'resp_tcp_seq']
                        tap_side = new_flows.at[index, 'tap_side']
                        _type = new_flows.at[index, 'type']
                        start_time_us = new_flows.at[index, 'start_time_us']
                        end_time_us = new_flows.at[index, 'end_time_us']
                        span_id = new_flows.at[index, 'span_id']
                        parent_span_id = new_flows.at[index, 'parent_span_id']
                        x_request_id_0 = new_flows.at[index, 'x_request_id_0']
                        x_request_id_1 = new_flows.at[index, 'x_request_id_1']
                        syscall_trace_id_request = new_flows.at[
                            index, 'syscall_trace_id_request']
                        syscall_trace_id_response = new_flows.at[
                            index, 'syscall_trace_id_response']
                        flow_trace_id = new_flows.at[index, 'trace_id']

                        id_to_related_tag[_id] = {
                            '_id': _id,
                            'vtap_id': vtap_id,
                            'req_tcp_seq': req_tcp_seq,
                            'resp_tcp_seq': resp_tcp_seq,
                            'tap_side': tap_side,
                            'type': _type,
                            'start_time_us': start_time_us,
                            'end_time_us': end_time_us,
                            'span_id': span_id,
                            'parent_span_id': parent_span_id,
                            'x_request_id_0': x_request_id_0,
                            'x_request_id_1': x_request_id_1,
                            'syscall_trace_id_request':
                            syscall_trace_id_request,
                            'syscall_trace_id_response':
                            syscall_trace_id_response
                        }
                        # Delete different trace id data
                        if not allow_multiple_trace_ids_in_tracing_result:
                            if trace_id and flow_trace_id and trace_id != flow_trace_id:
                                new_flow_delete_index.append(index)
                                deleted_trace_ids.add(flow_trace_id)
                                continue
                        # delete dup _id for performance
                        if _id in old_ids:
                            new_flow_delete_index.append(index)
                    if new_flow_delete_index:
                        new_flows = new_flows.drop(
                            new_flow_delete_index).reset_index(drop=True)
                    if deleted_trace_ids:
                        log.debug(f"删除的trace id为：{deleted_trace_ids}")
                    new_flows.rename(columns={'_id_str': '_id'}, inplace=True)

                    # 先标记可能存在的关联关系，在 new_related_map 中通过多次迭代标记上有关联的 _id
                    # 如果一个 _id 没有标记到 new_related_map 中，flow 会被删掉，后续逻辑不再处理
                    new_related_map = defaultdict(dict)
                    new_flow_ids = set(new_flows['_id'])
                    if xrequests:
                        for x_request in xrequests:
                            x_request.set_relate(new_flow_ids, new_related_map,
                                                 id_to_related_tag)
                    if syscalls:
                        for syscall in syscalls:
                            syscall.set_relate(new_flow_ids, new_related_map,
                                               id_to_related_tag)
                    if networks:
                        for network in networks:
                            network.set_relate(new_flow_ids, new_related_map,
                                               id_to_related_tag)

                    # 注意上面的 new_flow_delete_index append 了多次，此处可能去掉的数据有:
                    # 1. _id 已经存在的重复数据
                    # 2. 通过 trace_id 关联，在不允许多 trace_id 的情况下查出了非本次追踪的 trace_id 的数据
                    # 3. 通过 tcp_seq / syscall_trace_id / x_request_id 关联不上任何关系的数据
                    # 4. 虽然关联上了，但是 network_delay_us 没有落在范围内被丢弃的数据
                    # 此处为第一次筛选，在后面的关联合并排序中仍然会去掉无关联数据
                    new_flow_delete_index = []
                    for index in range(len(new_flows.index)):
                        _id = new_flows['_id'][index]
                        # Delete unrelated data
                        if _id not in new_related_map:
                            new_flow_delete_index.append(index)
                    if new_flow_delete_index:
                        new_flows = new_flows.drop(
                            new_flow_delete_index).reset_index(drop=True)

            # Merge all flows and check if any new flows are generated
            old_flows_length = len(dataframe_flowmetas)
            dataframe_flowmetas = pd.concat(
                [dataframe_flowmetas, new_flows, new_trace_id_flows],
                join="outer",
                ignore_index=True).drop_duplicates(["_id"
                                                    ]).reset_index(drop=True)
            # L7 Flow ID信息
            l7_flow_ids |= set(dataframe_flowmetas['_id'])
            new_flows_length = len(dataframe_flowmetas)
            if old_flows_length == new_flows_length:
                break
        # end of max_iteration loop
        # 做 span 追溯，标记所有 span 是因为什么信息而被追踪关联
        set_all_relate(dataframe_flowmetas, related_map, network_delay_us)
        if not l7_flow_ids:
            return {}
        # 获取追踪到的所有应用流日志
        # 通过 RETURN_FIELDS 确定需要返回哪些字段（精简有用的返回信息）
        return_fields += RETURN_FIELDS
        flow_fields = list(RETURN_FIELDS)
        if self.has_attributes:
            return_fields.append("attribute")
            flow_fields.append("attribute")
        # Q5: 此处查询会获取这些 _id 对应的完整 Application Metadata
        l7_flows = await self.query_all_flows(time_filter, l7_flow_ids,
                                              flow_fields)
        if type(l7_flows) != DataFrame:
            return {}
        l7_flows.rename(columns={'_id_str': '_id'}, inplace=True)
        l7_flows = pd.concat(
            [l7_flows, pd.DataFrame(third_app_spans_all)],
            join="outer",
            ignore_index=True).drop_duplicates(["_id"]).reset_index(drop=True)
        l7_flows.insert(0, "related_ids", "")
        l7_flows = l7_flows.where(l7_flows.notnull(), None)
        # 对查出来的所有调用日志，通过之前构建的 related_map 标记所有有关联关系的 _id
        for index in l7_flows.index:
            l7_flows.at[index, 'related_ids'] = related_map[l7_flows.at[index,
                                                                        '_id']]
        # 对所有应用流日志排序
        # 这里实际上包含几个动作：排序+合并+分组+设置父子关系
        l7_flows_merged, app_flows, networks = sort_all_flows(
            l7_flows, network_delay_us, return_fields, ntp_delay_us)
        return format(l7_flows_merged, networks, app_flows,
                      self.args.get('_id'), network_delay_us)

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
        type, req_tcp_seq, resp_tcp_seq, toUnixTimestamp64Micro(start_time) AS start_time_us, toUnixTimestamp64Micro(end_time) AS end_time_us,
        vtap_id, syscall_trace_id_request, syscall_trace_id_response, span_id, parent_span_id, l7_protocol,
        trace_id, x_request_id_0, x_request_id_1, toString(_id) AS `_id_str`, tap_side, auto_instance_0, auto_instance_1
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


def set_all_relate(dataframe_flowmetas, related_map, network_delay_us):
    """
    用于 span 追溯关联
    先构建 tcp_seq/syscall_trace_id/x_request_id 对 _id 的反向索引，再对每一种类型的关联通过各自的 `set_relate` 判断是否有关联
    """
    new_network_metas = set()
    new_syscall_metas = set()
    new_x_request_metas = set()
    new_app_metas = set()
    req_tcp_seq_to_ids = defaultdict(set)
    resp_tcp_seq_to_ids = defaultdict(set)
    syscall_req_to_ids = defaultdict(set)
    syscall_resp_to_ids = defaultdict(set)
    span_id_to_ids = defaultdict(set)
    parent_span_id_to_ids = defaultdict(set)
    x_req_0_to_ids = defaultdict(set)
    x_req_1_to_ids = defaultdict(set)
    id_to_related_tag = defaultdict(dict)

    # 先提取出所有有意义的 tcp_seq/syscall_trace_id/x_request_id/span_id，构建一个对 _id 的反向索引
    for index in dataframe_flowmetas.index:
        req_tcp_seq = dataframe_flowmetas.at[index, 'req_tcp_seq']
        resp_tcp_seq = dataframe_flowmetas.at[index, 'resp_tcp_seq']
        tap_side = dataframe_flowmetas.at[index, 'tap_side']
        _id = dataframe_flowmetas.at[index, '_id']
        vtap_id = dataframe_flowmetas.at[index, 'vtap_id']
        _type = dataframe_flowmetas.at[index, 'type']
        start_time_us = dataframe_flowmetas.at[index, 'start_time_us']
        end_time_us = dataframe_flowmetas.at[index, 'end_time_us']
        span_id = dataframe_flowmetas.at[index, 'span_id']
        parent_span_id = dataframe_flowmetas.at[index, 'parent_span_id']
        x_request_id_0 = dataframe_flowmetas.at[index, 'x_request_id_0']
        x_request_id_1 = dataframe_flowmetas.at[index, 'x_request_id_1']
        syscall_trace_id_request = dataframe_flowmetas.at[
            index, 'syscall_trace_id_request']
        syscall_trace_id_response = dataframe_flowmetas.at[
            index, 'syscall_trace_id_response']
        flow_trace_id = dataframe_flowmetas.at[index, 'trace_id']

        id_to_related_tag[_id] = {
            '_id': _id,
            'vtap_id': vtap_id,
            'req_tcp_seq': req_tcp_seq,
            'resp_tcp_seq': resp_tcp_seq,
            'tap_side': tap_side,
            'type': _type,
            'start_time_us': start_time_us,
            'end_time_us': end_time_us,
            'span_id': span_id,
            'parent_span_id': parent_span_id,
            'x_request_id_0': x_request_id_0,
            'x_request_id_1': x_request_id_1,
            'syscall_trace_id_request': syscall_trace_id_request,
            'syscall_trace_id_response': syscall_trace_id_response
        }

        if req_tcp_seq == 0 and resp_tcp_seq == 0:
            continue
        if tap_side not in [TAP_SIDE_CLIENT_PROCESS, TAP_SIDE_SERVER_PROCESS
                            ] and tap_side not in const.TAP_SIDE_RANKS:
            continue
        new_network_metas.add((_id, _type, req_tcp_seq, resp_tcp_seq,
                               start_time_us, end_time_us, span_id))

        if req_tcp_seq:
            req_tcp_seq_to_ids[req_tcp_seq].add(_id)
        if resp_tcp_seq:
            resp_tcp_seq_to_ids[resp_tcp_seq].add(_id)

    for index in dataframe_flowmetas.index:
        syscall_trace_id_request = dataframe_flowmetas.at[
            index, 'syscall_trace_id_request']
        syscall_trace_id_response = dataframe_flowmetas.at[
            index, 'syscall_trace_id_response']
        _id = dataframe_flowmetas.at[index, '_id']
        vtap_id = dataframe_flowmetas.at[index, 'vtap_id']
        if syscall_trace_id_request > 0 or syscall_trace_id_response > 0:
            new_syscall_metas.add((_id, vtap_id, syscall_trace_id_request,
                                   syscall_trace_id_response))
            if syscall_trace_id_request:
                syscall_req_to_ids[syscall_trace_id_request].add(_id)
            if syscall_trace_id_response:
                syscall_resp_to_ids[syscall_trace_id_response].add(_id)

    for index in dataframe_flowmetas.index:
        x_request_id_0 = dataframe_flowmetas.at[index, 'x_request_id_0']
        x_request_id_1 = dataframe_flowmetas.at[index, 'x_request_id_1']
        _id = dataframe_flowmetas.at[index, '_id']
        if x_request_id_0 in [0, ''] and x_request_id_1 in [0, '']:
            continue
        new_x_request_metas.add((_id, x_request_id_0, x_request_id_1))
        if x_request_id_0:
            x_req_0_to_ids[x_request_id_0].add(_id)
        if x_request_id_1:
            x_req_1_to_ids[x_request_id_1].add(_id)
    for index in dataframe_flowmetas.index:
        span_id = dataframe_flowmetas.at[index, 'span_id']
        parent_span_id = dataframe_flowmetas.at[index, 'parent_span_id']
        tap_side = dataframe_flowmetas.at[index, 'tap_side']
        _id = dataframe_flowmetas.at[index, '_id']
        if tap_side not in [
                TAP_SIDE_CLIENT_PROCESS, TAP_SIDE_SERVER_PROCESS,
                TAP_SIDE_CLIENT_APP, TAP_SIDE_SERVER_APP, TAP_SIDE_APP
        ] or not span_id:
            continue
        if span_id or parent_span_id:
            new_app_metas.add((_id, tap_side, span_id, parent_span_id))
            if span_id:
                span_id_to_ids[span_id].add(_id)
            if parent_span_id:
                parent_span_id_to_ids[parent_span_id].add(_id)
    networks = [
        L7NetworkMeta(nnm, network_delay_us) for nnm in new_network_metas
    ]
    syscalls = [L7SyscallMeta(nsm) for nsm in new_syscall_metas]
    xrequests = [L7XrequestMeta(nxr) for nxr in new_x_request_metas]
    apps = [L7AppMeta(nam) for nam in new_app_metas]

    # 对每一种关联类型，标记 flow 两两之间是通过什么关系关联上的，打上标记
    for x_request in xrequests:
        if x_request.x_request_id_0:
            x_req_ids = x_req_1_to_ids[x_request.x_request_id_0]
            x_request.set_relate(x_req_ids, related_map, id_to_related_tag)
        if x_request.x_request_id_1:
            x_req_ids = x_req_0_to_ids[x_request.x_request_id_1]
            x_request.set_relate(x_req_ids, related_map, id_to_related_tag)

    for syscall in syscalls:
        if syscall.syscall_trace_id_request:
            syscall_req_ids = syscall_req_to_ids[
                syscall.syscall_trace_id_request]
            syscall_resp_ids = syscall_resp_to_ids[
                syscall.syscall_trace_id_request]
            syscall_ids = syscall_req_ids | syscall_resp_ids
            syscall.set_relate(syscall_ids, related_map, id_to_related_tag)
        if syscall.syscall_trace_id_response:
            syscall_req_ids = syscall_req_to_ids[
                syscall.syscall_trace_id_response]
            syscall_resp_ids = syscall_resp_to_ids.get(
                syscall.syscall_trace_id_response)
            syscall_ids = syscall_req_ids | syscall_resp_ids
            syscall.set_relate(syscall_ids, related_map, id_to_related_tag)

    for network in networks:
        if network.req_tcp_seq:
            network_ids = req_tcp_seq_to_ids[network.req_tcp_seq]
            network.set_relate(network_ids, related_map, id_to_related_tag)
        if network.resp_tcp_seq:
            network_ids = resp_tcp_seq_to_ids[network.resp_tcp_seq]
            network.set_relate(network_ids, related_map, id_to_related_tag)

    for app in apps:
        if app.span_id:
            span_id_ids = span_id_to_ids[app.span_id]
            parent_span_id_ids = parent_span_id_to_ids[app.span_id]
            span_ids = span_id_ids | parent_span_id_ids
            app.set_relate(span_ids, related_map, id_to_related_tag)
        if app.parent_span_id:
            span_ids = span_id_to_ids[app.parent_span_id]
            app.set_relate(span_ids, related_map, id_to_related_tag)


class L7XrequestMeta:
    """
    x_request_id追踪：
    """
    def __init__(self, flow_metas: Tuple):
        self._id = flow_metas[0]
        self.x_request_id_0 = flow_metas[1]
        self.x_request_id_1 = flow_metas[2]

    def __eq__(self, rhs):
        return (self.x_request_id_0 == rhs.x_request_id_0
                and self.x_request_id_1 == rhs.x_request_id_1)

    def set_relate(self, _ids, related_map, id_to_related_tag):
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
        for _id in _ids:
            _id_df = id_to_related_tag[_id]['_id']
            x_request_id_0_df = id_to_related_tag[_id]['x_request_id_0']
            x_request_id_1_df = id_to_related_tag[_id]['x_request_id_1']
            if _id_df == self._id:
                continue
            # x_request_id_0 语义是 x_request_id_req，x_request_id_1 语义是 x_request_id_resp
            # x_request_id_0 == x_request_id_1 实际上是标注网关内部的关联关系，把跨进程/线程的请求/响应关联
            # 由于先发生【被请求】，再发生【转发】，所以 x_request_id_1 一定在 x_request_id_0 之上
            if self.x_request_id_0 and self.x_request_id_0 == x_request_id_1_df:
                related_map[_id_df][self._id] = related_map[_id_df].get(
                    self._id, set())
                related_map[_id_df][self._id].add('xrequestid')
            if self.x_request_id_1 and self.x_request_id_1 == x_request_id_0_df:
                related_map[_id_df][self._id] = related_map[_id_df].get(
                    self._id, set())
                related_map[_id_df][self._id].add('xrequestid')


class L7NetworkMeta:
    """
    网络流量追踪信息:
    { _id, type, req_tcp_seq, resp_tcp_seq, start_time_us, end_time_us, span_id, network_delay_us }
    """
    def __init__(self, flow_metas: Tuple, network_delay_us: int):
        self._id = flow_metas[0]
        self.type = flow_metas[1]
        self.req_tcp_seq = flow_metas[2]
        self.resp_tcp_seq = flow_metas[3]
        self.start_time_us = flow_metas[4]
        self.end_time_us = flow_metas[5]
        self.span_id = flow_metas[6] if flow_metas[6] else ''
        self.network_delay_us = network_delay_us

    def __eq__(self, rhs):
        return (self.type == rhs.type and self.req_tcp_seq == rhs.req_tcp_seq
                and self.resp_tcp_seq == rhs.resp_tcp_seq)

    def set_relate(self, _ids, related_map, id_to_related_tag):
        """
        使用 tcp_seq 标记穿越不同网元的关联关系
             req_tcp_seq_1 ┌──────┐req_tcp_seq_1 ┌─────┐
             ─────────────>│      │─────────────>│     │
        user               │ Node │              │ Pod │
             <─────────────│      │<─────────────│     │
            resp_tcp_seq_2 └──────┘resp_tcp_seq_2└─────┘
        """
        for _id in _ids:
            _id_df = id_to_related_tag[_id]['_id']
            type_df = id_to_related_tag[_id]['type']
            span_id_df = id_to_related_tag[_id]['span_id']
            start_time_us_df = id_to_related_tag[_id]['start_time_us']
            end_time_us_df = id_to_related_tag[_id]['end_time_us']
            req_tcp_seq_df = id_to_related_tag[_id]['req_tcp_seq']
            resp_tcp_seq_df = id_to_related_tag[_id]['resp_tcp_seq']
            if _id_df == self._id:
                continue
            if type_df != L7_FLOW_TYPE_RESPONSE and self.type != L7_FLOW_TYPE_RESPONSE and span_id_df:
                if span_id_df != self.span_id:
                    continue
            # network_delay_us 用于判断网络流两两之间的时差不应大于【一定值】，否则认为超出追踪范围，在后续逻辑中会无法加入 related_map 而被丢弃
            # 当两个 Span 两侧的 TCP Seq 都有值时，他们必须同时相等
            # 当某个 Span 只有一侧 TCP Seq 有值时，只要求一侧相等
            if self.req_tcp_seq and self.resp_tcp_seq and req_tcp_seq_df and resp_tcp_seq_df:
                if abs(self.start_time_us -
                       start_time_us_df) <= self.network_delay_us and abs(
                           self.end_time_us -
                           end_time_us_df) <= self.network_delay_us:
                    if self.req_tcp_seq == req_tcp_seq_df and self.resp_tcp_seq == resp_tcp_seq_df:
                        related_map[_id_df][
                            self._id] = related_map[_id_df].get(
                                self._id, set())
                        related_map[_id_df][self._id].add('network')
            elif self.req_tcp_seq and req_tcp_seq_df:
                if abs(self.start_time_us -
                       start_time_us_df) <= self.network_delay_us:
                    if self.req_tcp_seq == req_tcp_seq_df:
                        related_map[_id_df][
                            self._id] = related_map[_id_df].get(
                                self._id, set())
                        related_map[_id_df][self._id].add('network')
            elif self.resp_tcp_seq and resp_tcp_seq_df:
                if abs(self.end_time_us -
                       end_time_us_df) <= self.network_delay_us:
                    if self.resp_tcp_seq == resp_tcp_seq_df:
                        related_map[_id_df][
                            self._id] = related_map[_id_df].get(
                                self._id, set())
                        related_map[_id_df][self._id].add('network')


class L7SyscallMeta:
    """
    系统调用追踪信息:
    { vtap_id, syscall_trace_id_request, syscall_trace_id_response, tap_side, start_time_us, end_time_us }
    """
    def __init__(self, flow_metas: Tuple):
        self._id = flow_metas[0]
        self.vtap_id = flow_metas[1]
        self.syscall_trace_id_request = flow_metas[2]
        self.syscall_trace_id_response = flow_metas[3]

    def __eq__(self, rhs):
        return (self.vtap_id == rhs.vtap_id and self.syscall_trace_id_request
                == rhs.syscall_trace_id_request
                and self.syscall_trace_id_response
                == rhs.syscall_trace_id_response)

    def set_relate(self, _ids, related_map, id_to_related_tag):
        """
        syscall_trace_id_x 关联关系连接同一个线程内出入请求
        ┌─────┐ syscall_trace_id_request  ┌─────────┐ syscall_trace_id_request  ┌───────┐
        │     │ ──────────────────────────│─>1   1─>│───────────────────────────│->2    │
        │ Req │                           │   Pod1  |                           │  Pod2 │
        │     │ <─────────────────────────│<─3   3<─│───────────────────────────│<─2    │
        └─────┘ syscall_trace_id_response └─────────┘ syscall_trace_id_response └───────┘
        """
        # 对于 syscall_trace_id_request：
        # 在 Pod1 的关联是 syscall_trace_id_request_1 = syscall_trace_id_request_1
        # 在 Pod2 的关联是 syscall_trace_id_request_2 = syscall_trace_id_response_2
        # 同时，在 Pod1 也有 syscall_trace_id_response_3 = syscall_trace_id_response_3
        # 也即同时存在内部追踪关系与 ID 跨越服务不变性
        for _id in _ids:
            _id_df = id_to_related_tag[_id]['_id']
            vtap_id_df = id_to_related_tag[_id]['vtap_id']
            syscall_trace_id_request_df = id_to_related_tag[_id][
                'syscall_trace_id_request']
            syscall_trace_id_response_df = id_to_related_tag[_id][
                'syscall_trace_id_response']
            if _id_df == self._id or self.vtap_id != vtap_id_df:
                continue
            if self.syscall_trace_id_request > 0:
                if self.syscall_trace_id_request == syscall_trace_id_request_df or self.syscall_trace_id_request == syscall_trace_id_response_df:
                    related_map[_id_df][self._id] = related_map[_id_df].get(
                        self._id, set())
                    related_map[_id_df][self._id].add('syscall')
            if self.syscall_trace_id_response > 0:
                if self.syscall_trace_id_response == syscall_trace_id_request_df or self.syscall_trace_id_response == syscall_trace_id_response_df:
                    related_map[_id_df][self._id] = related_map[_id_df].get(
                        self._id, set())
                    related_map[_id_df][self._id].add('syscall')


class L7AppMeta:
    """
    应用插桩的追踪信息:
    { span_id, parent_span_id }
    """
    def __init__(self, flow_metas: Tuple):
        self._id = flow_metas[0]
        self.tap_side = flow_metas[1]
        self.span_id = flow_metas[2]
        self.parent_span_id = flow_metas[3]

    def __eq__(self, rhs):
        return (self.tap_side == rhs.tap_side and self.span_id == rhs.span_id
                and self.parent_span_id == rhs.parent_span_id)

    def set_relate(self, _ids, related_map, id_to_related_tag):
        """
        app-span 通过 trace_id/span_id 关联 span，其中，上游的 span_id 到达下游服务后会成为下游服务发起请求的 parent_span_id
                  ┌─────┐ span_id => parent_span_id ┌────────┐ span_id => parent_span_id ┌────────┐
                  │     │ ─────────────────────────>│        │ ─────────────────────────>│        │
        trace_id ─|─Req─| ──────────────────────────│─-Pod1-─| ──────────────────────────│─-Pod2-─│──────> trace_id
                  │     │                           │        │                           │        │
                  └─────┘                           └────────┘                           └────────┘
        """
        for _id in _ids:
            _id_df = id_to_related_tag[_id]['_id']
            span_id_df = id_to_related_tag[_id]['span_id']
            parent_span_id_df = id_to_related_tag[_id]['parent_span_id']
            if _id_df == self._id:
                continue
            if self.span_id:
                if self.span_id == span_id_df or self.span_id == parent_span_id_df:
                    related_map[_id_df][self._id] = related_map[_id_df].get(
                        self._id, set())
                    related_map[_id_df][self._id].add('app')
            if self.parent_span_id:
                if self.parent_span_id == span_id_df:
                    related_map[_id_df][self._id] = related_map[_id_df].get(
                        self._id, set())
                    related_map[_id_df][self._id].add('app')


class Networks:
    def __init__(self):
        # 标识 tcp_seq 用于匹配 sys-span 与 net-span
        self.req_tcp_seq = None
        self.resp_tcp_seq = None
        # 标识 span_id 用于匹配 app-span
        self.span_id = None
        # 标识是否已找到了 sys-span，如果有则不需要关联 app-span，优先设置为 sys-span 的 parent/child
        self.has_syscall = False
        # 存储所有 MERGE_KEYS 数据，用于匹配另一个 flow 是否完全一致
        self.metas = {}
        # 分组聚合所有 tcp_seq 相同的 flow
        self.flows = []
        # time_us 用于判断合并的流是否超出流时差
        self.start_time_us = None
        self.end_time_us = None

    def add_flow(self, flow, network_delay_us):
        """
        将 net-span 与 sys-span 按 tcp_seq 分组
        """
        if self.flows:
            if self.req_tcp_seq and flow["req_tcp_seq"] and (
                    self.req_tcp_seq != flow["req_tcp_seq"]):
                # 如果 req_tcp_seq 不相等，只允许【flow 是响应，且没有合并请求的 tcp_seq】这种场景，否则返回
                return False
            if self.resp_tcp_seq and flow["resp_tcp_seq"] and (
                    self.resp_tcp_seq != flow["resp_tcp_seq"]):
                # 如果 resp_tcp_seq 不相等，只允许【flow 是请求，且没有合并响应的 tcp_seq】这种场景
                return False

            # One has only req_tcp_seq, the other has only resp_tcp_seq
            for key in MERGE_KEYS:
                if not flow["req_tcp_seq"] or not self.req_tcp_seq: # no request in self.flows or flow
                    if key in MERGE_KEY_REQUEST:  # skip keys only for requsest
                        continue
                if not flow["resp_tcp_seq"] or not self.resp_tcp_seq:  # no response in self.flows or flow
                    if key in MERGE_KEY_RESPONSE:  # skip keys only for response
                        continue
                if self.get(key) and flow.get(key):
                    # agent 有可能协议识别有误，没将 http2 识别为 grpc，此处忽略这个差异，不要返回
                    # 虽然 http2 不仅仅只有 grpc 一种实现，但如果两个流只有 l7_protocol 协议不一致而其他值都一致，则仍然认为是同一个流
                    if key == 'l7_protocol' and self.get(key) in [
                            L7_PROTOCOL_HTTP2, L7_PROTOCOL_GRPC
                    ] and flow.get(key) in [L7_PROTOCOL_HTTP2, L7_PROTOCOL_GRPC]:
                        continue
                    # 如果 self/flow 的 merge_keys 任意一个不相等，应直接返回
                    if self.get(key) != flow.get(key):
                        return False

            # 如果超出流时差，暂时判断为无关系，可能有以下原因:
            # 可能是 tcp_seq 重复
            # 可能是 L4 网关与应用所在宿主机时间差异太大，明明是同一个请求但采集时间相差过远
            if abs(self.start_time_us -
                   flow["start_time_us"]) > network_delay_us or abs(
                       self.end_time_us -
                       flow["end_time_us"]) > network_delay_us:
                return False
        if not self.req_tcp_seq and flow["req_tcp_seq"]:
            self.req_tcp_seq = flow["req_tcp_seq"]
        if not self.resp_tcp_seq and flow["resp_tcp_seq"]:
            self.resp_tcp_seq = flow["resp_tcp_seq"]
        for key in MERGE_KEYS:
            if not self.get(key) and flow.get(key):
                self.metas[key] = flow[key]
        if not self.start_time_us:
            self.start_time_us = flow["start_time_us"]
        if not self.end_time_us:
            self.end_time_us = flow["end_time_us"]
        if not self.span_id and flow["span_id"]:
            self.span_id = flow["span_id"]
        self.flows.append(flow)
        if flow["tap_side"] in [
                TAP_SIDE_SERVER_PROCESS, TAP_SIDE_CLIENT_PROCESS
        ]:
            # 标识 self 根据 tcp_seq 找到了对应的 sys-span
            # 对 s/s-nd，需要找 s-p，对 c/c-nd 需要找 c-p
            self.has_syscall = True
            # self 不一定是 net-span，外层的调用是 net-span + sys-span 组成的列表
            flow["networks"] = self
        return True

    def get(self, key):
        if type(self.metas.get(key, None)) == float:
            if math.isnan(self.metas[key]):
                return None
        return self.metas.get(key, None)

    def sort_and_set_parent(self):
        self.flows = network_flow_sort(self.flows)
        self.flows.reverse()
        for i, _ in enumerate(self.flows):
            if i + 1 >= len(self.flows):
                break
            # 某些情况下，可能会有两个 SYS Span 拥有同样的 TCP Seq，此类情况一般是由于 eBPF 内核适配不完善导致。
            # 例如：self.flows 数组中可能包含两个 c-p Span（拥有同样的 TCP Seq）、多个 net Span、一个 s-p Span，开头两个 c-p Span 实际上没有父子关系。
            # 这里做一个简单的处理，当相邻两个 Span 都是 SYS Span 时不要按照 TCP Seq 来设置他们的 Parent 关系。
            if self.flows[i]["tap_side"] in [
                    TAP_SIDE_SERVER_PROCESS, TAP_SIDE_CLIENT_PROCESS
                    ] and self.flows[i + 1]["tap_side"] in [
                            TAP_SIDE_SERVER_PROCESS, TAP_SIDE_CLIENT_PROCESS]:
                continue
            _set_parent(self.flows[i], self.flows[i + 1],
                        "trace mounted due to tcp_seq")
        self.flows.reverse()


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
    只有一个请求和一个响应能合并，不能合并多个请求或多个响应；
    按如下策略合并：
    按start_time递增的顺序从前向后扫描，每发现一个请求，都找一个它后面离他最近的响应。
    例如：请求1、请求2、响应1、响应2
    则请求1和响应1配对，请求2和响应2配对

    对 net-span: 合并未被 agent 合并的请求-响应
    对 sys-span: 同上，外加会话+响应可能会合并为一个 span，原因：
    系统Span的flow合并场景：
    一次 DNS 请求会触发多次 DNS 应答，其中第一个请求和应答被聚合为一个类型为会话的 Flow，
    后续的应答被聚合为类型为响应的 Flow，这些 Flow 需要最终被聚合为 Span，
    合并条件为：会话的cap_seq_1 == 响应的cap_seq_1 + 1
    System Span's flow merging scenario:
    One DNS request triggers multiple DNS responses, where the first request and response are aggregated into a flow of type session.
    Subsequent responses are aggregated into flows of type response, which need to be eventually aggregated into spans.
    Merge condition: Session cap_seq_1 == Response cap_seq_1 + 1
    """
    if flow['type'] == L7_FLOW_TYPE_SESSION \
        and flow['tap_side'] not in [TAP_SIDE_SERVER_PROCESS, TAP_SIDE_CLIENT_PROCESS]:
        return False
    # vtap_id, l7_protocol, flow_id, request_id
    for i in range(len(flows)):
        if flow['_id'] == flows[i]['_id']:
            continue
        if flow['flow_id'] != flows[i]['flow_id']:
            continue
        if flows[i]['tap_side'] not in [
                TAP_SIDE_SERVER_PROCESS, TAP_SIDE_CLIENT_PROCESS
        ]:
            if flows[i]['type'] == L7_FLOW_TYPE_SESSION:
                continue
            # 每条flow的_id最多只有一来一回两条
            # 当 len(flows[i]['_id']) > 1 表明可能已被合并
            if len(flows[i]['_id']) > 1 or flow["type"] == flows[i]["type"]:
                continue
        equal = True
        request_flow = None
        response_flow = None
        if flows[i]['type'] == L7_FLOW_TYPE_REQUEST:
            request_flow = flows[i]
            response_flow = flow
        elif flows[i]['type'] == L7_FLOW_TYPE_RESPONSE:
            request_flow = flow
            response_flow = flows[i]
        else:  # for DNS sys span
            if flow['type'] == L7_FLOW_TYPE_REQUEST:
                request_flow = flow
                response_flow = flows[i]
            elif flow['type'] == L7_FLOW_TYPE_RESPONSE:
                request_flow = flows[i]
                response_flow = flow
            else:
                continue
        if not request_flow or not response_flow:
            continue

        for key in [
                'vtap_id', 'tap_port', 'tap_port_type', 'l7_protocol',
                'request_id', 'tap_side'
        ]:
            if _get_df_key(request_flow, key) != _get_df_key(
                    response_flow, key):
                # 不合并1: 上述 key 不一致，说明不是一个会话内
                equal = False
                break
        if request_flow['start_time_us'] > response_flow['end_time_us']:
            # 不合并2: 请求的时间比响应的时间大，说明响应不对应此请求
            equal = False
        if request_flow['tap_side'] in [
                TAP_SIDE_SERVER_PROCESS, TAP_SIDE_CLIENT_PROCESS
        ] and request_flow['l7_protocol'] == L7_PROTOCOL_DNS:
            # 应用span syscall_cap_seq判断合并
            if request_flow['syscall_cap_seq_1'] + 1 != response_flow[
                    'syscall_cap_seq_1'] or not (
                        request_flow['type'] == L7_FLOW_TYPE_SESSION
                        and response_flow['type'] == L7_FLOW_TYPE_RESPONSE):
                # 不合并3: 对 sys-span 当协议为 dns 协议且当 request_flow 是会话时，response_flow 只合并响应
                # syscall_cap_seq 会在 agent 标记正确的请求-响应顺序，cap_seq+1 可找到“后续”的一条流，
                # 如果 request_flow 的 cap_seq_1+1 不匹配 response_flow 的 cap_seq_1，说明响应不对应此请求
                equal = False

        if equal:  # 合并字段
            # FIXME 确认要合并哪些字段

            flows[i]['_id'].extend(flow['_id'])
            flows[i]['auto_instance_0'] = flow['auto_instance_0']
            flows[i]['auto_instance_1'] = flow['auto_instance_1']
            flows[i]['auto_service_0'] = flow['auto_service_0']
            flows[i]['auto_service_1'] = flow['auto_service_1']
            for key in MERGE_KEYS:
                if key in MERGE_KEY_REQUEST:
                    if flow['req_tcp_seq']:  # flow has request
                        flows[i][key] = flow[key]
                elif key in MERGE_KEY_RESPONSE:
                    if flow['resp_tcp_seq']:  # flow has response
                        flows[i][key] = flow[key]
                else:
                    if not flows[i][key]:
                        flows[i][key] = flow[key]
            if flow['req_tcp_seq']:  # flow is request or session
                # flows[i] has no request
                if not flows[i]['req_tcp_seq']:
                    flows[i]['start_time_us'] = flow['start_time_us']
                    flows[i]['req_tcp_seq'] = flow['req_tcp_seq']
                    flows[i]['syscall_cap_seq_0'] = flow['syscall_cap_seq_0']
            if flow['resp_tcp_seq']:  # flow is response or session
                # case #1: flows[i] has no response
                # case #2: for DNS sys span, a session (flows[i]) can be merged with a consequence response (flow)
                # Note: We could omit the judgment condition for #1, since it is covered by the condition for #2.
                #       However, we have kept all the conditions for the sake of clarity.
                if not flows[i]['resp_tcp_seq'] or flows[i]['end_time_us'] < flow['end_time_us']:
                    flows[i]['end_time_us'] = flow['end_time_us']
                    flows[i]['resp_tcp_seq'] = flow['resp_tcp_seq']
                    flows[i]['syscall_cap_seq_1'] = flow['syscall_cap_seq_1']

            # request response合并后type改为session
            if flow['type'] + flows[i]['type'] == 1:
                # L7_FLOW_TYPE_REQUEST(0) + L7_FLOW_TYPE_RESPONSE(1) = 1
                flows[i]['type'] = L7_FLOW_TYPE_SESSION
            else:
                flows[i]['type'] = max(flows[i]['type'], flow['type'])

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
    id_map = {}
    # 按start_time升序，用于merge_flow
    dict_flows = dataframe_flows.sort_values(by=["start_time_us"],
                                             ascending=True).to_dict("list")
    for index in range(len(dataframe_flows.index)):
        flow = {}
        for key in return_fields:
            key = key.strip("'")
            if key == '_id':  # 流合并后会对应多条记录
                flow[key] = [dict_flows[key][index]]
            else:
                flow[key] = dict_flows[key][index]
        if merge_flow(flows, flow):  # 合并单向Flow为会话
            continue
        # assert '_uid' not in flow
        flow['_uid'] = index
        flows.append(flow)
    flowcount = len(flows)
    # FIXME: 此处暂时不清楚场景，先别去掉
    for i, flow in enumerate(reversed(flows)):
        # 单向的c-p和s-p进行第二轮merge
        if len(flow['_id']) > 1 or flow['tap_side'] not in [
                TAP_SIDE_SERVER_PROCESS, TAP_SIDE_CLIENT_PROCESS
        ]:
            continue
        if merge_flow(flows, flow):
            del flows[flowcount - i - 1]
    network_flows = []
    app_flows = []
    syscall_flows = []
    # 对 flow 分类，而后分别做排序，方便做层级处理
    # 对 network_flows: net-span 的排序按固定的顺序（TAP_SIDE_RANKS），然后根据 span_id 挂 app-span，根据 tcp_seq 挂 sys-span
    # 对 network_flows local/rest/xx_gw 位置或非虚拟网络的 net-span，需要按照响应时延倒序，见 `network_flow_sort` 中 response_duration_sort 逻辑
    # 对 app_flows: app-span 按固定的规则设置层级（span_id/parent_span_id），按 span_id 挂 sys-span 以及挂到 sys-span 构建的 <service> 上
    # 对 syscall_flows: sys-span 需要提取<vtap_id, local_process_id>分组定义为<service> ，并以此为主体构建火焰图骨架
    for flow in flows:
        for _id in flow['_id']:
            id_map[str(_id)] = flow['_uid']
        flow['duration'] = flow['end_time_us'] - flow['start_time_us']
        if flow['tap_side'] in [
                TAP_SIDE_SERVER_PROCESS, TAP_SIDE_CLIENT_PROCESS
        ]:
            syscall_flows.append(flow)
        elif flow['tap_side'] in const.TAP_SIDE_RANKS:
            network_flows.append(flow)
        elif flow['tap_side'] in [
                TAP_SIDE_CLIENT_APP, TAP_SIDE_SERVER_APP, TAP_SIDE_APP
        ]:
            app_flows.append(flow)
    for flow in flows:
        related_ids = set()
        for _id, related_types in flow["related_ids"].items():
            if _id in flow['_id']:
                # flow['_id'] 包含 _id，在上面逻辑中已被合并，此处无需处理自身
                continue
            if id_map.get(_id, None) is not None:
                related_ids.add(
                    f"{id_map[_id]}-{','.join(related_types)}-{_id}")
        flow["related_ids"] = list(related_ids)

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
    for flow in network_flows:
        if not flow["req_tcp_seq"] and not flow["resp_tcp_seq"]:
            continue
        is_add = False
        for network in networks:
            if network.add_flow(flow, network_delay_us):
                is_add = True
        if not is_add:
            network = Networks()
            network.add_flow(flow, network_delay_us)
            networks.append(network)

    # 将应用span挂到Service上
    for index, app_flow in enumerate(app_flows):
        for service_key, service in service_map.items():
            if service.attach_app_flow(app_flow):
                break
    app_flow_set_service(app_flows)
    # 获取没有系统span存在的networks分组
    net_spanid_flows = defaultdict(list)
    for network in networks:
        if not network.has_syscall and network.span_id:
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
    return services, app_flows, networks


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


def networks_set_to_app_fow(array, network_flows):
    """
    设置 net-span 与 app-span 的层级关系
    """
    array.reverse()
    for flow in array:
        # 2. 存在span_id相同的应用span，将该网络span的parent设置为该span_id相同的应用span
        if flow["span_id"] in network_flows:
            _set_parent(network_flows[flow["span_id"]].flows[0], flow,
                        "network mounted duo to span_id")
            flow["network_flows"] = network_flows[flow["span_id"]]
    array.reverse()


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
                '_uid']] = f"{direct_flow_span_id}.{flow['tap_side']}.{flow['_uid']}"
            if flow['_uid'] not in tracing:
                response["tracing"].append(_get_flow_dict(flow))
                tracing.add(flow['_uid'])
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
                '_uid']] = f"{network.span_id}.{flow['tap_side']}.{flow['_uid']}"
            if flow['_uid'] not in tracing:
                response["tracing"].append(_get_flow_dict(flow))
                tracing.add(flow['_uid'])

    for flow in app_flows:
        id_map[flow["_uid"]] = flow["span_id"]
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


# Obtain traces after pruning
def get_tree(_id, remain_trees, network_delay_us):
    trees = []
    tree_ids = []
    new_remain_trees = []
    root_start_time_us = 0
    root_end_time_us = 0
    # 当出现多棵树的时候，先按遍历顺序随机选取一棵树作为 root 来做后续判断
    for trace in remain_trees:
        trace_start_time_us = trace.get('start_time_us', 0)
        trace_end_time_us = trace.get('end_time_us', 0)
        if not root_start_time_us:
            root_start_time_us = trace_start_time_us
        if not root_end_time_us:
            root_end_time_us = trace_end_time_us
        _ids = trace.get('_ids', [])
        # 遍历其他的树，如果其他树和 root 的时间范围有交叠（流时差范围内），不被剪枝
        if trace_start_time_us - network_delay_us <= root_end_time_us and trace_end_time_us + network_delay_us >= root_start_time_us:
            trees.append(trace)
            tree_ids.extend(_ids)
        else:
            # 此处被剪枝
            new_remain_trees.append(trace)
    if _id not in tree_ids and new_remain_trees:
        # 如果入口点击的 _id 不在保留的树内，那就一定在被剪枝的树内，说明与 root 相关的树不是求值结果，这里反转以被剪枝的树作为主体重新求值
        # FIXME: 有可能被 append 到 `trees` 里的树和 `new_remain_trees` 也有交叠，此时可能剪多了，应该要回溯检查
        return get_tree(_id, new_remain_trees, network_delay_us)
    else:
        return trees


def pruning_trace(response, _id, network_delay_us):
    """
    剪枝
    """
    traces = response.get('tracing', [])
    response['tracing'] = get_tree(_id, traces, network_delay_us)


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
            trace = id_to_trace_map.get(flow.get('_uid'))
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
        if flow.get('_uid') not in ids:
            continue
        trace = id_to_trace_map.get(flow.get('_uid'))
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


def format(services, networks, app_flows, _id, network_delay_us):
    response = format_trace(services, networks, app_flows)
    pruning_trace(response, _id, network_delay_us)
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
        self.sorted_indexs = []

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
        "_ids":
        list(map(str, flow["_id"])),
        "related_ids":
        flow["related_ids"],
        "start_time_us":
        flow["start_time_us"],
        "end_time_us":
        flow["end_time_us"],
        "duration":
        flow["end_time_us"] - flow["start_time_us"],
        "selftime":
        flow["duration"],
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
        "id":
        flow["_uid"],
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
        flow["resource_from_vtap"][2]
        if flow["resource_from_vtap"][0] else None,
        "set_parent_info":
        flow.get("set_parent_info"),
        "auto_instance":
        flow["auto_instance_0"] if flow["tap_side"][0] == 'c'
        and flow["tap_side"] != "app" else flow["auto_instance_1"],
        "tap_id":
        flow.get("tap_id", None),
        "tap":
        flow.get("tap", None)
    }
    if flow["tap_side"] in [TAP_SIDE_SERVER_PROCESS, TAP_SIDE_CLIENT_PROCESS]:
        flow_dict["subnet"] = flow.get("subnet")
        flow_dict["ip"] = flow.get("ip")
        flow_dict["auto_service"] = flow.get("auto_service")
        flow_dict["auto_service_id"] = flow.get("auto_service_id")
        flow_dict["process_kname"] = flow.get("process_kname")
    return flow_dict


def _get_df_key(df: DataFrame, key: str):
    if type(df[key]) == float:
        if math.isnan(df[key]):
            return None
    return df[key]


def _set_parent(flow, flow_parent, info=None):
    flow['parent_id'] = flow_parent['_uid']
    if flow_parent.get("childs"):
        flow_parent["childs"].append(flow['_uid'])
    else:
        flow_parent["childs"] = [flow['_uid']]
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
        if trace.get('_uid') == parent_trace.get('_uid'):
            continue
        if trace.get('x_request_id_0') == parent_trace.get('x_request_id_1'):
            # Avoid ring
            new_traces = [
                i for i in traces if i.get('_uid') != trace.get('_uid')
            ]
            # 递归，继续在 `traces` 里找到 `trace` 的子节点
            return get_parent_trace(trace, new_traces)
    else:
        return parent_trace


def sort_by_x_request_id(traces):
    for trace_0 in traces:
        if trace_0.get('parent_id', -1) < 0:
            parent_traces = []
            for trace_1 in traces:
                if trace_0.get('_uid') == trace_1.get('_uid'):
                    continue
                if not trace_1.get('x_request_id_1') or not trace_0.get(
                        'x_request_id_0'):
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
