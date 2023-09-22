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


class L7FlowTracing(Base):

    async def query(self):
        max_iteration = self.args.get("max_iteration", 30)
        network_delay_us = self.args.get("network_delay_us")
        ntp_delay_us = self.args.get("ntp_delay_us", 10000)
        self.failed_regions = set()
        time_filter = f"time>={self.start_time} AND time<={self.end_time}"
        _id = self.args.get("_id")
        self.has_attributes = self.args.get("has_attributes", 0)
        if not _id:
            trace_id = self.args.get("trace_id")
            _id = await self.get_id_by_trace_id(trace_id, time_filter)
            _id = str(_id)
            self.args._id = _id
        if not _id:
            return self.status, {}, self.failed_regions
        base_filter = f"_id={_id}"
        rst = await self.trace_l7_flow(time_filter=time_filter,
                                       base_filter=base_filter,
                                       return_fields=["related_ids"],
                                       max_iteration=max_iteration,
                                       network_delay_us=network_delay_us,
                                       ntp_delay_us=ntp_delay_us)
        return self.status, rst, self.failed_regions

    async def get_id_by_trace_id(self, trace_id, time_filter):
        sql = f"SELECT toString(_id) AS `_id` FROM l7_flow_log WHERE trace_id='{trace_id}' AND {time_filter} limit 1"
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
                            max_iteration: int = 30,
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
        related_map = defaultdict(list)
        third_app_spans_all = []

        dataframe_flowmetas = await self.query_flowmetas(
            time_filter, base_filter)
        if type(dataframe_flowmetas) != DataFrame:
            return {}
        dataframe_flowmetas.rename(columns={'_id_str': '_id'}, inplace=True)
        related_map[dataframe_flowmetas['_id'][0]] = [
            f"{dataframe_flowmetas['_id'][0]}-base"
        ]
        trace_id = self.args.get("trace_id") if self.args.get(
            "trace_id") else ''
        allow_multiple_trace_ids_in_tracing_result = config.allow_multiple_trace_ids_in_tracing_result
        call_apm_api_to_supplement_trace = config.call_apm_api_to_supplement_trace
        multi_trace_ids = set()
        for i in range(max_iteration):
            if type(dataframe_flowmetas) != DataFrame:
                break
            filters = []

            # 主动注入的追踪信息
            if not allow_multiple_trace_ids_in_tracing_result:
                delete_index = []
                for index in range(len(dataframe_flowmetas.index)):
                    if dataframe_flowmetas['trace_id'][index] in [0, '']:
                        continue
                    if trace_id and trace_id != dataframe_flowmetas[
                            'trace_id'][index]:
                        delete_index.append(index)
                    if not trace_id:
                        trace_id = dataframe_flowmetas['trace_id'][index]
                if trace_id:
                    filters.append(f"trace_id='{trace_id}'")
                dataframe_flowmetas = dataframe_flowmetas.drop(delete_index)
                if call_apm_api_to_supplement_trace and trace_id not in multi_trace_ids:
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
                new_trace_ids = set()
                third_app_spans = []
                for index in range(len(dataframe_flowmetas.index)):
                    if dataframe_flowmetas['trace_id'][index] in [0, '']:
                        continue
                    apm_trace_id = dataframe_flowmetas['trace_id'][index]
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

                new_trace_ids -= trace_ids
                trace_ids |= new_trace_ids
                if new_trace_ids:
                    trace_ids_set = set([nxrid[1] for nxrid in new_trace_ids])
                    filters.append('(' + ' OR '.join([
                        "trace_id='{tid}'".format(tid=tid)
                        for tid in trace_ids_set
                    ]) + ')')

            # 新的网络追踪信息
            new_network_metas = set()
            for index in range(len(dataframe_flowmetas.index)):
                if dataframe_flowmetas['req_tcp_seq'][index] == 0 \
                    and dataframe_flowmetas['resp_tcp_seq'][index] == 0:
                    continue
                if dataframe_flowmetas['tap_side'][index] not in [
                        TAP_SIDE_CLIENT_PROCESS, TAP_SIDE_SERVER_PROCESS
                ] and dataframe_flowmetas['tap_side'][
                        index] not in const.TAP_SIDE_RANKS:
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
            if networks:
                networks_tuple_map = {
                    network.to_tuple(): network
                    for network in networks
                }
                networks_filters = '((' + ' OR '.join([
                    networks_tuple_map[nnm].to_sql_filter()
                    for nnm in set(list(networks_tuple_map.keys()))
                ]) + ')' + ' AND (resp_tcp_seq!=0 OR req_tcp_seq!=0))'
                filters.append(networks_filters)

            # 新的系统调用追踪信息
            new_syscall_metas = set()
            for index in range(len(dataframe_flowmetas.index)):
                if dataframe_flowmetas['syscall_trace_id_request'][index] > 0 or \
                    dataframe_flowmetas['syscall_trace_id_response'][index] > 0:
                    new_syscall_metas.add((
                        dataframe_flowmetas['_id'][index],
                        dataframe_flowmetas['vtap_id'][index],
                        dataframe_flowmetas['syscall_trace_id_request'][index],
                        dataframe_flowmetas['syscall_trace_id_response']
                        [index],
                        dataframe_flowmetas['tap_side'][index],
                        dataframe_flowmetas['start_time_us'][index],
                        dataframe_flowmetas['end_time_us'][index],
                    ))
            new_syscall_metas -= syscall_metas
            syscall_metas |= new_syscall_metas
            syscalls = [L7SyscallMeta(nsm) for nsm in new_syscall_metas]
            if syscalls:
                syscalls_tuple_map = {
                    syscall.to_tuple(): syscall
                    for syscall in syscalls
                }
                syscall_filters = '(' + ' OR '.join([
                    syscalls_tuple_map[nsm].to_sql_filter()
                    for nsm in set(list(syscalls_tuple_map.keys()))
                ]) + ')'
                filters.append(syscall_filters)

            # 新的应用span追踪信息
            new_app_metas = set()
            for index in range(len(dataframe_flowmetas.index)):
                if dataframe_flowmetas['tap_side'][index] not in [
                        TAP_SIDE_CLIENT_PROCESS, TAP_SIDE_SERVER_PROCESS,
                        TAP_SIDE_CLIENT_APP, TAP_SIDE_SERVER_APP, TAP_SIDE_APP
                ] or not dataframe_flowmetas['span_id'][index]:
                    continue
                if type(dataframe_flowmetas['span_id'][index]) == str and \
                    dataframe_flowmetas['span_id'][index] and \
                        type(dataframe_flowmetas['parent_span_id'][index]) == str and \
                            dataframe_flowmetas['parent_span_id'][index]:
                    new_app_metas.add(
                        (dataframe_flowmetas['_id'][index],
                         dataframe_flowmetas['tap_side'][index],
                         dataframe_flowmetas['span_id'][index],
                         dataframe_flowmetas['parent_span_id'][index]))
            new_app_metas -= app_metas
            app_metas |= new_app_metas
            apps = [L7AppMeta(nam) for nam in new_app_metas]
            if apps:
                apps_tuple_map = {app.to_tuple(): app for app in apps}
                app_filters = '(' + ' OR '.join([
                    apps_tuple_map[nam].to_sql_filter()
                    for nam in set(list(apps_tuple_map.keys()))
                ]) + ')'
                filters.append(app_filters)

            new_x_request_metas = set()
            for index in range(len(dataframe_flowmetas.index)):
                if dataframe_flowmetas['x_request_id_0'][index] in [
                        0, ''
                ] and dataframe_flowmetas['x_request_id_1'][index] in [0, '']:
                    continue
                new_x_request_metas.add(
                    (dataframe_flowmetas['_id'][index],
                     dataframe_flowmetas['x_request_id_0'][index],
                     dataframe_flowmetas['x_request_id_1'][index]))
            new_x_request_metas -= x_request_metas
            x_request_metas |= new_x_request_metas
            x_requests = [L7XrequestMeta(nxr) for nxr in new_x_request_metas]
            if x_requests:
                x_requests_tuple_map = {
                    x_request.to_tuple(): x_request
                    for x_request in x_requests
                }
                x_request_filters = '(' + ' OR '.join([
                    x_requests_tuple_map[xrm].to_sql_filter()
                    for xrm in set(list(x_requests_tuple_map.keys()))
                ]) + ')'
                filters.append(x_request_filters)

            # L7 Flow ID信息
            l7_flow_ids |= set(dataframe_flowmetas['_id'])
            len_of_flows = len(l7_flow_ids)

            if not filters:
                break

            if not allow_multiple_trace_ids_in_tracing_result and trace_id:
                new_filters = []
                new_filters.append(f"({'OR '.join(filters)})")
                new_filters.append(f"(trace_id='{trace_id}' OR trace_id='')")
                new_flows = await self.query_flowmetas(
                    time_filter, ' AND '.join(new_filters))
            else:
                new_flows = await self.query_flowmetas(time_filter,
                                                       ' OR '.join(filters))
            if type(new_flows) != DataFrame:
                break
            new_flows.rename(columns={'_id_str': '_id'}, inplace=True)

            if xrequests:
                for x_request in xrequests:
                    x_request.set_relate(new_flows, related_map)

            if syscalls:
                for syscall in syscalls:
                    syscall.set_relate(new_flows, related_map)

            if networks:
                for network in networks:
                    network.set_relate(new_flows, related_map)

            if apps:
                for app in apps:
                    app.set_relate(new_flows, related_map)
            dataframe_flowmetas = pd.concat([dataframe_flowmetas, new_flows],
                                            join="outer",
                                            ignore_index=True).drop_duplicates(
                                                ["_id"]).reset_index(drop=True)
            if len(set(dataframe_flowmetas['_id'])) - len_of_flows < 1:
                break
        if not l7_flow_ids:
            return {}
        # 获取追踪到的所有应用流日志
        return_fields += RETURN_FIELDS
        flow_fields = list(RETURN_FIELDS)
        if self.has_attributes:
            return_fields.append("attribute")
            flow_fields.append("attribute")
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
        for index in range(len(l7_flows.index)):
            l7_flows["related_ids"][index] = related_map[l7_flows._id[index]]
        # 对所有应用流日志排序
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
        sql = """
        SELECT 
        type, req_tcp_seq, resp_tcp_seq, toUnixTimestamp64Micro(start_time) AS start_time_us, toUnixTimestamp64Micro(end_time) AS end_time_us, 
        vtap_id, syscall_trace_id_request, syscall_trace_id_response, span_id, parent_span_id, l7_protocol, 
        trace_id, x_request_id_0, x_request_id_1, toString(_id) AS `_id_str`, tap_side, auto_instance_0, auto_instance_1
        FROM `l7_flow_log` 
        WHERE (({time_filter}) AND ({base_filter})) limit {l7_tracing_limit}
        """.format(time_filter=time_filter,
                   base_filter=base_filter,
                   l7_tracing_limit=config.l7_tracing_limit)
        response = await self.query_ck(sql)
        self.status.append("Query FlowMetas", response)
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

    def to_tuple(self):
        return (self.x_request_id_0, self.x_request_id_1)

    def set_relate(self, df, related_map):
        for i in range(len(df.index)):
            if df._id[i] == self._id:
                continue
            if type(self.x_request_id_0) == str and self.x_request_id_0:
                if self.x_request_id_0 == df.x_request_id_1[i]:
                    related_map[df._id[i]].append(
                        str(self._id) + "-xrequestid")
                    continue
            if type(self.x_request_id_1) == str and self.x_request_id_1:
                if self.x_request_id_1 == df.x_request_id_0[i]:
                    related_map[df._id[i]].append(
                        str(self._id) + "-xrequestid")
                    continue

    def to_sql_filter(self) -> str:
        # 返回空时需要忽略此条件
        sql_filters = []
        if type(self.x_request_id_0) == str and self.x_request_id_0:
            sql_filters.append(f"x_request_id_1='{self.x_request_id_0}'")
        if type(self.x_request_id_1) == str and self.x_request_id_1:
            sql_filters.append(f"x_request_id_0='{self.x_request_id_1}'")
        if not sql_filters:
            return '1!=1'
        # filter time range to prune
        sql = f"{' OR '.join(sql_filters)}"
        return f"({sql})"


class L7AppMeta:
    """
    应用span追踪：
        span_id, parent_span_id
    """

    def __init__(self, flow_metas: Tuple):
        self._id = flow_metas[0]
        self.tap_side = flow_metas[1]
        self.span_id = flow_metas[2]
        self.parent_span_id = flow_metas[3]

    def __eq__(self, rhs):
        return (self.tap_side == rhs.tap_side and self.span_id == rhs.span_id
                and self.parent_span_id == rhs.parent_span_id)

    def to_tuple(self):
        return (self.tap_side, self.span_id, self.parent_span_id)

    def set_relate(self, df, related_map):
        for i in range(len(df.index)):
            if df._id[i] == self._id:
                continue
            if type(self.span_id) == str and self.span_id:
                if self.span_id == df.span_id[
                        i] or self.span_id == df.parent_span_id[i]:
                    related_map[df._id[i]].append(str(self._id) + "-app")
                    continue
            if type(self.parent_span_id) == str and self.parent_span_id:
                if self.parent_span_id == df.span_id[
                        i] or self.parent_span_id == df.parent_span_id[i]:
                    related_map[df._id[i]].append(str(self._id) + "-app")
                    continue

    def to_sql_filter(self) -> str:
        sql_filters = []
        if type(self.span_id) == str and self.span_id:
            sql_filters.append(
                f"""(parent_span_id='{self.span_id}' OR span_id='{self.span_id}')"""
            )
        if type(self.parent_span_id) == str and self.parent_span_id:
            sql_filters.append(
                f"""(span_id='{self.parent_span_id}' OR parent_span_id='{self.parent_span_id}')"""
            )
        if not sql_filters:
            return '1!=1'
        return '(' + ' OR '.join(sql_filters) + ')'


class L7NetworkMeta:
    """
    网络流量追踪信息:
        req_tcp_seq, resp_tcp_seq, start_time_us, end_time_us
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

    def to_tuple(self):
        return (self.type, self.req_tcp_seq, self.resp_tcp_seq)

    def set_relate(self, df, related_map):
        for i in range(len(df.index)):
            if df._id[i] == self._id:
                continue
            if df.type[i] != L7_FLOW_TYPE_RESPONSE and type(
                    self.span_id
            ) == str and self.type != L7_FLOW_TYPE_RESPONSE and type(
                    df.span_id[i]) == str and df.span_id[i]:
                if df.span_id[i] != self.span_id:
                    continue
            if self.type != L7_FLOW_TYPE_RESPONSE and self.req_tcp_seq > 0:
                if abs(self.start_time_us -
                       df.start_time_us[i]) <= self.network_delay_us:
                    if self.req_tcp_seq == df.req_tcp_seq[i]:
                        related_map[df._id[i]].append(
                            str(self._id) + "-network")
                        continue
            if self.type != L7_FLOW_TYPE_REQUEST and self.resp_tcp_seq > 0:
                if abs(self.end_time_us -
                       df.end_time_us[i]) <= self.network_delay_us:
                    if self.resp_tcp_seq == df.resp_tcp_seq[i]:
                        related_map[df._id[i]].append(
                            str(self._id) + "-network")
                        continue

    def to_sql_filter(self) -> str:
        # 返回空时需要忽略此条件
        # 由于会话可能没有合并，有一侧的seq可以是零（数据不会存在两侧同时为0的情况）
        # 考虑到网络传输时延，时间需要增加一个delay
        sql_filters = []
        if self.type == L7_FLOW_TYPE_SESSION and self.req_tcp_seq > 0 and self.resp_tcp_seq > 0:
            sql_filters.append(
                f"""((req_tcp_seq={self.req_tcp_seq} AND resp_tcp_seq={self.resp_tcp_seq}) OR (req_tcp_seq={self.req_tcp_seq} AND type=0) OR (type=1 AND resp_tcp_seq={self.resp_tcp_seq}))"""
            )
        elif self.type == L7_FLOW_TYPE_REQUEST and self.req_tcp_seq > 0:
            sql_filters.append("""(req_tcp_seq={req_tcp_seq})""".format(
                req_tcp_seq=self.req_tcp_seq))
        elif self.type == L7_FLOW_TYPE_RESPONSE and self.resp_tcp_seq > 0:
            sql_filters.append("""(resp_tcp_seq={resp_tcp_seq})""".format(
                resp_tcp_seq=self.resp_tcp_seq))
        if not sql_filters:
            return '1!=1'

        sql = '(' + ' OR '.join(sql_filters) + ')'
        tailor_sql = ""
        if self.type != L7_FLOW_TYPE_RESPONSE:
            if type(self.span_id) == str and self.span_id:
                tailor_sql += f" AND (span_id='{self.span_id}' OR type=1 OR span_id='')"
        if tailor_sql:
            sql = f"({sql} {tailor_sql})"
        return sql


class L7SyscallMeta:
    """
    系统调用追踪信息:
        vtap_id, syscall_trace_id_request, syscall_trace_id_response, tap_side, start_time_us, end_time_us
    """

    def __init__(self, flow_metas: Tuple):
        self._id = flow_metas[0]
        self.vtap_id = flow_metas[1]
        self.syscall_trace_id_request = flow_metas[2]
        self.syscall_trace_id_response = flow_metas[3]
        self.tap_side = flow_metas[4]
        self.start_time_us = flow_metas[5]
        self.end_time_us = flow_metas[6]

    def __eq__(self, rhs):
        return (self.vtap_id == rhs.vtap_id and self.syscall_trace_id_request
                == rhs.syscall_trace_id_request
                and self.syscall_trace_id_response
                == rhs.syscall_trace_id_response)

    def to_tuple(self):
        return (self.vtap_id, self.syscall_trace_id_request,
                self.syscall_trace_id_response)

    def set_relate(self, df, related_map):
        for i in range(len(df.index)):
            if df._id[i] == self._id:
                continue
            if self.vtap_id != df.vtap_id[i]:
                continue
            if self.syscall_trace_id_request > 0:
                if self.syscall_trace_id_request == df.syscall_trace_id_request[
                        i] or self.syscall_trace_id_request == df.syscall_trace_id_response[
                            i]:
                    related_map[df._id[i]].append(str(self._id) + "-syscall")
                    continue
            if self.syscall_trace_id_response > 0:
                if self.syscall_trace_id_response == df.syscall_trace_id_request[
                        i] or self.syscall_trace_id_response == df.syscall_trace_id_response[
                            i]:
                    related_map[df._id[i]].append(str(self._id) + "-syscall")
                    continue

    def to_sql_filter(self) -> str:
        # 返回空时需要忽略此条件
        sql_filters = []
        if self.syscall_trace_id_request > 0:
            sql_filters.append(
                'syscall_trace_id_request={syscall_trace_id_request} OR syscall_trace_id_response={syscall_trace_id_request}'
                .format(
                    syscall_trace_id_request=self.syscall_trace_id_request))
        if self.syscall_trace_id_response > 0:
            sql_filters.append(
                'syscall_trace_id_request={syscall_trace_id_response} OR syscall_trace_id_response={syscall_trace_id_response}'
                .format(
                    syscall_trace_id_response=self.syscall_trace_id_response))
        if not sql_filters:
            return '1!=1'
        # filter time range to prune
        sql = f"vtap_id={self.vtap_id} AND ({' OR '.join(sql_filters)})"
        return f"({sql})"


class Networks:

    def __init__(self):
        self.req_tcp_seq = None
        self.resp_tcp_seq = None
        self.span_id = None
        self.has_syscall = False
        self.metas = {}
        self.flows = []
        self.start_time_us = None
        self.end_time_us = None

    def add_flow(self, flow, network_delay_us):
        if self.flows:
            if self.req_tcp_seq and flow["type"] != L7_FLOW_TYPE_RESPONSE and (
                    self.req_tcp_seq != flow["req_tcp_seq"]):
                return False
            if self.resp_tcp_seq and flow["type"] != L7_FLOW_TYPE_REQUEST and (
                    self.resp_tcp_seq != flow["resp_tcp_seq"]):
                return False
            for key in MERGE_KEYS:
                if flow["type"] == L7_FLOW_TYPE_RESPONSE or not self.req_tcp_seq:
                    if key in MERGE_KEY_REQUEST:
                        continue
                if flow["type"] == L7_FLOW_TYPE_REQUEST or not self.resp_tcp_seq:
                    if key in MERGE_KEY_RESPONSE:
                        continue
                if self.get(key) and flow.get(key) and (self.get(key) !=
                                                        flow.get(key)):
                    # http2 == grpc
                    if key == 'l7_protocol' and self.get(key) in [
                            21, 41
                    ] and flow.get(key) in [21, 41]:
                        continue
                    elif key == 'l7_protocol_str' and self.get(key) in [
                            'HTTP2', 'gRPC'
                    ] and flow.get(key) in ['HTTP2', 'gRPC']:
                        continue
                    return False
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
            self.has_syscall = True
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
        # 有s-p
        if self.direct_flows[0]['tap_side'] == TAP_SIDE_SERVER_PROCESS:
            for i, direct_flow in enumerate(self.direct_flows[1:]):
                if not direct_flow.get('parent_id'):
                    if direct_flow.get('parent_app_flow', None):
                        # 1. 存在span_id相同的应用span，将该系统span的parent设置为该span_id相同的应用span
                        _set_parent(direct_flow,
                                    direct_flow['parent_app_flow'],
                                    "c-p mounted on parent_app_flow")
                    else:
                        # 2. 所属service中存在应用span，将该系统span的arent设置为service中最后一条应用span
                        if self.app_flow_of_direct_flows:
                            _set_parent(direct_flow,
                                        self.app_flow_of_direct_flows[-1],
                                        "c-p mounted on latest app_flow")
                        else:
                            # 3. 存在syscalltraceid相同且tap_side=s的系统span，该系统span的parent设置为该flow(syscalltraceid相同且tap_side=s)
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

    def check_client_process_flow(self, flow: dict):
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
            for client_process_flow in self.direct_flows[1:]:
                if flow['parent_span_id'] == client_process_flow['span_id']:
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
    则请求1和响应1配队，请求2和响应2配队
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
        else:
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
                equal = False
                break
        # 请求的时间必须比响应的时间小
        if request_flow['start_time_us'] > response_flow['end_time_us']:
            equal = False
        if request_flow['tap_side'] in [
                TAP_SIDE_SERVER_PROCESS, TAP_SIDE_CLIENT_PROCESS
        ]:
            # 应用span syscall_cap_seq判断合并
            if request_flow['syscall_cap_seq_0'] + 1 != response_flow[
                    'syscall_cap_seq_1']:
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
                    if flow['type'] in [
                            L7_FLOW_TYPE_REQUEST, L7_FLOW_TYPE_SESSION
                    ]:
                        flows[i][key] = flow[key]
                elif key in MERGE_KEY_RESPONSE:
                    if flow['type'] in [
                            L7_FLOW_TYPE_RESPONSE, L7_FLOW_TYPE_SESSION
                    ]:
                        flows[i][key] = flow[key]
                else:
                    if not flows[i][key]:
                        flows[i][key] = flow[key]
            if flow['type'] == L7_FLOW_TYPE_REQUEST:
                if flow['start_time_us'] < flows[i]['start_time_us']:
                    flows[i]['start_time_us'] = flow['start_time_us']
                else:
                    if flows[i]['req_tcp_seq'] in [0, '']:
                        flows[i]['req_tcp_seq'] = flow['req_tcp_seq']
                flows[i]['syscall_cap_seq_0'] = flow['syscall_cap_seq_0']
            else:
                if flow['end_time_us'] > flows[i]['end_time_us']:
                    flows[i]['end_time_us'] = flow['end_time_us']
                    if flows[i]['resp_tcp_seq'] in [0, '']:
                        flows[i]['resp_tcp_seq'] = flow['resp_tcp_seq']
                flows[i]['syscall_cap_seq_1'] = flow['syscall_cap_seq_1']
            if flow['type'] == L7_FLOW_TYPE_SESSION:
                flows[i]['req_tcp_seq'] = flow['req_tcp_seq']
                flows[i]['resp_tcp_seq'] = flow['resp_tcp_seq']
            # request response合并后type改为session
            if flow['type'] + flows[i]['type'] == 1:
                flows[i]['type'] = 2
            flows[i]['type'] = max(flows[i]['type'], flow['type'])
            return True

    return False


def sort_all_flows(dataframe_flows: DataFrame, network_delay_us: int,
                   return_fields: list, ntp_delay_us: int) -> list:
    """对应用流日志排序，用于绘制火焰图。

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
        related_ids = []
        for related_id in flow["related_ids"]:
            related_id = related_id.split("-")
            if related_id[0] in flow["_id"]:
                continue
            if id_map.get(related_id[0], None) is not None:
                related_ids.append(
                    f"{id_map[related_id[0]]}-{related_id[1]}-{related_id[0]}")
        flow["related_ids"] = related_ids

    # 从Flow中提取Service：一个<vtap_id, local_process_id>二元组认为是一个Service。
    service_map = defaultdict(Service)
    for flow in syscall_flows:
        if flow['tap_side'] != TAP_SIDE_SERVER_PROCESS:
            continue
        local_process_id = flow['process_id_1']
        vtap_id = flow['vtap_id']
        if (vtap_id, local_process_id, 0) not in service_map:
            service = Service(vtap_id, local_process_id)
            service_map[(vtap_id, local_process_id, 0)] = service
            # Service直接接收或发送的Flows_
            service.add_direct_flow(flow)
        else:
            index = 0
            for key in service_map.keys():
                if key[0] == vtap_id and key[1] == local_process_id:
                    index += 1
            service = Service(vtap_id, local_process_id)
            service_map[(vtap_id, local_process_id, index)] = service
            service.add_direct_flow(flow)

    for flow in syscall_flows:
        if flow['tap_side'] != TAP_SIDE_CLIENT_PROCESS:
            continue
        local_process_id = flow['process_id_0']
        vtap_id = flow['vtap_id']
        index = 0
        max_start_time_service = None
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
    # 1.网络span及系统span按照tap_side_rank进行排序
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
    app_flows_map = {app_flow["span_id"]: app_flow for app_flow in app_flows}
    for i in range(len(services)):
        if services[i].direct_flows[0]['tap_side'] == TAP_SIDE_SERVER_PROCESS:
            # 1. 存在span_id相同的应用span，将该系统span的parent设置为该span_id相同的应用span
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


def pruning_trace(response, _id, network_delay_us):
    tree = []
    root_start_time_us = 0
    root_end_time_us = 0
    tree_ids = set()
    for i, trace in enumerate(response.get('tracing', [])):
        trace_start_time_us = trace.get('start_time_us', 0)
        trace_end_time_us = trace.get('end_time_us', 0)
        _ids = trace.get('_ids')
        if not tree:
            tree.append(trace)
            root_start_time_us = trace_start_time_us
            root_end_time_us = trace_end_time_us
            tree_ids |= set(_ids)
            continue
        if trace_start_time_us - network_delay_us <= root_end_time_us and trace_end_time_us + network_delay_us >= root_start_time_us:
            tree.append(trace)
            tree_ids |= set(_ids)
        else:
            if _id in tree_ids:
                response['tracing'] = tree
                break
            else:
                tree = [trace]
                tree_ids = set()
                tree_ids |= set(_ids)
                root_start_time_us = trace_start_time_us
                root_end_time_us = trace_end_time_us
        if i == len(response['tracing']) - 1:
            response['tracing'] = tree


def merge_service(services, app_flows, response):
    metrics_map = {}
    prun_services = set()
    auto_services = set()
    ids = set()
    id_to_trace_map = {}
    for res in response.get('tracing', []):
        id_to_trace_map[res.get('id')] = res
        if res.get('auto_service'):
            auto_services.add(
                (res.get('auto_service_id'), res.get('auto_service')))
        ids.add(res.get('id'))
    for service in services:
        if (service.auto_service_id, service.auto_service) in auto_services:
            prun_services.add(service)
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
        for index, flow in enumerate(service.direct_flows):
            metrics_map[service_uid]["duration"] += flow["duration"]
            flow['service_uid'] = service_uid
            flow['service_uname'] = service_uname
            trace = id_to_trace_map.get(flow.get('_uid'))
            if trace:
                trace["service_uid"] = service_uid
                trace["service_uname"] = service_uname
            flow['process_id'] = service.process_id
    serivce_name_to_service_uid = {}
    for flow in app_flows:
        if flow.get("service"):
            service_uid = f"{flow['service'].auto_service_id}-"
            serivce_name_to_service_uid[flow['app_service']] = service_uid
    for flow in app_flows:
        if flow.get('_uid') not in ids:
            continue
        trace = id_to_trace_map.get(flow.get('_uid'))
        if not flow.get("service") and flow[
                'app_service'] not in serivce_name_to_service_uid:
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
            metrics_map[service_uid]["duration"] += flow["duration"]
        elif flow['app_service'] in serivce_name_to_service_uid:
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
            metrics_map[service_uid]["duration"] += flow["duration"]
        elif flow.get("service"):
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
            metrics_map[service_uid]["duration"] += flow["duration"]
    response["services"] = _call_metrics(metrics_map)


def format(services, networks, app_flows, _id, network_delay_us):
    response = format_trace(services, networks, app_flows)
    pruning_trace(response, _id, network_delay_us)
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
        for trace in self.traces:
            if trace["parent_id"] == -1:
                spans.append(trace)
                spans.extend(self.find_child(trace["childs"]))
        return spans

    def find_child(self, child_ids):
        spans = []
        for _id in child_ids:
            if _id not in self.uid_index_map:
                continue
            trace = self.traces[self.uid_index_map[_id]]
            spans.append(trace)
            spans.extend(self.find_child(trace["childs"]))
        return spans


def _call_metrics(services: dict):
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
    if flow_parent['duration'] >= (flow['end_time_us'] -
                                   flow['start_time_us']):
        flow_parent['duration'] -= (flow['end_time_us'] -
                                    flow['start_time_us'])
    else:
        flow_parent['duration'] = 0
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
    """
    local_rest_traces = []
    sorted_traces = []
    for trace in traces:
        if trace['tap_side'] in [const.TAP_SIDE_LOCAL, const.TAP_SIDE_REST]:
            local_rest_traces.append(trace)
        else:
            sorted_traces.append(trace)
    sorted_traces = sorted(
        sorted_traces, key=lambda x: const.TAP_SIDE_RANKS.get(x['tap_side']))
    if not sorted_traces:
        sorted_traces += local_rest_traces
    else:
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
    for trace in traces:
        if trace.get('_uid') == parent_trace.get('_uid'):
            continue
        if trace.get('x_request_id_0') == parent_trace.get('x_request_id_1'):
            return get_parent_trace(trace, traces)
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
                if trace_1.get('x_request_id_1') == trace_0.get(
                        'x_request_id_0'):
                    parent_traces.append(trace_1)
            # 如果span有多个父span，选父span的叶子span作为parent
            if parent_traces:
                parent_trace = get_parent_trace(parent_traces[0],
                                                parent_traces)
                _set_parent(trace_0, parent_trace,
                            "trace mounted due to x_request_id")
