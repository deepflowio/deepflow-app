import json
import uuid
import time
import asyncio
import aiohttp
import pandas as pd

from log import logger

from config import config
from common import const, utils

log = logger.getLogger(__name__)
CONTROLLER_STATE_EXCEPTION = 4
NODE_TYPE_REGION_MASTER = 1


class Query(object):

    def __init__(self,
                 query_uuid,
                 region,
                 host,
                 database,
                 sql,
                 datasource,
                 query_id,
                 debug,
                 headers=None):
        self.query_uuid = query_uuid
        self.query_id = query_id
        self.region = region
        self.host = host
        self.database = database if database else ""
        self.sql = sql
        self.datasource = datasource
        self.debug = debug

        self.status = 206
        self.query_region = -1
        self.result = None
        self.debug_info = None
        self.headers = headers

    def to_dataframe(self, result):
        df = pd.DataFrame(data=result['values'], columns=result['columns'])
        return df

    async def _exec(self):
        log.debug(
            f"Query UUID: {self.query_uuid} | Database: {self.database}@{self.host} | SQL: {self.sql}"
        )
        url = f"http://{self.host}:{config.querier_port}/v1/query/?query_uuid={self.query_uuid}&no_prewhere=true"
        if self.debug:
            url += "&debug=true"
        data = {'db': self.database, 'sql': self.sql}
        if self.datasource:
            data['datasource'] = self.datasource
        async with aiohttp.ClientSession() as session:
            async with getattr(session, 'post')(url,
                                                data=data,
                                                timeout=config.querier_timeout,
                                                headers=self.headers) as r:
                response = await r.read()
                response = json.loads(response)
                status_code = r.status
        return response, status_code

    async def exec(self):
        try:
            start_time = time.time()
            response, status = await self._exec()
            result_dict = response.get('result')
            result_df = None
            if result_dict and result_dict.get('values') and result_dict.get(
                    'columns'):
                result_df = self.to_dataframe(result_dict)
                if self.region is not None:
                    result_df['_tsdb_region_name'] = self.region
                if self.query_id is not None:
                    result_df['query_id'] = self.query_id
            if status != 200:
                self.query_region = -1
            else:
                end_time = time.time()
                self.query_region = end_time - start_time
            self.result = result_df
            self.status = status
            self.debug_info = response.get('debug')
            self.description = response.get('DESCRIPTION')
        except Exception as e:
            err_msg = f"Query UUID: {self.query_uuid} | Database: {self.database}@{self.host} | SQL: {self.sql} | Error: {e}"
            log.error(err_msg)
            self.status = const.HTTP_PARTIAL_RESULT
            self.description = err_msg


class Querier(object):

    def __init__(self,
                 callback=lambda x: x,
                 headers=None,
                 query_id=None,
                 to_dataframe=False,
                 debug=False):
        self.status = 200
        self.query_uuids = dict()
        self.query_id = query_id
        self.query_total_time = None
        self.query_regions = dict()
        self.callback = callback if isinstance(callback, list) else [callback]
        self.headers = headers
        self.to_dataframe = to_dataframe
        self.debug = debug
        self.debug_info = dict()
        self.description = ''

    def format_result(self, result_list):
        results = list()
        if result_list:
            result = pd.concat(result_list, ignore_index=True)
            for callback in self.callback:
                result = callback(result)
            if not self.to_dataframe:
                json_result = result.to_json(orient='records',
                                             default_handler=str)
                results = json.loads(json_result)
            else:
                results = result
        return {
            "status": self.status,
            "query_uuids": self.query_uuids,
            "total_time": self.query_total_time,
            "regions": self.query_regions,
            "sql": self.sql,
            "data": results,
            "debug": self.debug_info,
            "description": self.description
        }

    async def exec_query(self,
                         queriers,
                         database,
                         sql,
                         region_name=None,
                         datasource=None,
                         headers=None) -> list:
        querys = list()
        for name, host in queriers.items():
            if region_name and region_name != name:
                continue
            query_uuid = str(uuid.uuid4())
            querys.append(
                Query(query_uuid, name, host, database, sql, datasource,
                      self.query_id, self.debug, headers))
        tasks = []
        for query in querys:
            if query.host:
                tasks.append(query.exec())
        await asyncio.wait(tasks)
        return querys

    async def exec_all_clusters(self,
                                database,
                                sql,
                                region_name=None,
                                datasource=None):
        self.sql = sql
        total_start_time = time.time()
        headers = {}
        if self.headers is not None and self.headers.get('X-Org-Id'):
            headers = {"X-Org-Id": self.headers.get('X-Org-Id')}

        queriers = await get_queriers(database, region_name, headers)
        if not queriers:
            return {
                'description': "无法找到可用的查询节点",
                'status': const.HTTP_PARTIAL_RESULT
            }
        if region_name:
            if not queriers.get(region_name):
                return {
                    'description': "无法找到可用的查询节点",
                    'status': const.HTTP_PARTIAL_RESULT
                }
        querys = await self.exec_query(queriers, database, sql, region_name,
                                       datasource, headers)
        result_list = list()
        for query in querys:
            self.status = query.status if query.status > self.status else self.status
            self.description = query.description if query.description else self.description
            self.query_regions[query.region] = query.query_region
            self.query_uuids[query.region] = query.query_uuid
            if query.result is not None:
                result_list.append(query.result)
            if query.debug_info is not None:
                self.debug_info[query.region] = query.debug_info

        total_end_time = time.time()
        self.query_total_time = total_end_time - total_start_time
        format_result = self.format_result(result_list)
        return format_result


QUERIERS = {}


async def get_queriers(database, region_name=None, headers=None):
    global QUERIERS
    if not QUERIERS:
        QUERIERS["time"] = time.time()
        QUERIERS["queriers"] = dict()
    if QUERIERS["queriers"] and (time.time() - QUERIERS.get("time", 0) < 120):
        return QUERIERS["queriers"]
    res, code = await utils.curl_perform(
        'get',
        f"http://{config.controller_server}:{config.controller_port}" +
        f'/v1/controllers/',
        headers=headers)
    if code == 200 and res['DATA']:
        queriers = dict()
        for item in res['DATA']:
            if item.get('REGION_NAME', None) is None:
                log.warning(f"Get REGION_NAME Exception: {item}")
                continue
            if item['STATE'] == CONTROLLER_STATE_EXCEPTION:
                continue
            if item['NODE_TYPE'] == NODE_TYPE_REGION_MASTER:
                ip = config.querier_server
            else:
                ip = f"{item['REGION_DOMAIN_PREFIX']}{config.querier_server}"
            queriers[item['REGION_NAME']] = ip
        QUERIERS["queriers"] = await _check_queriers(queriers, database,
                                                     region_name, headers)
        QUERIERS["time"] = time.time()
    return QUERIERS["queriers"]


async def _check_queriers(queriers, database, region_name=None, headers=None):
    """
    check if all queriers region are available
    """
    if not queriers: return queriers
    if region_name and not queriers.get(region_name): return queriers

    querier_executor = Querier(headers=headers)
    test_db_sql = "select 1 from l7_flow_log limit 1"
    query_result = await querier_executor.exec_query(queriers,
                                                     database=database,
                                                     sql=test_db_sql,
                                                     region_name=region_name,
                                                     headers=headers)
    for result in query_result:
        if result.status == 200 and result.result is not None:
            # region is available only when get tables result
            continue
        # region is not available
        del (queriers[result.region])
    return queriers
