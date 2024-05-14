
# API
WORKER_NUMBER = 10
API_VERSION = 'v1'
API_PREFIX = '/' + API_VERSION + '/stats'

# http
HTTP_OK = 200
HTTP_PARTIAL_RESULT = 206
HTTP_BAD_REQUEST = 400
HTTP_FORBIDDEN = 403
HTTP_NOT_ALLOWED = 405
HTTP_INTERNAL_SERVER_ERROR = 500

SUCCESS = 'SUCCESS'
PARTIAL_RESULT = 'PARTIAL_RESULT'
INVALID_PARAMETERS = 'INVALID_PARAMETERS'
FORBIDDEN = 'FORBIDDEN'
SERVER_ERROR = 'SERVER_ERROR'
INVALID_POST_DATA = 'INVALID_POST_DATA'

JSON_TYPE = 'application/json; charset=utf-8'

# tap_side
TAP_SIDE_UNKNOWN = ''
TAP_SIDE_CLIENT_PROCESS = 'c-p'
TAP_SIDE_CLIENT_NIC = 'c'
TAP_SIDE_CLIENT_POD_NODE = 'c-nd'
TAP_SIDE_CLIENT_HYPERVISOR = 'c-hv'
TAP_SIDE_CLIENT_GATEWAY_HAPERVISOR = 'c-gw-hv'
TAP_SIDE_CLIENT_GATEWAY = 'c-gw'
TAP_SIDE_SERVER_GATEWAY = 's-gw'
TAP_SIDE_SERVER_GATEWAY_HAPERVISOR = 's-gw-hv'
TAP_SIDE_SERVER_HYPERVISOR = 's-hv'
TAP_SIDE_SERVER_POD_NODE = 's-nd'
TAP_SIDE_SERVER_NIC = 's'
TAP_SIDE_SERVER_PROCESS = 's-p'
TAP_SIDE_REST = 'rest'
TAP_SIDE_LOCAL = 'local'
TAP_SIDE_RANKS = {
    TAP_SIDE_CLIENT_PROCESS: 1,
    TAP_SIDE_CLIENT_NIC: 2,
    TAP_SIDE_CLIENT_POD_NODE: 3,
    TAP_SIDE_CLIENT_HYPERVISOR: 4,
    TAP_SIDE_CLIENT_GATEWAY_HAPERVISOR: 5,
    TAP_SIDE_CLIENT_GATEWAY: 6,
    TAP_SIDE_SERVER_GATEWAY: 6,  # 由于可能多次穿越网关区域，c-gw和s-gw还需要重排
    TAP_SIDE_SERVER_GATEWAY_HAPERVISOR: 8,
    TAP_SIDE_SERVER_HYPERVISOR: 9,
    TAP_SIDE_SERVER_POD_NODE: 10,
    TAP_SIDE_SERVER_NIC: 11,
    TAP_SIDE_SERVER_PROCESS: 12,
    TAP_SIDE_REST: 13,
    TAP_SIDE_LOCAL: 13,  # rest和local需要就近排列到其他位置上
}

# signal_source
L7_FLOW_SIGNAL_SOURCE_PACKET = 0
L7_FLOW_SIGNAL_SOURCE_EBPF = 3
L7_FLOW_SIGNAL_SOURCE_OTEL = 4