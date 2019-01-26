import os

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
DB_DIR = os.path.join(ROOT_DIR, 'db')
DRIVER_DIR = os.path.join(ROOT_DIR, 'drivers')
BUILD_DIR = os.path.join(ROOT_DIR, 'build')
LOG_DIR = os.path.join(ROOT_DIR, 'logs')
RTP4APP_DIR = os.path.join(ROOT_DIR, 'rtp4app')
CONFIG_FILE = os.path.join(RTP4APP_DIR, 'config.ini')

DB_NAME = "database.sqlite3"
JSON_NAME = "rtp4app.json"

WILDCARDS_GENERATION_TIMEOUT = 10
WILDCARDS_GENERATION_THRESHOLD = 5
#STRING_FIELDS = {"ethernet_t":["srcAddr","dstAddr"],"ipv4_t":["srcAddr","dstAddr"]}

FLOW_TRACKER_COUNT_REGISTER = 'ctr_flows'
FLOW_TRACKER_IDX_REGISTERS = ['flow_xor_idx1','flow_xor_idx2','flow_xor_idx3']
FLOW_TRACKER_FLOW_REGISTERS = ['flow_xor_proto','flow_xor_srcAddr','flow_xor_dstAddr','flow_xor_srcPort','flow_xor_dstPort']
FLOW_TRACKER_METRIC_REGISTERS = ['ctr_packets']


