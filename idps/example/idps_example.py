#!/usr/bin/env python2

import pandas as pd
import datetime
import time

import os, sys
parentPath = os.path.abspath("..")
if parentPath not in sys.path:
    sys.path.insert(0, parentPath)

from util.wildcards import generate_flows_with_wildcards,convert_bin_to_value_mask
from controller_client import IDPSClientController

# - DoS attacks made are:
# ICMP flood, land, estoa, smurf, flood of SYN packets, teardrop and flood of UDP packets.
# - On the other hand, port scanning type attacks are:
# TCP SYN scan, TCP connect scan, SCTP INIT scan, Null scan, FIN scan, Xmas scan, TCP ACK scan,
# TCP Window scan e TCP Maimon scan.
#csv_files = ["icmp-flood-hping3_flows.csv", "land_flows.csv", "nestea_flows.csv", "probe_flows.csv", "punk_flows.csv",
#             "smurf_flows.csv", "syn-flood-hping3-sem-pfring-filtrado_flows.csv", "syn-flood_flows.csv",
#             "teardrop_flows.csv", "udp_flood-filtrado_flows.csv"]

csv_files = ["icmp-flood-hping3_flows.csv", "land_flows.csv", "nestea_flows.csv"]

#csv_files = ["icmp-flood-hping3_flows.csv", "land_flows.csv", "nestea_flows.csv", "smurf_flows.csv",
#             "syn-flood-hping3-sem-pfring-filtrado_flows.csv", "syn-flood_flows.csv",
#             "teardrop_flows.csv", "udp_flood-filtrado_flows.csv"]

def read_csv_files():
    dfs = []

    print("# " + str(datetime.datetime.now()) + " - Reading CSVs...")

    for file in csv_files:
        dfs.append(pd.read_csv("csv/" + file, sep='\t',
                               usecols=['hdrDesc', 'srcIP', 'dstIP', 'srcPort', 'dstPort', 'l4Proto']))

    print("# " + str(datetime.datetime.now()) + " - CSVs loaded as dataframes...")

    print("# " + str(datetime.datetime.now()) + " - Concatenating all dataframes...")

    df = pd.concat(dfs)

    filter1 = df['hdrDesc'] != "eth:arp"
    filter2 = df['hdrDesc'] != "eth:ipv6:udp"

    df = df[filter1 & filter2].reset_index(drop=True)

    print("# " + str(datetime.datetime.now()) + " - All dataframes concatenated...")

    return df

df = read_csv_files()
num_flows = len(df.index)
generate_flows_with_wildcards(df)
df = df[["srcIP","srcPort","dstIP","dstPort","l4Proto"]].drop_duplicates()

print(df)

print("Number of Original Flows: " + str(num_flows))
print("Number of Flows with Wildcards: " + str(len(df.index)))

print("# " + str(datetime.datetime.now()) + " - Connecting to controller servers...")

idps_client = IDPSClientController()
idps_client.startClientController("server.txt")

print("# " + str(datetime.datetime.now()) + " - Start to create malicious rules...")

for index, row in df.iterrows():
    #print("Add - " + str(row["l4Proto"]))
    idps_client.writeMaliciousRule(str(row["l4Proto"]),row["srcIP"],row["dstIP"],row["srcPort"],row["dstPort"])
        #writeMaliciousRule(self, proto, src_ip_range, dst_ip_range, src_port_range=None, dst_port_range=None)
