#!/usr/bin/env python
import pandas as pd
import definitions

data = {'flow_xor_proto': [0, 0, 0, 0, 0, 0, 0, 6, 0, 6, 0, 0, 0, 0, 6, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        'flow_xor_srcAddr': [0, 0, 0, 0, 0, 0, 0, 167772417, 0, 167772674, 0, 0, 0, 0, 167772417, 0, 0, 167772674, 771, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        'ctr_packets': [0, 0, 0, 0, 0, 0, 0, 1091, 0, 652, 0, 0, 0, 0, 1091, 0, 0, 652, 1743, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        'flow_xor_srcPort': [0, 0, 0, 0, 0, 0, 0, 58038, 0, 5001, 0, 0, 0, 0, 58038, 0, 0, 5001, 61759, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        'ctr_flows': [0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 0, 1, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        'flow_xor_dstAddr': [0, 0, 0, 0, 0, 0, 0, 167772674, 0, 167772417, 0, 0, 0, 0, 167772674, 0, 0, 167772417, 771, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        'flow_xor_idx3': [0, 0, 0, 0, 0, 0, 0, 18, 0, 18, 0, 0, 0, 0, 18, 0, 0, 18, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        'flow_xor_idx2': [0, 0, 0, 0, 0, 0, 0, 14, 0, 9, 0, 0, 0, 0, 14, 0, 0, 9, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        'flow_xor_idx1': [0, 0, 0, 0, 0, 0, 0, 7, 0, 17, 0, 0, 0, 0, 7, 0, 0, 17, 22, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        'flow_xor_dstPort': [0, 0, 0, 0, 0, 0, 0, 5001, 0, 58038, 0, 0, 0, 0, 5001, 0, 0, 58038, 61759, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]}

class FlowTrackerIBLT():

    def __init__(self, data):
        self.count_column = definitions.FLOW_TRACKER_COUNT_REGISTER
        self.idx_columns = definitions.FLOW_TRACKER_IDX_REGISTERS
        self.flow_columns = definitions.FLOW_TRACKER_FLOW_REGISTERS
        self.metrics_columns = definitions.FLOW_TRACKER_METRIC_REGISTERS
        is_created, columns = self.create_iblt(data)
        if not is_created:
            raise Exception('The following fields are not in data structure: ' + str(columns))

    def create_iblt(self, data):
        set_registers = set([self.count_column] + self.idx_columns + self.flow_columns + self.metrics_columns)
        set_datakeys = set(data.keys())
        diff = set_registers - set_datakeys
        if len(diff) > 0:
            return False,diff
        self.df = pd.DataFrame(data)
        return True,diff

    def listing(self):
        flows = []
        while True:
            searcheable_row = self.df[self.df[self.count_column] == 1].head(1)
            if not searcheable_row.empty:
                flow = {}
                selected_columns = self.idx_columns + self.flow_columns + self.metrics_columns
                for column in selected_columns:
                    flow[column] = searcheable_row.iloc[0][column]
                flows.append(flow)
                for idx_column in self.idx_columns:
                    idx_value = searcheable_row.iloc[0][idx_column]
                    self.remove(flow, idx_value)
            else:
                break
        return flows

    def remove(self, flow, idx):
        self.df.iloc[idx][self.count_column] -= 1
        for column in self.idx_columns:
            self.df.iloc[idx][column] = self.df.iloc[idx][column] ^ flow[column]
        for column in self.flow_columns:
            self.df.iloc[idx][column] = self.df.iloc[idx][column] ^ flow[column]
        for column in self.metrics_columns:
            self.df.iloc[idx][column] -= flow[column]







#iblt = FlowTrackerIBLT(data)
#print(iblt.listing())