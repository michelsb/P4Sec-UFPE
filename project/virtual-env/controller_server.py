#!/usr/bin/env python

import argparse
import grpc
import os
import sys
import commands

from p4thrift_lib.convert import convert_bin_to_ip

from p4switch_lib.p4switch import P4Switch
import p4runtime_lib.helper

from SimpleXMLRPCServer import SimpleXMLRPCServer
from SimpleXMLRPCServer import SimpleXMLRPCRequestHandler

# Restrict to a particular path.
class RequestHandler(SimpleXMLRPCRequestHandler):
    rpc_paths = ('/RPC2',)

class RTP4ServerController():

    def __init__(self,p4info_file_path,bmv2_file_path):
        self.hostname = commands.getoutput("hostname")  # Get the hostname
        self.p4info_file_path = p4info_file_path
        self.bmv2_file_path = bmv2_file_path
        # Instantiate a P4Runtime helper from the p4info file
        self.p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)
        self.switches = []
        self.create_switches()

    def create_switches(self):
        self.switches.append(P4Switch(
            name='s1',
            address='127.0.0.1',
            grpc_port=50051,
            thrift_port=9090,
            device_id=0,
            p4_json_filepath=self.bmv2_file_path,
            proto_dump_file='logs/s1-p4runtime-requests.txt'))
        self.switches.append(P4Switch(
            name='s2',
            address='127.0.0.1',
            grpc_port=50052,
            thrift_port=9091,
            device_id=1,
            p4_json_filepath=self.bmv2_file_path,
            proto_dump_file='logs/s2-p4runtime-requests.txt'))
        self.switches.append(P4Switch(
            name='s3',
            address='127.0.0.1',
            grpc_port=50053,
            thrift_port=9092,
            device_id=2,
            p4_json_filepath=self.bmv2_file_path,
            proto_dump_file='logs/s3-p4runtime-requests.txt'))

    def connect_switches_p4runtime(self):
        for sw in self.switches:
            sw.connect_p4runtime()

    def disconnect_switches_p4runtime(self):
        for sw in self.switches:
            sw.disconnect_p4runtime()

    def connect_switches_p4thrift(self):
        for sw in self.switches:
            sw.connect_p4thrift()

    def disconnect_switches_p4thrift(self):
        for sw in self.switches:
            sw.disconnect_p4thrift()

    # Create XMLRPCLIB Server
    def create_server(self):
        self.server = SimpleXMLRPCServer((self.hostname, 8000),
                                         requestHandler=RequestHandler)
        self.server.register_introspection_functions()
        print "Controller server %s is UP!" % self.hostname

    ####### TABLE

    def writeTableRulePerSwitch(self, sw, table_name, rule):
        table_entry = self.p4info_helper.buildTableEntry(
            table_name=table_name,
            match_fields=rule["match_fields"],
            action_name=rule["action_name"],
            action_params=rule["action_params"],
            priority=rule["priority"])
        sw.WriteTableEntry(table_entry)
        print "Installed rule on %s" % sw.name

    def writeTableRuleAllSwitches(self, table_name, rule):
        response = False
        try:
            self.connect_switches_p4runtime()
            for sw in self.switches:
                self.writeTableRulePerSwitch(sw, table_name, rule)
            response = True
        except KeyboardInterrupt:
            print " Shutting down..."
        except grpc.RpcError as e:
            print(e)
            self.printGrpcError(e)
        self.disconnect_switches_p4runtime()
        return response

    def readTableRulesPerSwitch(self, sw, table_id=None):
        switch_rules = {"sw_name": sw.name, "tables":{}}

        print '\n----- Reading tables rules for %s -----' % sw.name
        for response in sw.ReadTableEntries(table_id=table_id):
            for entity in response.entities:
                entry = entity.table_entry
                # TODO For extra credit, you can use the p4info_helper to translate
                #      the IDs in the entry to names
                table_name = self.p4info_helper.get_tables_name(entry.table_id)
                #print '%s: ' % table_name,

                #id_key = str(entry.table_id)
                if table_name not in switch_rules["tables"]:
                    switch_rules["tables"][table_name] = {"id": entry.table_id, "rules":[]}

                rule_entry = {"match_fields":{}}
                for m in entry.match:
                    #print self.p4info_helper.get_match_field_name(table_name, m.field_id),
                    #print '%r' % (self.p4info_helper.get_match_field_value(m),),

                    #rule_entry["match_fields"][str(self.p4info_helper.get_match_field_name(table_name, m.field_id))] = '%r' % (self.p4info_helper.get_match_field_value(m),)
                    rule_entry["match_fields"][
                        str(self.p4info_helper.get_match_field_name(table_name, m.field_id))] = str(self.p4info_helper.get_match_field_value(m))

                action = entry.action.action
                action_name = self.p4info_helper.get_actions_name(action.action_id)
                #print '->', action_name,

                rule_entry["action_name"] = action_name
                rule_entry["action_params"] = {}

                for p in action.params:
                    #print self.p4info_helper.get_action_param_name(action_name, p.param_id),
                    #print '%r' % p.value,
                    #rule_entry["action_params"][str(self.p4info_helper.get_action_param_name(action_name, p.param_id))] = '%r' % p.value
                    rule_entry["action_params"][
                        str(self.p4info_helper.get_action_param_name(action_name, p.param_id))] = str(p.value)
                #print

                rule_entry["priority"] = entry.priority

                switch_rules["tables"][table_name]["rules"].append(rule_entry)

        return switch_rules

    def readTableRulesAllSwitches(self,table_name):
        response = []
        table_id = self.p4info_helper.get_tables_id(table_name)
        try:
            self.connect_switches_p4runtime()
            for sw in self.switches:
                response.append(self.readTableRulesPerSwitch(sw,table_id=table_id))
        except KeyboardInterrupt:
            print " Shutting down."
        except grpc.RpcError as e:
            self.printGrpcError(e)
        self.disconnect_switches_p4runtime()
        return response

    def deleteTableRulesPerSwitch(self, sw, table_name, rule):
        table_entry = self.p4info_helper.buildTableEntry(
            table_name=table_name,
            match_fields=rule["match_fields"],
            action_name=rule["action_name"],
            action_params=rule["action_params"],
            priority=rule["priority"])
        print(table_entry)
        sw.DeleteTableEntry(table_entry)
        print "Removed rule on %s" % sw.name

    def deleteTableRuleAllSwitches(self,table_name,rule):
        response = False
        #table_id =  self.p4info_helper.get_tables_id(table_name)
        try:
            self.connect_switches_p4runtime()
            for sw in self.switches:
                self.deleteTableRulesPerSwitch(sw,table_name,rule)
            response = True
        except KeyboardInterrupt:
            print " Shutting down."
        except grpc.RpcError as e:
            self.printGrpcError(e)
        self.disconnect_switches_p4runtime()
        return response

    # TESTBED
    def writeIPV4LPMTableRule(self, sw, dst_ip_addr, dst_eth_addr, egress_port):
        table_entry = self.p4info_helper.buildTableEntry(
            table_name="MyIngress.ipv4_lpm",
            match_fields={
                "hdr.ipv4.dstAddr": (dst_ip_addr, 32)
            },
            action_name="MyIngress.ipv4_forward",
            action_params={
                "dstAddr": dst_eth_addr,
                "port": egress_port
            })
        sw.WriteTableEntry(table_entry)
        print "Installed ingress tunnel rule on %s" % sw.name

    # TESTBED
    def createdForwardingRulesOnSwitches(self):
        # Write the forwarding rules for s1
        self.writeIPV4LPMTableRule(self.switches[0], "10.0.1.1", "00:00:00:00:01:01", 1)
        self.writeIPV4LPMTableRule(self.switches[0], "10.0.2.2", "00:00:00:00:02:02", 2)
        self.writeIPV4LPMTableRule(self.switches[0], "10.0.3.3", "00:00:00:00:03:03", 3)

        # Write the forwarding rules for s2
        self.writeIPV4LPMTableRule(self.switches[1], "10.0.1.1", "00:00:00:00:01:01", 2)
        self.writeIPV4LPMTableRule(self.switches[1], "10.0.2.2", "00:00:00:00:02:02", 1)
        self.writeIPV4LPMTableRule(self.switches[1], "10.0.3.3", "00:00:00:00:03:03", 3)

        # Write the forwarding rules for s3
        self.writeIPV4LPMTableRule(self.switches[2], "10.0.1.1", "00:00:00:00:01:01", 2)
        self.writeIPV4LPMTableRule(self.switches[2], "10.0.2.2", "00:00:00:00:02:02", 3)
        self.writeIPV4LPMTableRule(self.switches[2], "10.0.3.3", "00:00:00:00:03:03", 1)

    ####### COUNTER

    def readCounterPerSwitch(self, sw, counter_id, index):
        counters = []
        for response in sw.ReadCounters(counter_id, index):
            print(response)
            for entity in response.entities:
                counter = entity.counter_entry
                counters.append(sw.name + " " + counter_id + ": " + str(counter.data.packet_count) + " packets (" + str(counter.data.byte_count) + " bytes)")
        return counters

    def readCounterAllSwitches(self, counter_name, index):
        response = []
        if index is not None:
            counter_id = self.p4info_helper.get_counters_id(counter_name)
            try:
                self.connect_switches_p4runtime()
                for sw in self.switches:
                    response.extend(self.readCounterPerSwitch(sw, counter_id, index))
            except KeyboardInterrupt:
                print " Shutting down."
            except grpc.RpcError as e:
                self.printGrpcError(e)
            self.disconnect_switches_p4runtime()
            return response

    ####### FLOW TRACKER

    def readFlowTrackerPerSwitch(self, sw):
        response = {}
        response["ctr_flows"] = sw.ReadRegister("ctr_flows")
        response["flow_xor_idx1"] = sw.ReadRegister("flow_xor_idx1")
        response["flow_xor_idx2"] = sw.ReadRegister("flow_xor_idx2")
        response["flow_xor_idx3"] = sw.ReadRegister("flow_xor_idx3")
        response["flow_xor_proto"] = sw.ReadRegister("flow_xor_proto")
        response["flow_xor_srcAddr"] = sw.ReadRegister("flow_xor_srcAddr")
        response["flow_xor_dstAddr"] = sw.ReadRegister("flow_xor_dstAddr")
        response["flow_xor_srcPort"] = sw.ReadRegister("flow_xor_srcPort")
        response["flow_xor_dstPort"] = sw.ReadRegister("flow_xor_dstPort")
        response["ctr_packets"] = sw.ReadCounter("ctr_packets")
        return response

    def readFlowTrackerAllSwitches(self):
        response = []
        try:
            self.connect_switches_p4thrift()
            for sw in self.switches:
                response.append(self.readFlowTrackerPerSwitch(sw))
        except KeyboardInterrupt:
            print " Shutting down."
        except grpc.RpcError as e:
            self.printGrpcError(e)
        self.disconnect_switches_p4thrift()
        return response

    def resetFlowTrackerPerSwitch(self, sw):
        sw.ResetRegister("ctr_flows")
        sw.ResetRegister("flow_xor_idx1")
        sw.ResetRegister("flow_xor_idx2")
        sw.ResetRegister("flow_xor_idx3")
        sw.ResetRegister("flow_xor_proto")
        sw.ResetRegister("flow_xor_srcAddr")
        sw.ResetRegister("flow_xor_dstAddr")
        sw.ResetRegister("flow_xor_srcPort")
        sw.ResetRegister("flow_xor_dstPort")
        sw.ResetCounter("ctr_packets")

    def resetFlowTrackerAllSwitches(self):
        response = False
        try:
            self.connect_switches_p4thrift()
            for sw in self.switches:
                self.resetFlowTrackerPerSwitch(sw)
            response = True
        except KeyboardInterrupt:
            print " Shutting down."
        except grpc.RpcError as e:
            self.printGrpcError(e)
        self.disconnect_switches_p4thrift()
        return response

    ####### CREATE SERVICE

    def createRTP4ServiceOnSwitches(self):
        try:
            # Install the P4 program on the switches
            self.switches[0].SetForwardingPipelineConfig(p4info=self.p4info_helper.p4info,bmv2_json_file_path=self.bmv2_file_path)
            print "Installed RT P4 Program using SetForwardingPipelineConfig on s1"
            self.switches[1].SetForwardingPipelineConfig(p4info=self.p4info_helper.p4info,bmv2_json_file_path=self.bmv2_file_path)
            print "Installed RT P4 Program using SetForwardingPipelineConfig on s2"
            self.switches[2].SetForwardingPipelineConfig(p4info=self.p4info_helper.p4info,bmv2_json_file_path=self.bmv2_file_path)
            print "Installed RT P4 Program using SetForwardingPipelineConfig on s3"
        except KeyboardInterrupt:
         print " Shutting down."
        except grpc.RpcError as e:
         self.printGrpcError(e)

    def printGrpcError(self,e):
        print "gRPC Error:", e.details(),
        status_code = e.code()
        print "(%s)" % status_code.name,
        traceback = sys.exc_info()[2]
        print "[%s:%d]" % (traceback.tb_frame.f_code.co_filename, traceback.tb_lineno)

    def createRTP4Service(self):
        try:
            self.connect_switches_p4runtime()
            self.createRTP4ServiceOnSwitches()
            # TEST
            self.createdForwardingRulesOnSwitches()
        except KeyboardInterrupt:
            print " Shutting down."
        except grpc.RpcError as e:
            self.printGrpcError(e)
        self.disconnect_switches_p4runtime()

    def startAgentService(self):
        self.create_server()
        self.createRTP4Service()
        self.server.register_function(self.writeTableRuleAllSwitches, 'write_rule')
        self.server.register_function(self.readTableRulesAllSwitches, 'read_rules')
        self.server.register_function(self.deleteTableRuleAllSwitches, 'delete_rule')
        self.server.register_function(self.readFlowTrackerAllSwitches, 'read_flow_tracker')
        self.server.register_function(self.resetFlowTrackerAllSwitches, 'reset_flow_tracker')
        self.server.register_function(self.readCounterAllSwitches, 'read_counters')
        self.server.serve_forever()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='P4Runtime Controller')
    parser.add_argument('--p4info', help='p4info proto in text format from p4c',
                        type=str, action="store", required=False,
                        default='./build/rtp4app.p4info')
    parser.add_argument('--bmv2-json', help='BMv2 JSON file from p4c',
                        type=str, action="store", required=False,
                        default='./build/rtp4app.json')
    args = parser.parse_args()

    if not os.path.exists(args.p4info):
        parser.print_help()
        print "\np4info file not found: %s\nHave you run 'make'?" % args.p4info
        parser.exit(1)
    if not os.path.exists(args.bmv2_json):
        parser.print_help()
        print "\nBMv2 JSON file not found: %s\nHave you run 'make'?" % args.bmv2_json
        parser.exit(1)
    # Run the server's main loop
    try:
        print 'Use Control-C to exit'
        agent = RTP4ServerController(args.p4info, args.bmv2_json)
        #print agent.get_stats()
        agent.startAgentService()
    except KeyboardInterrupt:
        print 'Exiting'
    #main(args.p4info, args.bmv2_json)
