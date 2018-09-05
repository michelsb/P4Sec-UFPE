#!/usr/bin/env python2
import argparse
import grpc
import os
import sys
import commands
from time import sleep

import p4runtime_lib.bmv2
from p4runtime_lib.switch import ShutdownAllSwitchConnections
import p4runtime_lib.helper

from SimpleXMLRPCServer import SimpleXMLRPCServer
from SimpleXMLRPCServer import SimpleXMLRPCRequestHandler

# Restrict to a particular path.
class RequestHandler(SimpleXMLRPCRequestHandler):
    rpc_paths = ('/RPC2',)

class IDPSServerController():

    def __init__(self,p4info_file_path,bmv2_file_path):
        self.hostname = commands.getoutput("hostname")  # Get the hostname
        self.p4info_file_path = p4info_file_path
        self.bmv2_file_path = bmv2_file_path
        # Instantiate a P4Runtime helper from the p4info file
        self.p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)

    # Create XMLRPCLIB Server
    def create_server(self):
        self.server = SimpleXMLRPCServer((self.hostname, 8000),
                                         requestHandler=RequestHandler)
        self.server.register_introspection_functions()
        print "Controller server %s is UP!" % self.hostname

    def connect(self):
        #Create a switch connection object for s1, s2, and s3;
        # this is backed by a P4Runtime gRPC connection.
        # Also, dump all P4Runtime messages sent to switch to given txt files.
        self.s1 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s1',
            address='127.0.0.1:50051',
            device_id=0,
            proto_dump_file='logs/s1-p4runtime-requests.txt')
        self.s2 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s2',
            address='127.0.0.1:50052',
            device_id=1,
            proto_dump_file='logs/s2-p4runtime-requests.txt')
        self.s3 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s3',
            address='127.0.0.1:50053',
            device_id=2,
            proto_dump_file='logs/s3-p4runtime-requests.txt')

        # Send master arbitration update message to establish this controller as
        # master (required by P4Runtime before performing any other write operation)
        self.s1.MasterArbitrationUpdate()
        self.s2.MasterArbitrationUpdate()
        self.s3.MasterArbitrationUpdate()


    def disconnect(self):
        ShutdownAllSwitchConnections()

    def writeIDPSTernaryTableRule(self, sw, src_ip_addr, src_ip_mask, dst_ip_addr,dst_ip_mask):
        """
        Install table entry on the switch.

        :param p4info_helper: the P4Info helper
        :param sw: the switch connection
        :param dst_ip_addr: the destination Ethernet address to write in the
                            egress rule
        :param dst_eth_addr: the destination IP to match in the ingress rule
        :param egress_port: the egress port
        """
        table_entry = self.p4info_helper.buildTableEntry(
            table_name="MyIngress.idps_ternary",
            match_fields={
                "hdr.ipv4.srcAddr": (src_ip_addr,src_ip_mask),
                "hdr.ipv4.dstAddr": (dst_ip_addr,dst_ip_mask)
            },
            action_name="MyIngress.mark_as_suspicious",
            action_params={},
            priority=1)
        sw.WriteTableEntry(table_entry)
        print "Installed ingress tunnel rule on %s" % sw.name

    def writeIPV4LPMTableRule(self, sw, dst_ip_addr, dst_eth_addr, egress_port):
        """
        Install table entry on the switch.

        :param p4info_helper: the P4Info helper
        :param sw: the switch connection
        :param dst_ip_addr: the destination Ethernet address to write in the
                            egress rule
        :param dst_eth_addr: the destination IP to match in the ingress rule
        :param egress_port: the egress port
        """
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

    def readTableRules(self, sw):
        """
        Reads the table entries from all tables on the switch.

        :param p4info_helper: the P4Info helper
        :param sw: the switch connection
        """
        print '\n----- Reading tables rules for %s -----' % sw.name
        for response in sw.ReadTableEntries():
            for entity in response.entities:
                entry = entity.table_entry
                # TODO For extra credit, you can use the p4info_helper to translate
                #      the IDs in the entry to names
                table_name = self.p4info_helper.get_tables_name(entry.table_id)
                print '%s: ' % table_name,
                for m in entry.match:
                    print self.p4info_helper.get_match_field_name(table_name, m.field_id),
                    print '%r' % (p4info_helper.get_match_field_value(m),),
                action = entry.action.action
                action_name = self.p4info_helper.get_actions_name(action.action_id)
                print '->', action_name,
                for p in action.params:
                    print self.p4info_helper.get_action_param_name(action_name, p.param_id),
                    print '%r' % p.value,
                print

    def readCounter(self, sw, counter_name, index):
        """
        Reads the specified counter at the specified index from the switch. In our
        program, the index is the tunnel ID. If the index is 0, it will return all
        values from the counter.

        :param sw:  the switch connection
        :param counter_name: the name of the counter from the P4 program
        :param index: the counter index (in our case, the tunnel ID)
        """
        counters = []
        for response in sw.ReadCounters(self.p4info_helper.get_counters_id(counter_name), index):
            for entity in response.entities:
                counter = entity.counter_entry
                counters.append(sw.name + " " + counter_name + ": " + str(counter.data.packet_count) + " packets (" + str(counter.data.byte_count) + " bytes)")
        return counters

    def createIDPSServiceOnSwitches(self):
        try:
            # Install the P4 program on the switches
            self.s1.SetForwardingPipelineConfig(p4info=self.p4info_helper.p4info,bmv2_json_file_path=self.bmv2_file_path)
            print "Installed P4 Program using SetForwardingPipelineConfig on s1"
            self.s2.SetForwardingPipelineConfig(p4info=self.p4info_helper.p4info,bmv2_json_file_path=self.bmv2_file_path)
            print "Installed P4 Program using SetForwardingPipelineConfig on s2"
            self.s3.SetForwardingPipelineConfig(p4info=self.p4info_helper.p4info,bmv2_json_file_path=self.bmv2_file_path)
            print "Installed P4 Program using SetForwardingPipelineConfig on s3"
        except KeyboardInterrupt:
         print " Shutting down."
        except grpc.RpcError as e:
         printGrpcError(e)

    def createdForwardingRulesOnSwitches(self):
        # Write the forwarding rules for s1
        self.writeIPV4LPMTableRule(self.s1, "10.0.1.1", "00:00:00:00:01:01", 1)
        self.writeIPV4LPMTableRule(self.s1, "10.0.2.2", "00:00:00:00:02:02", 2)
        self.writeIPV4LPMTableRule(self.s1, "10.0.3.3", "00:00:00:00:03:03", 3)

        # Write the forwarding rules for s2
        self.writeIPV4LPMTableRule(self.s2, "10.0.1.1", "00:00:00:00:01:01", 2)
        self.writeIPV4LPMTableRule(self.s2, "10.0.2.2", "00:00:00:00:02:02", 1)
        self.writeIPV4LPMTableRule(self.s2, "10.0.3.3", "00:00:00:00:03:03", 3)

        # Write the forwarding rules for s3
        self.writeIPV4LPMTableRule(self.s3, "10.0.1.1", "00:00:00:00:01:01", 2)
        self.writeIPV4LPMTableRule(self.s3, "10.0.2.2", "00:00:00:00:02:02", 3)
        self.writeIPV4LPMTableRule(self.s3, "10.0.3.3", "00:00:00:00:03:03", 1)


    def printGrpcError(e):
        print "gRPC Error:", e.details(),
        status_code = e.code()
        print "(%s)" % status_code.name,
        traceback = sys.exc_info()[2]
        print "[%s:%d]" % (traceback.tb_frame.f_code.co_filename, traceback.tb_lineno)

    def createIDPSService(self):
        try:
            self.connect()
            self.createIDPSServiceOnSwitches()
            self.createdForwardingRulesOnSwitches()
        except KeyboardInterrupt:
            print " Shutting down."
        except grpc.RpcError as e:
            printGrpcError(e)
        self.disconnect()

    def readSwitchesCounters(self):
        response = []
        try:
            self.connect()
            response.extend(self.readCounter(self.s1, "MyIngress.ctr_normal", 1))
            response.extend(self.readCounter(self.s1, "MyIngress.ctr_suspicious", 2))
            response.extend(self.readCounter(self.s2, "MyIngress.ctr_normal", 1))
            response.extend(self.readCounter(self.s2, "MyIngress.ctr_suspicious", 2))
            response.extend(self.readCounter(self.s3, "MyIngress.ctr_normal", 1))
            response.extend(self.readCounter(self.s3, "MyIngress.ctr_suspicious", 2))
        except KeyboardInterrupt:
            print " Shutting down."
        except grpc.RpcError as e:
            printGrpcError(e)
        self.disconnect()
        return response

    def writeMaliciousRule(self,src_range,dst_range):
        response = False
        try:
            self.connect()
            #self.writeIDPSTernaryTableRule(s1, src_value, src_mask, dst_value, dst_mask)
            #self.writeIDPSTernaryTableRule(s2, src_value, src_mask, dst_value, dst_mask)
            #self.writeIDPSTernaryTableRule(s3, src_value, src_mask, dst_value, dst_mask)
            self.writeIDPSTernaryTableRule(self.s1, 0b00001010000000000000000100000001,0b11111111111111111111111111111111,0b11000000101010000000000000000001,0b11111111111111111111111111111111)
            self.writeIDPSTernaryTableRule(self.s2, 0b00001010000000000000000100000001,0b11111111111111111111111111111111,0b11000000101010000000000000000001,0b11111111111111111111111111111111)
            self.writeIDPSTernaryTableRule(self.s3, 0b00001010000000000000000100000001,0b11111111111111111111111111111111,0b11000000101010000000000000000001,0b11111111111111111111111111111111)
            response = True
        except KeyboardInterrupt:
            print " Shutting down."
        except grpc.RpcError as e:
            printGrpcError(e)
        self.disconnect()
        return response

        #writeIDPSTernaryTableRule(p4info_helper, s1, src_value, src_mask, dst_value, dst_mask)

    def startAgentService(self):
        self.create_server()
        self.createIDPSService()
        self.server.register_function(self.writeMaliciousRule, 'write_malicious_rule')
        self.server.register_function(self.readSwitchesCounters, 'read_switches_counters')
        self.server.serve_forever()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='P4Runtime Controller')
    parser.add_argument('--p4info', help='p4info proto in text format from p4c',
                        type=str, action="store", required=False,
                        default='./build/idps.p4info')
    parser.add_argument('--bmv2-json', help='BMv2 JSON file from p4c',
                        type=str, action="store", required=False,
                        default='./build/idps.json')
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
        agent = IDPSServerController(args.p4info, args.bmv2_json)
        #print agent.get_stats()
        agent.startAgentService()
    except KeyboardInterrupt:
        print 'Exiting'
    #main(args.p4info, args.bmv2_json)
