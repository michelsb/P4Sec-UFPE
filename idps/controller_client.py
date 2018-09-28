import xmlrpclib
import threading

class IDPSClientController():

    def __init__(self):
        self.conn = dict()
        self.servers = []
        self.up_servers = []
        self.down_servers = []
        self.firstTime = True

    def addUPServer(self, server_name):
        print ("Server " + server_name + " up!")
        self.up_servers.append(server_name)
        if server_name in self.down_servers:
            self.down_servers.remove(server_name)

    def addDownServer(self, server_name):
        print ("Server " + server_name + " down!")
        self.down_servers.append(server_name)
        if server_name in self.up_servers:
            self.up_servers.remove(server_name)

    def connectServer(self, server_name):
        try:
            self.conn[server_name] = xmlrpclib.ServerProxy('http://' + server_name + ':8000')
            self.addUPServer(server_name)
            return True
        except Exception, err:
            print("Error accessing " + server_name)
            print("Message   :", err)
            self.addDownServer(server_name)
        return False

    def connectServers(self,file_name):
        ref_file = open(file_name, "r")
        servers = []
        for line in ref_file:
            server_name = line.split()[0]
            if '#' not in server_name:
                servers.append(server_name)
        for server_name in servers:
            self.connectServer(server_name)
        ref_file.close()

    def tryConnectDownServers(self):
        for server_name in self.down_servers:
            self.connectServer(server_name)

    def getUpServers(self):
        return self.up_servers

    def getDownServers(self):
        return self.down_servers

    def writeMaliciousRulePerControllerServer(self,server_name,proto, src_ip_range,dst_ip_range,src_port_range,dst_port_range):
        # Get remote data from server
        if self.conn[server_name] is not None:
            try:
                response = self.conn[server_name].write_malicious_rule(proto,src_ip_range,dst_ip_range,src_port_range,dst_port_range)
                print response
            except (xmlrpclib.Fault, xmlrpclib.ProtocolError, xmlrpclib.ResponseError) as err:
                print("A fault occurred")
                print("Fault code: " + str(err.faultCode))
                print ("Fault string: " + err.faultString)
                # In case of exception in the connection, return the server to the list of down servers
                self.addDownServer(server_name)
                return False
        else:
            print("ERROR: The stats from server " + server_name + " cannot be recovered. It does not have a valid connection.")
            self.addDownServer(server_name)

    def readSwitchesCountersPerControllerServer(self,server_name):
        # Get remote data from server
        if self.conn[server_name] is not None:
            try:
                remote_counters = self.conn[server_name].read_switches_counters()
                print remote_counters
            except (xmlrpclib.Fault, xmlrpclib.ProtocolError, xmlrpclib.ResponseError) as err:
                print("A fault occurred")
                print("Fault code: " + str(err.faultCode))
                print ("Fault string: " + err.faultString)
                # In case of exception in the connection, return the server to the list of down servers
                self.addDownServer(server_name)
                return False
        else:
            print("ERROR: The stats from server " + server_name + " cannot be recovered. It does not have a valid connection.")
            self.addDownServer(server_name)

    def readSwitchesCounters(self):
        for server_name in self.up_servers:
            self.readSwitchesCountersPerControllerServer(server_name)

    def writeMaliciousRule(self,proto,src_ip_range,dst_ip_range,src_port_range = None,dst_port_range = None):
        for server_name in self.up_servers:
            self.writeMaliciousRulePerControllerServer(server_name,proto, src_ip_range,dst_ip_range,src_port_range,dst_port_range)

    def startClientController(self,file_name):
        if self.firstTime:
            self.connectServers(file_name)
            self.firstTime = False
            threading.Timer(5, self.tryConnectDownServers).start()
