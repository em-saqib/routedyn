#!/usr/bin/python

import os
import sys
import time
import pox
import re
import itertools
from pprint import pprint as pp                # Used for better datastructure print
from copy import deepcopy

import pox.lib.packet as pkt                   # This is used to handle packets
import pox.openflow.libopenflow_01 as of
import pox.openflow.discovery
import pox.host_tracker
from pox.core import core
from pox.lib.packet.ethernet import ethernet
from pox.lib.addresses import EthAddr, IPAddr  # Used to play with network addresses
from pox.lib.recoco import Timer               # Will be used for timer
from pox.lib.revent import *                   # Events management
from pox.lib.util import dpid_to_str

# TODO: This is a global todo list for this project 
# - Move the various messages into the messages categories of the provided POX logger.


# Configurations
PERIODIC_CHECK_DELAY = 1           # Delay of flow and port statistics requests
MODFLOW_IDLE_TIMEOUT = 120         # Seconds used to set the routing rules idle_timeout. After this delay, the rules will expires
FLOW_BURST_MARGIN_PERCENT = 3      # Percent of tolerance if used bandwidth exceed capacity of the link. Prevent some false congestion detection
CONGESTION_CHECK_COUNT_TRIGGER = 5 # If congestion is detected this number of time successively on stats check, trigger reroute algorithm (Algo 2)
CONGESTION_RETRIGGER_DELAY = 5     # Second delay before another reroute could be triggered
HOST_LINKS_MBPS_CAPACITY = 10      # Host to Switch link capacity (handled by the code, but not needed for this project)
SWITCH_LINKS_MBPS_CAPACITY = {     # Topology link capacities in Mbps
    "1-4": 10,
    "2-4": 10,
    "3-4": 10,
    "4-5": 3,
    "4-6": 4,
    "4-7": 10,
    "5-6": 3,
    "7-8": 2,
    "8-9": 2,
    "9-6": 10,
    "6-10": 10,
    "6-11": 10,
    "6-12": 10,
    "12-6": 10,
    "11-6": 10,
    "10-6": 10,
    "6-5": 3,
    "6-4": 4,
    "6-9": 10,
    "5-4": 3,
    "9-8": 2,
    "8-7": 2,
    "7-4": 10,
    "4-3": 10,
    "4-2": 10,
    "4-1": 10
}

### Colors of console messages
COLOR_RESET_SEQ = "\033[0m"
COLOR_ACTION = "\033[96m"   # Cyan    - Action
COLOR_INFO = "\033[93m"     # Yellow  - Information
COLOR_DEBUG = "\033[95m"    # Magenta - Debug
COLOR_ERROR = "\033[91m"    # Red     - Error



###############################################################################
### Display console infos with colors
def print_color(msg, color):
    print(color + msg + COLOR_RESET_SEQ)



###############################################################################
### DFS algo. Returns all possible paths between two nodes
def find_all_paths(graph, start, end, path=[]):
    path = path + [start]
    if start == end:
        return [path]
    if not graph.has_key(start):
        return []
    paths = []
    for node in graph[start]:
        if node not in path:
            newpaths = find_all_paths(graph, node, end, path)
            for newpath in newpaths:
                paths.append(newpath)
    return paths


###############################################################################
### Find all paths between two hosts.
def find_all_hosts_paths(srcIp, dstIp, SwitchPathsCollection, HostSwitchLinks):
    srcSwitch = -1
    dstSwitch = -1
    hostsPaths = []  # Keep all paths between source and destination hosts

    # Get the switchs that are connected to the source and destination hosts
    for link in HostSwitchLinks:
        if link.get('ip') ==  srcIp:
            srcSwitch = link.get('switch')
        if link.get('ip') == dstIp:
            dstSwitch = link.get('switch')

    # Get all available paths between the two switchs
    for path in SwitchPathsCollection:
        if path[0] == srcSwitch and path[-1] == dstSwitch: # Get all paths that begins and end with the two switchs
            hostsPaths.append(path)

    # If no path is found, then the two hosts are connected to the same switch
    if not hostsPaths:
        hostsPaths.append(srcSwitch)

    return hostsPaths


###############################################################################
### Create all possible paths
def create_all_paths(hostsPaths, SwitchPortUsedByLink, srcip, dstip):
    allPaths = {} # Store all calculated paths

    for path in hostsPaths:
        newPath = {
            "PathID": "",         # Unique ID
            "Hops": [],           # All switchs on the path
            "Links": {},          # All the ports used by the switchs on the path from source to destination
            "Ingress": "",        # Switch that is connected to source
            "IngressPort": 0,     # Port of the switch that is connected to source
            "Egress": "",         # Switch that is connected to dest
            "EgressPort": 0,      # Port of the switch that is connected to dest
            "Capacity": 0,        # Bandwitdh capacity in Mbps based on the link with the smallest capacity on the path
            "Flows": set(),       # All FlowID that goes through this path
            "UsedBandwidth": 0,   # Bandwidth used in Mbps
            "FreeCapacity": 0     # Bandwidth available in Mbps
        }

        # Create & set unique a somewhat unique PathID that fit our experiment needs. ie: sw1-sw2-sw3        
        pathId = '-'.join(map(str, path))
        newPath["PathID"] = pathId
        newPath["Hops"] = path
        newPath["Links"] = get_all_switch_port_used_on_path(SwitchPortUsedByLink, path, srcip, dstip)
        newPath["Ingress"] = path[0]
        newPath["Egress"] = path[-1]

        # Make sense to keep Ingress & Egress ports here since we already have all the required info
        swToSrcKey = str(path[0]) +"-"+ srcip
        swToDstKey = str(path[-1]) +"-"+ dstip
        newPath["IngressPort"] = SwitchPortUsedByLink[swToSrcKey]
        newPath["EgressPort"] = SwitchPortUsedByLink[swToDstKey]

        # Get the smallest link on the path to set capacity
        pathCapacity = get_smallest_link_on_path(path)
        newPath["Capacity"] = pathCapacity
        newPath["FreeCapacity"] = pathCapacity # FreeCapacity is also Capacity at path creation
        #print_color("DEBUG: Smallest capacity on path ["+ ", ".join(str(s) for s in path) +"] is: "+ str(pathCapacity), COLOR_DEBUG)

        # Add path to results
        allPaths[newPath["PathID"]] = newPath

    return allPaths


###############################################################################
### Check if the host-switch link is discovered
def is_discovered_host_switch_link(hostSwitchLinks, hostIp):
    for link in hostSwitchLinks:
        if link["ip"] == hostIp:
            return True
    return False


###############################################################################
### Get all the ports used on the switchs in the path from source to destination
def get_all_switch_port_used_on_path(SwitchPortUsedByLink, path, srcip, dstip):
    SwitchPortUsedByLinkForPath = {}

    # Get the ports for source and destinations hosts switchs. This also take care of two hosts connected to the same switch
    swToSrcKey = str(path[0]) +"-"+ srcip
    swToDstKey = str(path[-1]) +"-"+ dstip
    SwitchPortUsedByLinkForPath[swToSrcKey] = SwitchPortUsedByLink[swToSrcKey]
    SwitchPortUsedByLinkForPath[swToDstKey] = SwitchPortUsedByLink[swToDstKey]

    # Get all the ports in the path
    for index in range(len(path)-1):
        swToSwKey = str(path[index]) +"-"+ str(path[index+1])
        SwitchPortUsedByLinkForPath[swToSwKey] = SwitchPortUsedByLink[swToSwKey]
        
    #pp(path)
    #pp(SwitchPortUsedByLinkForPath)

    return SwitchPortUsedByLinkForPath


###############################################################################
### Find the smallest link on a path
def get_smallest_link_on_path(path):
    capacity = -1
    # Handle case where both hosts could be connected to the same switch
    if len(path) is 1:
        return HOST_LINKS_MBPS_CAPACITY

    # Get the smallest link on the path
    for index in range(len(path)-1):
        swToSwKey = str(path[index]) +"-"+ str(path[index+1])
        if capacity == -1:
            capacity = SWITCH_LINKS_MBPS_CAPACITY[swToSwKey]
        elif SWITCH_LINKS_MBPS_CAPACITY[swToSwKey] < capacity:
            capacity = SWITCH_LINKS_MBPS_CAPACITY[swToSwKey]
        
    return capacity


###############################################################################
### Create a new Flow. Forward = Source to Destination, Backward = Destination to Source
def create_new_flow(ipPacket, isForward):
    # Set the direction of the flow (src -> dst OR dst -> src)
    if isForward:
        srcip = ipPacket.srcip.toStr()
        dstip = ipPacket.dstip.toStr()
    else:
        srcip = ipPacket.dstip.toStr()
        dstip = ipPacket.srcip.toStr()
    ipProtocol = ipPacket.protocol

     # Recreate the flow
    newFlow = {
        "FlowID": "",            # Unique Identifier for this flow
        "SrcIP": srcip,          # Source IP
        "DstIP": dstip,          # Destination IP
        "Protocol": ipProtocol,  # Protocol of IP payload
        "SrcPort": 0,            # TCP/UDP Source port
        "DstPort": 0,            # TCP/UDP Destination port
        "UsedBandwidth": 0       # Flow used bandwidth in Mbps 
    }

    # If tcp or UDP, get ports from TCP or UDP payload
    if ipProtocol is 6 or ipProtocol is 17:
        # Match the port to direction
        if isForward:
            newFlow["SrcPort"] = ipPacket.payload.srcport
            newFlow["DstPort"] = ipPacket.payload.dstport
        else:
            newFlow["SrcPort"] = ipPacket.payload.dstport
            newFlow["DstPort"] = ipPacket.payload.srcport
    
    ## Set FlowID from attributes
    flowId = generate_flow_id(srcip, newFlow["SrcPort"], dstip, newFlow["DstPort"], ipProtocol)
    newFlow["FlowID"] = flowId

    return newFlow


###############################################################################
### Return concatenated flow attributes to create a somewhat unique FlowID. 
def generate_flow_id(srcip, srcport, dstip, dstport, ipProtocol):
    # srcip-srcport-dstip-dstport-ipProtocol 
    # ie: 10.0.0.1-39546-10.0.0.6-5001-6
    return srcip +"-"+ str(srcport) +"-"+ dstip +"-"+ str(dstport) +"-"+ str(ipProtocol)


###############################################################################
### Get the pathId of the path which have the trunk with the most FreeCapacity between two hosts
def get_pathId_using_trunk_with_most_FreeCapacity(endPoints, PathsCollection, FlowsCollection):
    trunkStats = {} # Bandwidth stats of the trunks

    # Calculate the cummulative bandwidth of the trunks
    for ep in PathsCollection:
        for pathId in PathsCollection[ep]:
            for flowId in PathsCollection[ep][pathId]["Flows"]:
                # Get trunk by removing first and last switch in the path
                trunkId = '-'.join(map(str, PathsCollection[ep][pathId]["Hops"][1:-1]))
                if not trunkStats.has_key(trunkId):
                    trunkStats[trunkId] = {}
                    trunkStats[trunkId]["TotalUsed"] = 0
                trunkStats[trunkId]["TotalUsed"] += FlowsCollection[flowId]["UsedBandwidth"]

    # Find the path which use the trunk with the most FreeCapacity
    trunkBestFreeCapacity = 0
    bestPathId = ""
    for pathId in PathsCollection[endPoints]:
        trunkId = '-'.join(map(str, PathsCollection[endPoints][pathId]["Hops"][1:-1]))
        trunkCapacity = PathsCollection[endPoints][pathId]["Capacity"]
        
        # Have max capacity by default
        trunkFreeCapacity = trunkCapacity

        # Substract used bandwidth, if any
        if trunkStats.has_key(trunkId):
            trunkFreeCapacity = trunkCapacity - trunkStats[trunkId]["TotalUsed"]

        # Keep best values
        if trunkFreeCapacity > trunkBestFreeCapacity:
            trunkBestFreeCapacity = trunkFreeCapacity
            bestPathId = pathId

    print_color("PathID ["+ bestPathId +"] has most FreeCapacity: "+ str(trunkBestFreeCapacity) +" EndPoints: "+ endPoints, COLOR_INFO)
    
    return bestPathId


###############################################################################
### Apply a burstable reduction. This can prevent some false congestion detection
def apply_speed_burst_margin(mbpsSpeed):
    return (mbpsSpeed - (mbpsSpeed * (FLOW_BURST_MARGIN_PERCENT * 0.01)))


###############################################################################
### Handle installation of routing rules for all switchs on the path of a flow 
def install_routing_rules_on_path_switchs(path, flow, TrackedSwitchs):
    #print_color("DEBUG: Handling install of routing rules on path: ["+ path["PathID"] +"] for flow: ["+ flow["FlowID"] +"]", COLOR_DEBUG)
    hops = path["Hops"]    # Hops on the path
    links = path["Links"]  # Port used on each links

    # Set rules on all switchs on the path
    for index in range(len(hops)-1):
        sw = hops[index]
        swToSwKey = str(hops[index]) +"-"+ str(hops[index+1])
        swPort = links[swToSwKey]
        TrackedSwitchs[sw].add_flow_routing_rules(swPort, flow)
        #print_color("DEBUG: Sw: "+ str(sw) +" Port: "+ str(swPort), COLOR_DEBUG)

    # Set Egress rule
    EgressSwitch = path["Egress"]
    EgressPort = path["EgressPort"]
    TrackedSwitchs[EgressSwitch].add_flow_routing_rules(EgressPort, flow)
    #print_color("DEBUG: EgressSw: "+ str(path["Egress"]) +" EgressPort: "+ str(path["EgressPort"]), COLOR_DEBUG)



###############################################################################
### Handle removal of routing rules for all switchs on the path of a flow 
def remove_routing_rules_on_path_switchs(path, flow, TrackedSwitchs):
    #print_color("DEBUG: Handling removal of rules on path: ["+ path["PathID"] +"] for flow: ["+ flow["FlowID"] +"]", COLOR_DEBUG)
    hops = path["Hops"]  # Hops on the path

    # Remove rules on all switchs on the path
    for index in range(len(hops)-1):
        sw = hops[index]
        swToSwKey = str(hops[index]) +"-"+ str(hops[index+1])
        TrackedSwitchs[sw].remove_flow_routing_rules(flow)
        #print_color("DEBUG: Sw: "+ str(sw), COLOR_DEBUG)

    # Remove Egress rule
    EgressSwitch = path["Egress"]
    TrackedSwitchs[EgressSwitch].remove_flow_routing_rules(flow)
    #print_color("DEBUG: EgressSw: "+ str(path["Egress"]), COLOR_DEBUG)




###############################################################################
### This is the core class that will process all POX events
###############################################################################
class RouteDyn(EventMixin):
    def __init__(self):
        super(EventMixin, self).__init__()

        # Data structures
        self.adjs = {}                  # Dictionary of neighboring nodes. Key: dpid, Value: set([All neighbors of this node])
        self.SwitchPathsCollection = [] # All available paths between the switchs
        self.SwitchPortUsedByLink = {}  # Port used on a switch to connect with its neighbor. Key: "dpid1-dest" Value: Port used on dpid1
        self.HostSwitchLinks = []       # All paths between hosts and switchs
        
        self.PathsCollection = {}       # Store all paths between source-dist. Key: "srcip-dstip", value: [All available Path]
        self.FlowsCollection = {}       # Store all flows
        self.TrackedSwitchs = {}        # Keep all TrackedSwitch objects
        self.TrackPathCongestion = {}   # Keep track of path congestion between stats check
        self.LastRerouteTriggered = time.time()   # Keep the time of the last reroute execution
        

        # Setup listeners
        core.listen_to_dependencies(self, 'openflow_discovery')                         # Used to detect links between switchs
        core.listen_to_dependencies(self, 'host_tracker')                               # Used to detect links between a switch and a host
        self.listenTo(core.openflow)                                                    # Listen for openflow events
        #core.openflow.addListenerByName("PacketIn", self._handle_PacketIn)             # Provided, but not needed. Handle events twice if added
        #core.openflow.addListenerByName("ConnectionUp", self._handle_ConnectionUp)     # Provided, but not needed. Handle events twice if added
        core.openflow_discovery.addListenerByName("LinkEvent", self._handle_LinkEvent)  # Listen to link events
        core.host_tracker.addListenerByName("HostEvent", self._handle_HostEvent)        # Listen to host events
        core.openflow.addListenerByName("FlowRemoved", self._handle_FlowRemoved)        # Listen on flow removal (routing rules expiration)



    #########################################################################################################################
    ### Called when a new switch connect to the controller
    #########################################################################################################################
    def _handle_ConnectionUp(self, event):
        print_color("Switch " + str(event.dpid) + " has come up. Its statistics are now tracked.", COLOR_ACTION)

        # New switch will be tracked for stats
        if not event.dpid in self.TrackedSwitchs:
            tswitch = TrackedSwitch(self)                  # Create an object that will track this switch
            tswitch.dpid = event.dpid     
            self.TrackedSwitchs[event.dpid] = tswitch      # Add with dpid as the key for this new tracked switch
            tswitch.start_stats_tracking(event.connection) # Start periodic tracking for this switch




    #########################################################################################################################
    ### Called when a flow is removed from the switchs
    #########################################################################################################################
    def _handle_FlowRemoved(self, event):
        # We will only handle idle_timeout. This should be enough for this project
        if event.idleTimeout is True:
            srcip = event.ofp.match.nw_src.toStr()
            srcport = event.ofp.match.tp_src
            dstip = event.ofp.match.nw_dst.toStr()
            dstport = event.ofp.match.tp_dst
            ipProtocol = event.ofp.match.nw_proto
            flowId = generate_flow_id(srcip, srcport, dstip, dstport, ipProtocol)
            #print_color("DEBUG: Flow Removal event from switch: "+ str(event.dpid) +" FlowID: ["+ flowId +"]", COLOR_DEBUG)

            # Clean up FlowsCollection
            if self.FlowsCollection.has_key(flowId):
                self.FlowsCollection.pop(flowId)

            # Clean up PathsCollection
            for endPoints in self.PathsCollection:
                for path in self.PathsCollection[endPoints]:
                    self.PathsCollection[endPoints][path]["Flows"].discard(flowId)



    #########################################################################################################################
    ### Called when openflow_discovery_LinkEvent is trigged following the detection of a new network link
    #########################################################################################################################
    def _handle_LinkEvent(self, event):  
        tmpSwitchsPathsList = []  # Temporary list for new links found between switchs
        link = event.link 
        #pp(link)
        dpid1 = link.dpid1 # Switch 1 ID 
        port1 = link.port1 # Switch 1 Port
        dpid2 = link.dpid2 # Switch 2 ID
        port2 = link.port2 # Switch 2 Port
        
        # Create new keys as needed
        if dpid1 not in self.adjs:
            self.adjs[dpid1] = set([])
        if dpid2 not in self.adjs:
            self.adjs[dpid2] = set([])

        # Add new links to data structures
        sw1sw2PortKey = str(dpid1) +"-"+ str(dpid2)
        sw2sw1PortKey = str(dpid2) +"-"+ str(dpid1)
        if event.added:
            self.adjs[dpid1].add(dpid2)
            self.adjs[dpid2].add(dpid1)
            self.SwitchPortUsedByLink[sw1sw2PortKey] = port1
            self.SwitchPortUsedByLink[sw2sw1PortKey] = port2
        elif event.removed: # Remove links that becomes unavailable
            if dpid2 in self.adjs[dpid1]:
                self.adjs[dpid1].remove(dpid2)
            if dpid1 in self.adjs[dpid2]:
                self.adjs[dpid2].remove(dpid1)
            if sw1sw2PortKey in self.SwitchPortUsedByLink:
                del self.SwitchPortUsedByLink[sw1sw2PortKey]
            if sw2sw1PortKey in self.SwitchPortUsedByLink:
                del self.SwitchPortUsedByLink[sw2sw1PortKey]
        
        #print "Liste d'adjacence:"
        #pp(self.adjs)
        #print "Switch to Switch used port:"
        #pp(self.SwitchPortUsedByLink)

        
        #print_color("Searching all possible paths...", COLOR_INFO)
        for pair in itertools.product(self.adjs, repeat=2): # Generate crossed product. Needed to test both way paths
            if not pair[0] == pair[1]:                      # Dont search a path if both switchs are the same..
                path = find_all_paths(self.adjs, pair[0], pair[1])
            
                for c in path:
                    if c not in tmpSwitchsPathsList:
                        tmpSwitchsPathsList.append(c)

        self.SwitchPathsCollection = deepcopy(tmpSwitchsPathsList)
        #pp(self.SwitchPathsCollection)
        # print(liste_chemins)
        #for path in tmpSwitchsPathsList: # Available Switch paths?
        #     print(path)




    #########################################################################################################################
    ### Called when a host interact with the network
    #########################################################################################################################
    def _handle_HostEvent(self, event):

        '''
            Dans event, on aura :
                l'adresse mac (event.entry.macaddr.toStr()) de l'hote connecte
                l'id du switch qui est connecte a l'hote
                le port entrant du switch 

            On peut obtenir la correspondance MAC/IP en envoyant une requete ARP et
            decoder la reponse. 
            Mais pour simplifier le code, on va tricher un peu pour ce projet.
            On va reconstruire l'adresse IP.
        '''
        #pp(event.entry)
        hostMAC = event.entry.macaddr.toStr()

        hostIP = "10.0.0."+re.sub("^0+(?!$)", "", hostMAC.split(':')[-1])

        dict_host_switch = {
            "mac": hostMAC,
            "ip" : hostIP,
            "switch" : event.entry.dpid,
            "port": event.entry.port
        } 
        
        # Keep the newly discovered host
        self.HostSwitchLinks.append(dict_host_switch)
        print_color("Discovered host "+ hostMAC +" with IP "+ hostIP, COLOR_ACTION)
        
        # Keep the switch port used to connect with this host
        self.SwitchPortUsedByLink[str(event.entry.dpid) +"-"+ hostIP] = event.entry.port
        #pp(self.SwitchPortUsedByLink)




    #########################################################################################################################
    ### Handle packets for which no routes exists
    #########################################################################################################################
    def _handle_PacketIn (self, event):
        ethPacket = event.parsed

        # Only handle IP Packets
        if ethPacket.type != ethernet.IP_TYPE:
            return
        ipPacket = ethPacket.payload
        srcip = ipPacket.srcip.toStr()
        dstip = ipPacket.dstip.toStr()
        endPointsForward = srcip +"-"+ dstip
        endPointsBackward = dstip +"-"+ srcip

        # Dont proceed if the hosts are not discovered yet... This is necessary in some situations.
        if not is_discovered_host_switch_link(self.HostSwitchLinks, srcip) or not is_discovered_host_switch_link(self.HostSwitchLinks, dstip):
            print_color("Packet Received, but waiting for host discovery...", COLOR_INFO)
            return


        ############################################
        # Paths Management
        ############################################
        # Find all paths between source and destination if they have not been calculated yet
        if not self.PathsCollection.has_key(endPointsForward):
            print_color("Discovered endpoints ["+ endPointsForward +"]. Calculating all available paths...", COLOR_ACTION)
            hostsPaths = find_all_hosts_paths(srcip, dstip, self.SwitchPathsCollection, self.HostSwitchLinks)
            allPaths = create_all_paths(hostsPaths, self.SwitchPortUsedByLink, srcip, dstip)
            self.PathsCollection[endPointsForward] = allPaths

        # Find all paths between destination and source if they have not been calculated yet
        if not self.PathsCollection.has_key(endPointsBackward):
            print_color("Discovered endpoints ["+ endPointsBackward +"]. Calculating all available paths...", COLOR_ACTION)
            hostsPaths = find_all_hosts_paths(dstip, srcip, self.SwitchPathsCollection, self.HostSwitchLinks)
            allPaths = create_all_paths(hostsPaths, self.SwitchPortUsedByLink, dstip, srcip)
            self.PathsCollection[endPointsBackward] = allPaths


        ############################################
        # Flows Management
        ############################################
        # Handle flow from source to destination
        forwardFlow = create_new_flow(ipPacket, True)   # Get forward Flow
        forwardFlowId = forwardFlow["FlowID"]
        
        if not self.FlowsCollection.has_key(forwardFlowId):
            print_color("Discovered Forward Flow ["+ forwardFlowId +"]", COLOR_ACTION)
            self.FlowsCollection[forwardFlowId] = forwardFlow                           # Add new flow to collection
            forwardRouteSelected = get_pathId_using_trunk_with_most_FreeCapacity(endPointsForward, self.PathsCollection, self.FlowsCollection) 
            choosenPath = self.PathsCollection[endPointsForward][forwardRouteSelected]  # Get that Path
            # DEBUG: Commented code below used to force a specific path for testing and debug
            '''
            if endPointsForward == "10.0.0.1-10.0.0.6":
                #forwardRouteSelected = "1-4-7-8-9-6-12" # 2 Mbps route
                forwardRouteSelected = "1-4-5-6-12"     # 3 Mbps route
                #forwardRouteSelected = "1-4-6-12"       # 4 Mbps route
                choosenPath = self.PathsCollection[endPointsForward][forwardRouteSelected] # Forward
            else:
                #forwardRouteSelected = "12-6-9-8-7-4-1" # 2 Mbps route
                forwardRouteSelected = "12-6-5-4-1"     # 3 Mbps route
                #forwardRouteSelected = "12-6-4-1"       # 4 Mbps route
                choosenPath = self.PathsCollection[endPointsForward][forwardRouteSelected] # Backward
            '''
            install_routing_rules_on_path_switchs(choosenPath, forwardFlow, self.TrackedSwitchs)      # Add rules on switchs for this flow
            self.PathsCollection[endPointsForward][forwardRouteSelected]["Flows"].add(forwardFlowId)  # Add FlowID to flows handled by the path

        # Handle flow from destination to source
        # Note: We are also using the path with the most FreeCapacity on the way back. (By design)
        #       The traffic from destination to source could use a different route (In the context of our experiment, it should)
        backwardFlow = create_new_flow(ipPacket, False) # Get backward Flow
        backwardFlowId = backwardFlow["FlowID"]

        if not self.FlowsCollection.has_key(backwardFlowId):
            print_color("Discovered Backward Flow ["+ backwardFlowId +"]", COLOR_ACTION)
            self.FlowsCollection[backwardFlowId] = backwardFlow
            backwardRouteSelected = get_pathId_using_trunk_with_most_FreeCapacity(endPointsBackward, self.PathsCollection, self.FlowsCollection)
            choosenPath = self.PathsCollection[endPointsBackward][backwardRouteSelected]
            # DEBUG: Commented code below used to force a specific path for testing
            '''
            if endPointsBackward == "10.0.0.6-10.0.0.1": # Forward
                #backwardRouteSelected = "12-6-9-8-7-4-1" # 2 Mbps route
                backwardRouteSelected = "12-6-5-4-1"     # 3 Mbps route
                #backwardRouteSelected = "12-6-4-1"       # 4 Mbps route
                choosenPath = self.PathsCollection[endPointsBackward][backwardRouteSelected]
            else:
                #backwardRouteSelected = "1-4-7-8-9-6-12" # 2 Mbps route
                backwardRouteSelected = "1-4-5-6-12"     # 3 Mbps route
                #backwardRouteSelected = "1-4-6-12"       # 4 Mbps route
                choosenPath = self.PathsCollection[endPointsBackward][backwardRouteSelected]
            '''
            install_routing_rules_on_path_switchs(choosenPath, backwardFlow, self.TrackedSwitchs)
            self.PathsCollection[endPointsBackward][backwardRouteSelected]["Flows"].add(backwardFlowId)




    #########################################################################################################################
    ### Called when receiving port stats from a switch
    #########################################################################################################################
    def _handle_PortStatsReceived(self, event):
        if event.connection.dpid in self.TrackedSwitchs: # Make sure the switch is part of our topology (should be the case)
            self.TrackedSwitchs[event.connection.dpid].process_ports_stats(event.stats, time.time()) # Process the received stats




    #########################################################################################################################
    ### Called when receiving flow stats from a switch
    #########################################################################################################################
    def _handle_FlowStatsReceived(self, event):
        dpid = event.connection.dpid
        if dpid in self.TrackedSwitchs: # Make sure the switch is part of our topology (should be the case)
            ############################################
            # Flow stats Management
            ############################################
            receptionTime = time.time() # Keep track on stats reception time
            
            # Process the received stats
            flowsStats = self.TrackedSwitchs[dpid].process_flow_stats(event.stats, receptionTime)
            
            # Update FlowsCollection
            for flowId in flowsStats:
                # Set new UsedBandwidth for this flow
                if self.FlowsCollection.has_key(flowId):
                    self.FlowsCollection[flowId]["UsedBandwidth"] = flowsStats[flowId]["UsedBandwidth"]
            

            # Update UsedBandwidth and FreeCapacity for each paths of all endPoints in PathsCollection
            for endPoints in self.PathsCollection:
                for pathId in self.PathsCollection[endPoints]:
                    # DEBUG: These 2 lines are only used for debug
                    #debugOldUsedBandwidth = str(self.PathsCollection[endPoints][pathId]["UsedBandwidth"])
                    #debugOldFreeCapacity = str(self.PathsCollection[endPoints][pathId]["FreeCapacity"])

                    # Reset UsedBandwitdh & FreeCapacity. Will be recalculated
                    pathCapacity = self.PathsCollection[endPoints][pathId]["Capacity"]
                    self.PathsCollection[endPoints][pathId]["FreeCapacity"] = pathCapacity
                    pathUsedBandwidth = 0
                    
                    # Loop all the flows to calculate FreeCapacity of this path
                    for flowId in self.PathsCollection[endPoints][pathId]["Flows"]:
                        # Add Flow UsedBandwitdh to Path
                        flowUsedBandwidth = self.FlowsCollection[flowId]["UsedBandwidth"]
                        pathUsedBandwidth += flowUsedBandwidth
                        
                    # Never go below 0
                    pathFreeCapacity = pathCapacity - pathUsedBandwidth
                    if pathFreeCapacity < 0:
                        pathFreeCapacity = 0
                    
                    # Set the new calculated bandwidth values
                    self.PathsCollection[endPoints][pathId]["FreeCapacity"] = pathFreeCapacity
                    self.PathsCollection[endPoints][pathId]["UsedBandwidth"] = pathUsedBandwidth

                    # DEBUG: The next block is only used for debug
                    #debugNewUsedBandwidth = str(pathUsedBandwidth)
                    #debugNewFreeCapacity = str(self.PathsCollection[endPoints][pathId]["FreeCapacity"])
                    #debugPathId = self.PathsCollection[endPoints][pathId]["PathID"]
                    #if debugOldUsedBandwidth != debugNewUsedBandwidth and debugOldFreeCapacity != debugNewFreeCapacity:
                    #    print_color("DEBUG: Path: ["+ debugPathId +"]", COLOR_DEBUG)
                    #    print_color("DEBUG: Old UsedBandwidth: "+ debugOldUsedBandwidth +" Old FreeCapacity: "+ debugOldFreeCapacity, COLOR_DEBUG)
                    #    print_color("DEBUG: New UsedBandwidth: "+ debugNewUsedBandwidth +" New FreeCapacity: "+ debugNewFreeCapacity, COLOR_DEBUG)
                    

            ############################################
            # Congestion Management
            ############################################
            trunkStats = {} # Keep stats of the network trunks

            # Calculate the sum of all flow on the trunks
            for endPoints in self.PathsCollection:
                for pathId in self.PathsCollection[endPoints]:
                    for flowId in self.PathsCollection[endPoints][pathId]["Flows"]:
                        if self.FlowsCollection[flowId]["UsedBandwidth"] > 0:
                            # Create trunkId by removing first and last switch of a path
                            trunkId = '-'.join(map(str, self.PathsCollection[endPoints][pathId]["Hops"][1:-1]))

                            # Init if a new trunk is found
                            if not trunkStats.has_key(trunkId):
                                trunkStats[trunkId] = {}
                                trunkStats[trunkId]["Capacity"] = self.PathsCollection[endPoints][pathId]["Capacity"]
                                trunkStats[trunkId]["TotalUsed"] = 0
                                trunkStats[trunkId]["InvolvedFlows"] = set()
                            trunkStats[trunkId]["TotalUsed"] += self.FlowsCollection[flowId]["UsedBandwidth"]
                            trunkStats[trunkId]["InvolvedFlows"].add(flowId) # Keep track of the flow causing congestion


            # Proceed with congestion check & management
            for trunkId in trunkStats:
                congestion = False # Track congestion detection in this loop
                capacity = trunkStats[trunkId]["Capacity"]
                totalUsed = trunkStats[trunkId]["TotalUsed"]
                if totalUsed > capacity:
                    totalUsed = apply_speed_burst_margin(totalUsed) # Apply burst margin. This could prevent some unneeded reroute

                # Handle congestion on path IF totalUsed > capacity AND reroute has not been triggered within the defined delay
                # Note: The program support defining a delay before another reroute could be triggered. This avoid
                #       unnecessary reroutes while we are waiting for the network to rebalance and stabilize
                if (totalUsed > capacity and (self.LastRerouteTriggered + CONGESTION_RETRIGGER_DELAY) < time.time()):
                    #print_color("DEBUG: Congestion detected! Trunk: ["+ trunkId +"] "+ str(totalUsed) +" out of "+ str(capacity) +" Mbps", COLOR_DEBUG)
                    congestion = True

                    # Track congestion events
                    if not self.TrackPathCongestion.has_key(trunkId):
                        # First congestion detected
                        self.TrackPathCongestion[trunkId] = {}
                        self.TrackPathCongestion[trunkId]["CongestionTime"] = receptionTime # Keep track of the last congestion report
                        self.TrackPathCongestion[trunkId]["CongestionSwitch"] = set()       # Keep track of switchs reporting congestion for path
                        self.TrackPathCongestion[trunkId]["CongestionSwitch"].add(dpid)
                        self.TrackPathCongestion[trunkId]["CongestionCount"] = 1            # Congestion count of successive stats checks
                        print_color("Congestion detected! Trunk: ["+ trunkId +"] "+ str(totalUsed) +" out of "+ str(capacity) +" Mbps", COLOR_INFO)

                    else:
                        # Congestion still exist on next stats check

                        # Make sure this detection is not part of the same stats check period. This prevent multithreading issues
                        congestionTime = self.TrackPathCongestion[trunkId]["CongestionTime"]
                        elapsedTime = receptionTime - congestionTime
                        elapsedTime = int(elapsedTime)
                        if elapsedTime == PERIODIC_CHECK_DELAY:
                            # Delay has passed. Congestion is considered valid as it is part of the next stats check
                            self.TrackPathCongestion[trunkId]["CongestionTime"] = receptionTime
                            self.TrackPathCongestion[trunkId]["CongestionCount"] = self.TrackPathCongestion[trunkId]["CongestionCount"] + 1
                            self.TrackPathCongestion[trunkId]["CongestionSwitch"].add(dpid) # Add reporting switch
                            congestionCountMsgStr = str(self.TrackPathCongestion[trunkId]["CongestionCount"])
                            print_color("Persisting congestion on trunk: ["+ trunkId +"]. Detection count is now: "+ congestionCountMsgStr, COLOR_INFO)

                        # Check if congestion count match reroute algoritm trigger value
                        # Note: The program support defining a specified amount of 
                        #       congestion detections before triggering a reroute
                        if self.TrackPathCongestion[trunkId]["CongestionCount"] == CONGESTION_CHECK_COUNT_TRIGGER:
                            # Congestion successively detected CONGESTION_CHECK_COUNT_TRIGGER time. Trigger reroute! 
                            print_color("Congestion count exceeded for trunk ["+ trunkId +"] Triggering reroute!", COLOR_ACTION)
                            self.LastRerouteTriggered = time.time()

                            # Init flowToReroute with a random Flow known to cause congestion
                            randomFlowId = next(iter(trunkStats[trunkId]["InvolvedFlows"]))
                            flowToReroute = self.FlowsCollection[randomFlowId]

                            # Find the smallest flow among all endPoints that are using the congested path
                            for flowId in trunkStats[trunkId]["InvolvedFlows"]:
                                flowUsedBandwidth = self.FlowsCollection[flowId]["UsedBandwidth"]

                                if flowUsedBandwidth != 0 and flowUsedBandwidth < flowToReroute["UsedBandwidth"]:
                                    flowToReroute = self.FlowsCollection[flowId]
                                    #print_color("DEBUG: New smallest Flow to reroute: ["+ str(flowToReroute) +"]", COLOR_DEBUG)
                            #print_color("DEBUG: Final Flow to reroute: ["+ str(flowToReroute) +"]", COLOR_DEBUG)
                            flowToRerouteId = flowToReroute["FlowID"]

                            # Reduce burst margin to fit the flow in a path if bandwidth is tight
                            flowToRerouteBandwidth = apply_speed_burst_margin(flowToReroute["UsedBandwidth"])

                            # Recreate EndPoints for this Flow
                            flowToRerouteEndPoints = flowToReroute["SrcIP"] +"-"+ flowToReroute["DstIP"]

                            # Find the path with to most FreeCapacity to pickup that Flow
                            newSelectedPath = get_pathId_using_trunk_with_most_FreeCapacity(flowToRerouteEndPoints, self.PathsCollection, self.FlowsCollection)
                            print_color("Rerouting Flow ["+ flowToRerouteId +"] through Path: ["+ newSelectedPath +"]", COLOR_ACTION)
                            choosenPath = self.PathsCollection[flowToRerouteEndPoints][newSelectedPath]
                            
                            # Find the previously used path for this flow
                            for pathId in self.PathsCollection[flowToRerouteEndPoints]:
                                if flowToRerouteId in self.PathsCollection[flowToRerouteEndPoints][pathId]["Flows"]:
                                    previousPathId = self.PathsCollection[flowToRerouteEndPoints][pathId]["PathID"]
                                    #print "Found flow in previous path:["+ previousPathId +"]."
                            previousPath = self.PathsCollection[flowToRerouteEndPoints][previousPathId]
                            
                            # Remove routes from switchs on previous path
                            remove_routing_rules_on_path_switchs(previousPath, flowToReroute, self.TrackedSwitchs)
                            
                            # Install new routes on switches
                            install_routing_rules_on_path_switchs(choosenPath, flowToReroute, self.TrackedSwitchs)
                            
                            # Swap the flow to the new Path in PathsCollection
                            self.PathsCollection[flowToRerouteEndPoints][previousPathId]["Flows"].remove(flowToRerouteId)
                            self.PathsCollection[flowToRerouteEndPoints][newSelectedPath]["Flows"].add(flowToRerouteId)

                            # Reset congestion count
                            self.TrackPathCongestion.pop(pathId, None)

                            # Dont trigger more than one reroute in the same period
                            break


                # Handle reset of congestion count for path while taking care of potential multithreading issues
                if congestion == False:
                    # No congestion detected on this stats check for path, delete any previous detection
                    if self.TrackPathCongestion.has_key(trunkId):
                        # Only a switch that had previously reported congestion can proceed in saying there is no more congestion
                        if dpid in self.TrackPathCongestion[trunkId]["CongestionSwitch"]:
                            # Make sure we are not in the same stats check period
                            elapsedTime = receptionTime - self.TrackPathCongestion[trunkId]["CongestionTime"]
                            if elapsedTime >= PERIODIC_CHECK_DELAY:
                                # Not same period. A switch can then retire itself from the congestion report
                                self.TrackPathCongestion[trunkId]["CongestionSwitch"].remove(dpid)

                                # If no more switch are congestested on this path, we can safely delete that congestion report
                                if self.TrackPathCongestion[trunkId]["CongestionSwitch"] == set():
                                    self.TrackPathCongestion.pop(trunkId, None)
                                    print_color("Congestion ended. Removed congestion tracking of trunk ["+ trunkId +"]", COLOR_INFO)




###############################################################################
### Define a class that will be used to track a switch
###############################################################################
class TrackedSwitch(EventMixin):
    def __init__(self, flow_tracker):
        self.connection = None
        self.isConnected = False
        self.dpid = None
        self._listeners = None
        self._timerPortStatsPeriodicCheck = None  # Store port stats Timer class
        self._timerFlowStatsPeriodicCheck = None  # Store flow stats Timer class
        self._connectionTime = None
        self._lastPortStatsRequestSentTime = None

        self._lastFlowStatsProcessTime = time.time()  # Keep track of the last Flow stats process time
        self._trackedFlowsStats = {}                  # Keep last ByteCount and UsedBandwidth for each flows

    # Define print representation
    def __repr__(self):
        return dpid_to_str(self.dpid)



    #########################################################################################################################
    ### Start recurrent tracking for this switch
    #########################################################################################################################
    def start_stats_tracking(self, connection):
        if self.dpid is None:
            self.dpid = connection.dpid
        assert self.dpid == connection.dpid

        self.connection = connection
        self.isConnected = True
        self._listeners = self.listenTo(connection)
        self._connectionTime = time.time()
        self._timerPortStatsPeriodicCheck = Timer(PERIODIC_CHECK_DELAY, self.send_port_stats_request, recurring=True)
        self._timerFlowStatsPeriodicCheck = Timer(PERIODIC_CHECK_DELAY, self.send_flow_stats_request, recurring=True)




    #########################################################################################################################
    ### Send a port stats request to the switch
    #########################################################################################################################
    def send_port_stats_request(self):
        if self.isConnected:
            self.connection.send(of.ofp_stats_request(body=of.ofp_port_stats_request())) # Send a port stats request to the switch
            self._lastPortStatsRequestSentTime = time.time()
            #print_color("DEBUG: Port Stats request sent to "+ dpid_to_str(self.dpid), COLOR_DEBUG)




    #########################################################################################################################
    ### Send a flow stats request to the switch
    #########################################################################################################################
    def send_flow_stats_request(self):
        if self.isConnected:
            self.connection.send(of.ofp_stats_request(body=of.ofp_flow_stats_request())) # Send a flow stats request to the switch
            #print_color("DEBUG: Flow Stats request sent to "+ dpid_to_str(self.dpid), COLOR_DEBUG)




    #########################################################################################################################
    ### Process the port stats that have been received by the controller
    #########################################################################################################################
    def process_ports_stats(self, stats, receptionTime):
        # Switch has to be connected
        if not self.isConnected:
            return
        # Note: This is not needed as we are handling both the stats generation and congestion detection through the flows
        #       This method has been validated and authorized by email on December 18.
        

        #if self.dpid == 4:
        #print("************************************")
        #print "Port stats received for Switch ", self.dpid
        #for port in stats:
        #    if port.port_no != 65534:
        #        print port.port_no
        #        print vars(port)
            
            #print(stats) # Print object for now...
            #print(vars(stats[0])) # One in the list for each port 

            #print("------------------------------------")




    #########################################################################################################################
    ### Process the flow stats that have been received by the controller
    #########################################################################################################################
    def process_flow_stats(self, stats, receptionTime):
        # Switch has to be connected
        if not self.isConnected:
            return

        flowStats = {} # Same as _trackedFlowsStats, will replace it just before return

        # Process stats for all flows
        for flow in stats:
            # Only care about IP stats
            if flow.match.nw_src is not None and flow.match.nw_dst is not None:
                # Extract usefull headers
                srcip = flow.match.nw_src.toStr()
                srcport = flow.match.tp_src
                dstip = flow.match.nw_dst.toStr()
                dstport = flow.match.tp_dst
                ipProtocol = flow.match.nw_proto

                # Recreate Flow ID
                flowId = generate_flow_id(srcip, srcport, dstip, dstport, ipProtocol)

                # Try to get previous byte_count of known flow
                if self._trackedFlowsStats.has_key(flowId):
                    previousByteCount = self._trackedFlowsStats[flowId]["ByteCount"]
                else:
                    previousByteCount = 0
                
                # If flow has traffic, proceed with datarate calculation
                if flow.byte_count > previousByteCount:
                    period = receptionTime - self._lastFlowStatsProcessTime  # Get the period
                    periodByteCount = flow.byte_count - previousByteCount    # Get byte count for period
                    bits = periodByteCount * 8                               # Swap to bits
                    mbps = (bits / period) / 1000000                         # Calculate Mbps rate
                else:
                    mbps = 0 # No traffic

                #print_color("DEBUG: Switch: "+ str(self.dpid) +" FlowID: "+ flowId +" Mbps: "+ str(mbps), COLOR_DEBUG)

                # Set byte_count for next time and update UsedBandwidth
                flowStats[flowId] = {}
                flowStats[flowId]["ByteCount"] = flow.byte_count
                flowStats[flowId]["UsedBandwidth"] = mbps

        # Update last flow stats proccess time
        self._lastFlowStatsProcessTime = receptionTime

        # Replace to keep _trackedFlowsStats clean
        self._trackedFlowsStats = flowStats

        # Return will be used to set UsedBandwidth for each flows in the main class
        return flowStats




    #########################################################################################################################
    ### Install flow routing rules to the switch routing table
    #########################################################################################################################
    def add_flow_routing_rules(self, outPort, flow):
        if not self.isConnected:
            return
        #print_color("DEBUG: Adding flow routing rules to switch: "+ str(self.dpid), COLOR_DEBUG)

        #pp(flow)

        # Define what we will match for this flow
        match = of.ofp_match()
        match.dl_type = 0x800                      # IPv4
        match.nw_proto = flow["Protocol"]          # IP Protocol 
        match.nw_src = IPAddr(flow["SrcIP"])       # IP Source
        match.tp_src = flow["SrcPort"]             # TCP Port Source
        match.nw_dst = IPAddr(flow["DstIP"])       # IP Destination
        match.tp_dst = flow["DstPort"]             # TCP Port Destination
        
        # Modification of the table on the switch to apply the new rule
        mod = of.ofp_flow_mod()
        mod.flags = of.OFPFF_SEND_FLOW_REM         # Get a notification when rule expire. This is needed to clean our data structures
        mod.idle_timeout = MODFLOW_IDLE_TIMEOUT    # Set rule idle time out
        #mod.priority = 1000
        mod.match = match
        mod.actions.append(of.ofp_action_output(port = outPort))
        self.connection.send(mod)




    #########################################################################################################################
    ### Remove a flow routing rules from the switch routing table
    #########################################################################################################################
    def remove_flow_routing_rules(self, flow):
        if not self.isConnected:
            return
        #print_color("DEBUG: Removing a flow routing rules to switch: "+ str(self.dpid), COLOR_DEBUG)

        #pp(flow)

        # Define match for the flow we want to remove
        match = of.ofp_match()
        match.dl_type = 0x800                      # IPv4
        match.nw_proto = flow["Protocol"]          # IP Protocol 
        match.nw_src = IPAddr(flow["SrcIP"])       # IP Source
        match.tp_src = flow["SrcPort"]             # TCP Port Source
        match.nw_dst = IPAddr(flow["DstIP"])       # IP Destination
        match.tp_dst = flow["DstPort"]             # TCP Port Destination
        
        # Remove the rule from the table on the switch
        rm = of.ofp_flow_mod(command=of.OFPFC_DELETE)
        #rm.priority = 1000
        rm.match = match
        self.connection.send(rm)




###############################################################################
### Register new module into POX
def launch():
    # Skip the INFO and keep console msg clean. This should be set to INFO or DEBUG when developing
    core.getLogger("").setLevel("ERROR")             # Core module
    core.getLogger("host_tracker").setLevel("ERROR") # host_tracker

    core.registerNew(RouteDyn)
