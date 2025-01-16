from pox.core import core
import pox.openflow.libopenflow_01 as of

log = core.getLogger()

class Part3Controller(object):
    def __init__(self, connection):
        self.connection = connection
        self.dpid = connection.dpid  # Datapath ID for the switch
        connection.addListeners(self)
        self.install_rules()

    def install_rules(self):
        # Add flooding rules for secondary switches
        if self.dpid in [1, 2, 3, 4]:  # Secondary switches: s1, s2, s3, dcs31
            self.add_flood_rule()
        elif self.dpid == 21:  # Core switch: cores21
            self.add_core_rules()

    def add_flood_rule(self):
        # Flood traffic on secondary switches
        msg = of.ofp_flow_mod()
        msg.priority = 10
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        self.connection.send(msg)
        log.info(f"Flood rule installed on switch {self.dpid}")

    def add_core_rules(self):
        # Core switch: Route based on destination IP
        # Route traffic to h10 (subnet 10.0.1.0/24)
        self.add_routing_rule("10.0.1.0/24", 1)
        # Route traffic to h20 (subnet 10.0.2.0/24)
        self.add_routing_rule("10.0.2.0/24", 2)
        # Route traffic to h30 (subnet 10.0.3.0/24)
        self.add_routing_rule("10.0.3.0/24", 3)
        # Route traffic to serv1 (subnet 10.0.4.0/24)
        self.add_routing_rule("10.0.4.0/24", 4)

        # Block all IP traffic from hnotrust1 to serv1
        self.add_block_rule("172.16.10.100", "10.0.4.10", 0x0800)

        # Block ICMP traffic from hnotrust1 to internal hosts
        self.add_block_rule("172.16.10.100", "10.0.0.0/8", 0x0800, nw_proto=1)

    def add_routing_rule(self, nw_dst, port):
        msg = of.ofp_flow_mod()
        msg.priority = 20
        msg.match.dl_type = 0x0800  # IP traffic
        msg.match.nw_dst = nw_dst
        msg.actions.append(of.ofp_action_output(port=port))
        self.connection.send(msg)
        log.info(f"Routing rule for {nw_dst} -> port {port} added on switch {self.dpid}")

    def add_block_rule(self, nw_src, nw_dst, dl_type, nw_proto=None):
        msg = of.ofp_flow_mod()
        msg.priority = 30
        msg.match.dl_type = dl_type  # Match on IP traffic
        msg.match.nw_src = nw_src
        msg.match.nw_dst = nw_dst
        if nw_proto is not None:
            msg.match.nw_proto = nw_proto  # Optional: Match on ICMP
        self.connection.send(msg)
        log.info(f"Block rule: {nw_src} -> {nw_dst} added on switch {self.dpid}")

    def _handle_PacketIn(self, event):
        # Log unhandled packets
        log.info(f"Unhandled packet from switch {self.dpid}: {event.parsed}")

def launch():
    def start_switch(event):
        log.info(f"Switch {event.connection.dpid} connected")
        Part3Controller(event.connection)

    core.openflow.addListenerByName("ConnectionUp", start_switch)
