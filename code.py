from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.arp import arp
from pox.lib.packet.ipv4 import ipv4
from pox.lib.addresses import EthAddr, IPAddr

log = core.getLogger()

class Part4Controller(object):
    def __init__(self, connection):
        self.connection = connection
        self.dpid = connection.dpid  # Datapath ID for the switch
        self.arp_table = {}  # L3 -> L2 mappings (IP -> (port, MAC))
        connection.addListeners(self)

        # Install default rules
        if self.dpid in [1, 2, 3, 4]:  # Secondary switches
            self.install_flood_rule()
        elif self.dpid == 21:  # Core switch (cores21)
            self.install_block_rules()

    def install_flood_rule(self):
        # Flood traffic on secondary switches
        msg = of.ofp_flow_mod()
        msg.priority = 10
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        self.connection.send(msg)
        log.info(f"Flood rule installed on switch {self.dpid}")

    def install_block_rules(self):
        # Block IP traffic from hnotrust1 to serv1
        self.add_block_rule("172.16.10.100", "10.0.4.10", 0x0800)

        # Block ICMP traffic from hnotrust1 to internal hosts and serv1
        self.add_block_rule("172.16.10.100", "10.0.0.0/8", 0x0800, nw_proto=1)

    def add_block_rule(self, nw_src, nw_dst, dl_type, nw_proto=None):
        msg = of.ofp_flow_mod()
        msg.priority = 30
        msg.match.dl_type = dl_type
        msg.match.nw_src = nw_src
        msg.match.nw_dst = nw_dst
        if nw_proto is not None:
            msg.match.nw_proto = nw_proto
        self.connection.send(msg)
        log.info(f"Block rule: {nw_src} -> {nw_dst} installed on cores21")

    def _handle_PacketIn(self, event):
        packet = event.parsed

        # Handle ARP packets
        if packet.type == ethernet.ARP_TYPE:
            self.handle_arp(packet, event)
            return

        # Handle IPv4 packets
        if packet.type == ethernet.IP_TYPE:
            self.handle_ip(packet, event)
            return

    def handle_arp(self, packet, event):
        arp_pkt = packet.payload

        # Learn ARP mappings
        self.arp_table[arp_pkt.protosrc] = (event.port, packet.src)
        log.info(f"Learned ARP mapping: {arp_pkt.protosrc} -> {packet.src} on port {event.port}")

        # Respond to ARP requests for the gateway
        if arp_pkt.opcode == arp.REQUEST and self.is_gateway(arp_pkt.protodst):
            self.send_arp_reply(arp_pkt, event.port)

    def send_arp_reply(self, arp_pkt, port):
        # Create ARP reply
        arp_reply = arp()
        arp_reply.opcode = arp.REPLY
        arp_reply.hwdst = arp_pkt.hwsrc
        arp_reply.protodst = arp_pkt.protosrc
        arp_reply.hwsrc = EthAddr("00:00:00:00:00:01")  # Example MAC for gateway
        arp_reply.protosrc = arp_pkt.protodst

        # Create Ethernet frame
        eth = ethernet()
        eth.type = ethernet.ARP_TYPE
        eth.src = EthAddr("00:00:00:00:00:01")  # Example MAC for gateway
        eth.dst = arp_pkt.hwsrc
        eth.payload = arp_reply

        # Send ARP reply
        msg = of.ofp_packet_out()
        msg.data = eth.pack()
        msg.actions.append(of.ofp_action_output(port=port))
        self.connection.send(msg)
        log.info(f"Sent ARP reply for {arp_pkt.protodst} to {arp_pkt.protosrc}")

    def is_gateway(self, ip):
        gateways = ["10.0.1.1", "10.0.2.1", "10.0.3.1", "10.0.4.1", "172.16.10.1"]
        return ip in gateways

    def handle_ip(self, packet, event):
        ip_pkt = packet.payload

        # Learn source IP mapping
        self.arp_table[ip_pkt.srcip] = (event.port, packet.src)

        # Forward packet if destination IP is known
        if ip_pkt.dstip in self.arp_table:
            port, mac = self.arp_table[ip_pkt.dstip]
            self.install_forwarding_rule(ip_pkt.dstip, mac, port)
            self.forward_packet(packet, port)
        else:
            log.info(f"Unknown destination {ip_pkt.dstip}, dropping packet")

    def install_forwarding_rule(self, nw_dst, dst_mac, port):
        msg = of.ofp_flow_mod()
        msg.priority = 20
        msg.match.dl_type = 0x0800
        msg.match.nw_dst = nw_dst
        msg.actions.append(of.ofp_action_dl_addr.set_dst(dst_mac))
        msg.actions.append(of.ofp_action_output(port=port))
        self.connection.send(msg)
        log.info(f"Installed forwarding rule for {nw_dst} -> port {port}")

    def forward_packet(self, packet, port):
        msg = of.ofp_packet_out()
        msg.data = packet.pack()
        msg.actions.append(of.ofp_action_output(port=port))
        self.connection.send(msg)

def launch():
    def start_switch(event):
        log.info(f"Switch {event.connection.dpid} connected")
        Part4Controller(event.connection)

    core.openflow.addListenerByName("ConnectionUp", start_switch)
