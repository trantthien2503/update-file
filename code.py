from pox.core import core
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt
from pox.lib.addresses import IPAddr, EthAddr

log = core.getLogger()

# Static IP and MAC definitions (replace with dynamic learning)
IPS = {
    "h10": ("10.0.1.10", "00:00:00:00:00:01"),
    "h20": ("10.0.2.20", "00:00:00:00:00:02"),
    "h30": ("10.0.3.30", "00:00:00:00:00:03"),
    "serv1": ("10.0.4.10", "00:00:00:00:00:04"),
    "hnotrust1": ("172.16.10.100", "00:00:00:00:00:05"),
}

class Part4Controller(object):
    def __init__(self, connection):
        self.connection = connection
        self.arp_table = {}  # Dynamic mapping of IP -> (MAC, port)
        self.connection.addListeners(self)

    def handle_arp(self, packet, packet_in):
        arp = packet.payload
        if arp.opcode == pkt.arp.REQUEST:
            # ARP Request: Generate ARP Reply if we are the target
            if IPAddr(arp.protodst) in self.arp_table:
                reply = pkt.arp()
                reply.hwsrc = self.arp_table[IPAddr(arp.protodst)][0]  # Our MAC
                reply.hwdst = arp.hwsrc  # Requester's MAC
                reply.opcode = pkt.arp.REPLY
                reply.protosrc = arp.protodst  # Our IP
                reply.protodst = arp.protosrc

                ether = pkt.ethernet()
                ether.type = pkt.ethernet.ARP_TYPE
                ether.src = reply.hwsrc
                ether.dst = reply.hwdst
                ether.payload = reply

                msg = of.ofp_packet_out()
                msg.data = ether.pack()
                msg.actions.append(of.ofp_action_output(port=packet_in.in_port))
                self.connection.send(msg)
            else:
                log.debug("Unknown ARP request for %s", arp.protodst)
        elif arp.opcode == pkt.arp.REPLY:
            # Learn the ARP reply information
            self.arp_table[IPAddr(arp.protosrc)] = (EthAddr(arp.hwsrc), packet_in.in_port)

    def handle_ip(self, packet, packet_in):
        ipv4 = packet.payload
        dst_ip = ipv4.dstip

        if dst_ip in self.arp_table:
            mac, out_port = self.arp_table[dst_ip]
            # Modify L2 header and forward
            msg = of.ofp_packet_out()
            msg.data = packet_in
            msg.actions.append(of.ofp_action_dl_addr.set_dst(mac))
            msg.actions.append(of.ofp_action_output(port=out_port))
            self.connection.send(msg)
        else:
            log.debug("Unknown IP %s", dst_ip)

    def _handle_PacketIn(self, event):
        packet = event.parsed
        if not packet.parsed:
            log.warning("Ignoring incomplete packet")
            return

        packet_in = event.ofp
        if packet.type == pkt.ethernet.ARP_TYPE:
            self.handle_arp(packet, packet_in)
        elif packet.type == pkt.ethernet.IP_TYPE:
            self.handle_ip(packet, packet_in)

    def install_flow_rule(self, match, actions, priority=10):
        msg = of.ofp_flow_mod()
        msg.match = match
        msg.actions = actions
        msg.priority = priority
        self.connection.send(msg)

def launch():
    def start_switch(event):
        log.debug("Controlling %s", event.connection)
        Part4Controller(event.connection)
    core.openflow.addListenerByName("ConnectionUp", start_switch)
