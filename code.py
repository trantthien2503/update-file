from pox.core import core
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt
from pox.lib.addresses import IPAddr, EthAddr

log = core.getLogger()

class Part4Controller(object):
    def __init__(self, connection):
        self.connection = connection
        self.arp_table = {}  # Map IP -> (MAC, port)
        self.connection.addListeners(self)

    def handle_arp(self, packet, packet_in):
        arp = packet.payload
        if arp.opcode == pkt.arp.REQUEST:
            # Handle ARP Request
            log.debug(f"Received ARP REQUEST for {arp.protodst}")
            if IPAddr(arp.protodst) in self.arp_table:
                # Generate ARP reply
                reply = pkt.arp()
                reply.hwsrc = self.arp_table[IPAddr(arp.protodst)][0]  # MAC of destination
                reply.hwdst = arp.hwsrc
                reply.opcode = pkt.arp.REPLY
                reply.protosrc = arp.protodst
                reply.protodst = arp.protosrc

                # Build Ethernet frame
                ether = pkt.ethernet()
                ether.type = pkt.ethernet.ARP_TYPE
                ether.src = reply.hwsrc
                ether.dst = reply.hwdst
                ether.payload = reply

                # Send ARP reply
                msg = of.ofp_packet_out()
                msg.data = ether.pack()
                msg.actions.append(of.ofp_action_output(port=packet_in.in_port))
                self.connection.send(msg)
            else:
                log.debug(f"ARP request for unknown IP {arp.protodst}")
        elif arp.opcode == pkt.arp.REPLY:
            # Learn ARP reply
            log.debug(f"Received ARP REPLY: {arp.protosrc} -> {arp.hwsrc}")
            self.arp_table[IPAddr(arp.protosrc)] = (EthAddr(arp.hwsrc), packet_in.in_port)

    def handle_ip(self, packet, packet_in):
        ipv4 = packet.payload
        dst_ip = ipv4.dstip

        if dst_ip in self.arp_table:
            mac, out_port = self.arp_table[dst_ip]
            # Forward packet with updated L2 headers
            log.debug(f"Forwarding packet to {dst_ip} via port {out_port}")
            actions = [
                of.ofp_action_dl_addr.set_dst(mac),
                of.ofp_action_output(port=out_port)
            ]
            msg = of.ofp_packet_out()
            msg.data = packet_in
            msg.actions.extend(actions)
            self.connection.send(msg)
        else:
            log.debug(f"Unknown IP {dst_ip}. Flooding packet")
            # Flood the packet if destination is unknown
            msg = of.ofp_packet_out()
            msg.data = packet_in
            msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
            self.connection.send(msg)

    def _handle_PacketIn(self, event):
        packet = event.parsed
        if not packet.parsed:
            log.warning("Ignoring incomplete packet")
            return

        packet_in = event.ofp

        # Drop IPv6 packets
        if packet.type == pkt.ethernet.IPV6_TYPE:
            log.debug("Dropping unsupported IPv6 packet")
            return

        # Handle ARP packets
        if packet.type == pkt.ethernet.ARP_TYPE:
            self.handle_arp(packet, packet_in)
            return

        # Handle IP packets
        elif packet.type == pkt.ethernet.IP_TYPE:
            self.handle_ip(packet, packet_in)
            return

        # Log unsupported packet types
        log.debug(f"Unsupported packet type: {packet.type}")

def launch():
    def start_switch(event):
        log.debug(f"Controlling {event.connection}")
        Part4Controller(event.connection)
    core.openflow.addListenerByName("ConnectionUp", start_switch)
