def _handle_PacketIn(self, event):
    """
    Handles incoming packets and decides how to process them.
    """
    packet = event.parsed
    if not packet.parsed:
        log.warning("Ignoring incomplete packet")
        return

    packet_in = event.ofp

    # Drop IPv6 packets (Ethernet type 0x86DD = 34525)
    if packet.type == pkt.ethernet.IPV6_TYPE:
        log.debug("Dropping unsupported IPv6 packet")
        return

    # Handle ARP packets
    if packet.type == pkt.ethernet.ARP_TYPE:
        self.handle_arp(packet, packet_in)
        return

    # Handle IPv4 packets
    if packet.type == pkt.ethernet.IP_TYPE:
        ipv4 = packet.payload

        # Drop DNS packets explicitly (UDP packets with port 53)
        if ipv4.protocol == pkt.ipv4.UDP_PROTOCOL:
            udp = ipv4.payload
            if udp.srcport == 53 or udp.dstport == 53:  # DNS traffic
                log.debug("Dropping unsupported DNS packet")
                return

        # Process IP packets
        self.handle_ip(packet, packet_in)
        return

    # Log and skip unsupported packet types
    log.debug(f"Unsupported packet type: {packet.type}")
