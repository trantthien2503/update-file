# Part 2 of Project 2

from pox.core import core
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt

log = core.getLogger()

class Firewall (object):
  """
  A Firewall object is created for each switch that connects.
  A Connection object for that switch is passed to the __init__ function.
  """
  def __init__ (self, connection):
    # Keep track of the connection to the switch so that we can
    # send it messages!
    self.connection = connection

    # This binds our PacketIn event listener
    connection.addListeners(self)

    # send the message to the switch: ARP and IPv4 traffic to all ports (non-sender)
    connection.send(of.ofp_flow_mod(action=of.ofp_action_output(port=of.OFPP_FLOOD),
					priority=10,
    		    			match=of.ofp_match(dl_type=0x0800, nw_proto=pkt.ipv4.ICMP_PROTOCOL)))	# ipv4: icmp
    connection.send(of.ofp_flow_mod(action=of.ofp_action_output(port=of.OFPP_FLOOD),
    		    			priority=9,
    		    			match=of.ofp_match(dl_type=0x0806)))	# arp
    self.connection.send(of.ofp_flow_mod(action=of.ofp_action_output(port=of.OFPP_IN_PORT),
					priority=8,
    		    			match=of.ofp_match(dl_type=0x86dd)))	# send ipv6 back
    self.connection.send(of.ofp_flow_mod(action=of.ofp_action_output(port=of.OFPP_IN_PORT),
					priority=7,
    		    			match=of.ofp_match(dl_type=0x0800)))	# send ipv4 back

  def _handle_PacketIn (self, event):
    """
    Packets not handled by the router rules will be
    forwarded to this method to be handled by the controller
    """

    packet = event.parsed # This is the parsed packet data.
    if not packet.parsed:
      log.warning("Ignoring incomplete packet")
      return

    packet_in = event.ofp # The actual ofp_packet_in message.
    print ("Unhandled packet :" + str(packet.dump()))

def launch ():
  """
  Starts the component
  """
  def start_switch (event):
    log.debug("Controlling %s" % (event.connection,))
    Firewall(event.connection)
  core.openflow.addListenerByName("ConnectionUp", start_switch)
