from mininet.topo import Topo

class Part4Topo(Topo):
    """
    Topology for Part 4:
      - Hosts (h10, h20, h30, serv1, hnotrust1)
      - Edge switches (s1, s2, s3)
      - Core switch (cores21)
      - Each host is in a separate subnet
    """

    def __init__(self):
        # Initialize topology
        Topo.__init__(self)

        # Add hosts
        h10 = self.addHost('h10', ip='10.0.1.10/24', defaultRoute='via 10.0.1.1')
        h20 = self.addHost('h20', ip='10.0.2.20/24', defaultRoute='via 10.0.2.1')
        h30 = self.addHost('h30', ip='10.0.3.30/24', defaultRoute='via 10.0.3.1')
        serv1 = self.addHost('serv1', ip='10.0.4.10/24', defaultRoute='via 10.0.4.1')
        hnotrust1 = self.addHost('hnotrust1', ip='172.16.10.100/24', defaultRoute='via 172.16.10.1')

        # Add switches
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')
        cores21 = self.addSwitch('cores21')

        # Add links between hosts and edge switches
        self.addLink(h10, s1)
        self.addLink(h20, s2)
        self.addLink(h30, s3)
        self.addLink(serv1, cores21)
        self.addLink(hnotrust1, cores21)

        # Add links between edge switches and core switch
        self.addLink(s1, cores21)
        self.addLink(s2, cores21)
        self.addLink(s3, cores21)

# To run this topology with Mininet:
# sudo mn --custom part4.py --topo part4topo --controller=remote

topos = {'part4topo': (lambda: Part4Topo())}
