from mininet.topo import Topo

class Part3Topo(Topo):
    """
    Custom topology for Part 3.
    
    Topology includes:
      - 3 hosts (h10, h20, h30)
      - 1 server (serv1)
      - 1 untrusted host (hnotrust)
      - 3 edge switches (s1, s2, s3)
      - 1 core switch (s21)
      - 1 datacenter switch (s31)
    """

    def __init__(self):
        # Initialize the topology
        Topo.__init__(self)

        # Add hosts
        h10 = self.addHost('h10', ip='10.0.1.10/24', mac='00:00:00:00:00:01')
        h20 = self.addHost('h20', ip='10.0.2.20/24', mac='00:00:00:00:00:02')
        h30 = self.addHost('h30', ip='10.0.3.30/24', mac='00:00:00:00:00:03')
        serv1 = self.addHost('serv1', ip='10.0.4.10/24', mac='00:00:00:00:00:04')
        hnotrust = self.addHost('hnotrust', ip='172.16.10.100/24', mac='00:00:00:00:00:05')

        # Add switches
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')
        s21 = self.addSwitch('s21')
        s31 = self.addSwitch('s31')

        # Add links between hosts and edge switches
        self.addLink(h10, s1)
        self.addLink(h20, s2)
        self.addLink(h30, s3)
        self.addLink(serv1, s31)
        self.addLink(hnotrust, s21)

        # Add links between switches
        self.addLink(s1, s21)
        self.addLink(s2, s21)
        self.addLink(s3, s21)
        self.addLink(s21, s31)

# To use this topology with Mininet:
# sudo mn --custom <filename>.py --topo part3topo --controller=remote

topos = { 'part3topo': ( lambda: Part3Topo() ) }
