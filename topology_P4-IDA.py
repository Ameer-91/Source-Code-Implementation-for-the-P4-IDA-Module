// File: topology/p4ida_topology.py
from mininet.topo import Topo

class P4IDATopo(Topo):
    def build(self):
        h1 = self.addHost('h1', ip='10.0.0.1')
        h2 = self.addHost('h2', ip='10.0.0.2')
        s1 = self.addSwitch('s1')
        self.addLink(h1, s1)
        self.addLink(h2, s1)
