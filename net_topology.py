#!/usr/bin/python

import os, sys
from mininet.net import Mininet
from mininet.node import OVSSwitch, Controller, RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink
import time

from subprocess import call

def topologie():
	call(["mn", "-c"])

	net = Mininet(controller=RemoteController, link=TCLink)
	c0 = net.addController('c0', controller=RemoteController, ip="127.0.0.1", port=6633)

	h1 = net.addHost('h1', ip='10.0.0.1', mac="00:00:00:00:00:01")
	h2 = net.addHost('h2', ip='10.0.0.2', mac="00:00:00:00:00:02")
	h3 = net.addHost('h3', ip='10.0.0.3', mac="00:00:00:00:00:03")
	h4 = net.addHost('h4', ip='10.0.0.4', mac="00:00:00:00:00:04")
	h5 = net.addHost('h5', ip='10.0.0.5', mac="00:00:00:00:00:05")
	h6 = net.addHost('h6', ip='10.0.0.6', mac="00:00:00:00:00:06")

	s1=net.addSwitch('s1')
	s2=net.addSwitch('s2')
	s3=net.addSwitch('s3')
	s4=net.addSwitch('s4')
	s5=net.addSwitch('s5')
	s6=net.addSwitch('s6')
	s7=net.addSwitch('s7')
	s8=net.addSwitch('s8')
	s9=net.addSwitch('s9')
	s10=net.addSwitch('s10')
	s11=net.addSwitch('s11')
	s12=net.addSwitch('s12')

	net.addLink(h1, s4)
	net.addLink(h2, h4)
	net.addLink(h3, s4)
	net.addLink(h4, s6)
	net.addLink(h5, s6)
	net.addLink(h6, s6)

	net.addLink(s1, s4, bw=10)
	net.addLink(s2, s4, bw=10)
	net.addLink(s3, s4, bw=10)
	net.addLink(s10, s6, bw=10)
	net.addLink(s11, s6, bw=10)
	net.addLink(s12, s6, bw=10)

	net.addLink(s4, s5, bw=3)
	net.addLink(s4, s6, bw=4)
	net.addLink(s4, s7, bw=3)
	net.addLink(s5, s6, bw=3)
	net.addLink(s6, s9, bw=3)
	net.addLink(s7, s8, bw=2)
	net.addLink(s8, s9, bw=2)

	net.start()

	net.pingAllFull()

        h4.cmd('ovs-ofctl dump-flows s4 > s1.txt &')
        h4.cmd('ovs-ofctl dump-flows s5 > s2.txt &')
        h4.cmd('ovs-ofctl dump-flows s6 > s3.txt &')
        h4.cmd('ovs-ofctl dump-flows s7 > s4.txt &')
        h4.cmd('ovs-ofctl dump-flows s4 > s5.txt &')
        h4.cmd('ovs-ofctl dump-flows s5 > s6.txt &')
        h4.cmd('ovs-ofctl dump-flows s6 > s7.txt &')
        h4.cmd('ovs-ofctl dump-flows s7 > s9.txt &')
        h4.cmd('ovs-ofctl dump-flows s5 > s10.txt &')
        h4.cmd('ovs-ofctl dump-flows s6 > s11.txt &')
        h4.cmd('ovs-ofctl dump-flows s7 > s12.txt &')
        sleep(2)

        info( '*** iperf h1 - h4 exchaging UDP \n')
        h4.cmd ('iperf -s -u -p 3000 -t 60 -i 1 > serveurH4.txt &')
        h1.cmd ('iperf -c 10.0.0.4 -u -b 4m -p 3000 -t 60 -i 1 > clientH1.txt &')
        sleep(2)

        info( '*** iperf h2 - h5 exchaging UDP \n')
        h5.cmd ('iperf -s -u -p 3000 -t 60 -i 1 > serveurH5.txt &')
        h2.cmd ('iperf -c 10.0.0.5 -u -b 3m -p 3000 -t 60 -i 1 > clientH2.txt &')
        sleep(2)

        info( '*** iperf h3 - h6 exchaging UDP \n')
        h6.cmd ('iperf -s -u -p 3000 -t 60 -i 1 > serveurH6.txt &')
        h3.cmd ('iperf -c 10.0.0.6 -u -b 2m -p 3000 -t 60 -i 1 > clientH3.txt &')
        sleep(2)




	CLI(net)
	net.stop()

if __name__ = '__main__':
	setLogLevel('info')
	topologie()
