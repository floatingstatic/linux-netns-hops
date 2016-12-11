#!/usr/bin/env python
import argparse
import socket
import sys
from netaddr import *
from binascii import hexlify

def lines_in_file(txt_file):
    count = len(open(txt_file).readlines())
    return count

def generate_ptr_ipv6(txt_file,subnet):
    # Load data from file into list
    f_lines = []
    with open(txt_file) as fh:
        for line in fh:
            f_lines.append(line.rstrip('\n'))

    # Open file handle for output
    out = open('ptr_records_v6.txt','w+')

    net = IPNetwork(subnet)
    index = 1
    count = 0
    while count < len(f_lines):
        ip_reverse = str(hexlify(socket.inet_pton(socket.AF_INET6, str(net[index]))))
        ptr = str()
        for x in ip_reverse[::-1]:
            ptr += x + "."
        ptr += "ip6.arpa." + "\tIN\tPTR\t" + f_lines[count] + ".\n"
        index += 2
        count += 1
        out.write(ptr)
    out.close()

def generate_ptr_ipv4(txt_file,subnet):
    # Load data from file into list
    f_lines = []
    with open(txt_file) as fh:
        for line in fh:
            f_lines.append(line.rstrip('\n'))

    # Open file handle for output
    out = open('ptr_records_v4.txt','w+')

    net = IPNetwork(subnet)
    index = 1
    count = 0
    while count < len(f_lines):
        ip = net[index]
        last_octet = str(ip.words[3])
        ptr = last_octet + "\t\tIN\tPTR\t" + f_lines[count] + ".\n"
        index += 2
        count += 1
        out.write(ptr)
    out.close()
    return len(f_lines)

def generate_namespaces(hops_out,hops):
    count = 1
    while count < hops + 1:
        hops_out.write(txt_to_cmd("ip netns add vrf%d" % count))
        count += 1

def generate_veth_interfaces(hops_out,hops):
    count = 1
    int_count = 1
    while count < hops + 1:
        int_a = int_count
        int_b = int_count + 1
        hops_out.write(txt_to_cmd("ip link add veth%d type veth peer name veth%d" % (int_a,int_b)))
        if count != 1:
            vrf1 = count - 1
            hops_out.write(txt_to_cmd("ip link set veth%d netns vrf%d" % (int_a,vrf1)))
            vrf2 = count
            hops_out.write(txt_to_cmd("ip link set veth%d netns vrf%d" % (int_b,vrf2)))
        else:
            hops_out.write(txt_to_cmd("ip link set veth%d netns vrf%d" % (int_b,count)))
        count += 1
        int_count += 2

def generate_veth_ips(hops_out,hops,subnets,mask):
    count = 1
    int_count = 1
    for x in subnets:
        if count > hops:
            break

        ipsubnet = IPNetwork(x)
        if count == 1:
            hops_out.write(txt_to_cmd("ip address add %s/%s dev veth1" % (str(ipsubnet[0]),mask)))
            hops_out.write(txt_to_cmd("ip netns exec vrf1 ip address add %s/%s dev veth2" % (str(ipsubnet[1]),mask))) 
            hops_out.write(txt_to_cmd("ip link set dev veth1 up"))
            hops_out.write(txt_to_cmd("ip netns exec vrf1 ip link set dev veth2 up"))
        else:
            int_a = int_count
            int_b = int_count + 1
            vrf1 = count - 1
            vrf2 = count
            hops_out.write(txt_to_cmd("ip netns exec vrf%d ip address add %s/%s dev veth%d" % (vrf1,str(ipsubnet[0]),mask,int_a)))
            hops_out.write(txt_to_cmd("ip netns exec vrf%d ip address add %s/%s dev veth%d" % (vrf2,str(ipsubnet[1]),mask,int_b)))
            hops_out.write(txt_to_cmd("ip netns exec vrf%d ip link set dev veth%d up" % (vrf1,int_a)))
            hops_out.write(txt_to_cmd("ip netns exec vrf%d ip link set dev veth%d up" % (vrf2,int_b)))
        count += 1
        int_count += 2

def generate_static_routes(hops_out,hops,subnets,mask):
    gw_forward = []
    gw_reverse = []
    vrf_routes = []
    count = 1

    for x in subnets:
        if count > hops:
            break
        ipsubnet = IPNetwork(x)
        vrf_routes.append(str(ipsubnet))
        gw_forward.append(str(ipsubnet[1]))
        gw_reverse.append(str(ipsubnet[0]))
        count += 1

    # Last hop
    last_hop = str(gw_forward[-1])
    print "Last hop: %s" % str(last_hop)
    
    # Routes to destination
    count = 1
    vrf_count = 0
    while count < hops + 1:
        if count == 1:
            hops_out.write(txt_to_cmd("ip route add %s/%s via %s" % (last_hop,mask,str(gw_forward[vrf_count]))))
        else:
            hops_out.write(txt_to_cmd("ip netns exec vrf%d ip route add %s/%s via %s" % (vrf_count,last_hop,mask,str(gw_forward[vrf_count]))))

        count += 1
        vrf_count += 1

    # Routes from destination
    count = hops - 1
    vrf_count = len(gw_reverse)

    while count > 0:
        gw_ip = IPAddress(gw_reverse[count])
        if gw_ip.version == 6:
            hops_out.write(txt_to_cmd("ip netns exec vrf%d ip route add ::/0 via %s" % (vrf_count,str(gw_reverse[count]))))
        if gw_ip.version == 4:
            hops_out.write(txt_to_cmd("ip netns exec vrf%d ip route add 0.0.0.0/0 via %s" % (vrf_count,str(gw_reverse[count])))) 
        count -= 1
        vrf_count -= 1

    gw_ip = IPAddress(gw_reverse[0])
    if gw_ip.version == 6:
        hops_out.write(txt_to_cmd("ip netns exec vrf1 ip route add ::/0 via %s" % str(gw_reverse[0])))
    if gw_ip.version == 4:
        hops_out.write(txt_to_cmd("ip netns exec vrf1 ip route add 0.0.0.0/0 via %s" % str(gw_reverse[0])))

    # Routes in between
    count = 1
    vrf_count = len(vrf_routes)
    gw_count = 0
    while count < vrf_count - 1: 
        if count == 1:
            for x in range(count,vrf_count):
                hops_out.write(txt_to_cmd("ip route add %s via %s"% (str(vrf_routes[x]),str(gw_forward[gw_count]))))
        else:
            vrf = count - 1
            for x in range(count,vrf_count):
                hops_out.write(txt_to_cmd("ip netns exec vrf%d ip route add %s via %s" % (vrf,str(vrf_routes[x]),str(gw_forward[gw_count]))))
        count += 1
        gw_count += 1

def generate_ipv6_forward_sysctl(hops_out,hops):
    # Base VRF
    hops_out.write(txt_to_cmd("sysctl -w net.ipv6.conf.all.forwarding=1"))
    hops_out.write(txt_to_cmd("sysctl -w net.ipv6.conf.default.forwarding=1"))
    hops_out.write(txt_to_cmd("sysctl -w net.ipv6.icmp.ratelimit=0"))
    # Namespaces
    count = 1
    while count < hops + 1:
        hops_out.write(txt_to_cmd("ip netns exec vrf%d sysctl -w net.ipv6.conf.all.forwarding=1" % count))
        hops_out.write(txt_to_cmd("ip netns exec vrf%d sysctl -w net.ipv6.conf.default.forwarding=1" % count))
        hops_out.write(txt_to_cmd("ip netns exec vrf%d sysctl -w net.ipv6.icmp.ratelimit=0" % count))
        count += 1

def generate_ipv4_forward_sysctl(hops_out,hops):
    # Base VRF
    hops_out.write(txt_to_cmd("sysctl -w net.ipv4.conf.all.forwarding=1"))
    hops_out.write(txt_to_cmd("sysctl -w net.ipv4.conf.default.forwarding=1"))
    hops_out.write(txt_to_cmd("sysctl -w net.ipv4.icmp_ratelimit=0"))
    # Namespaces
    count = 1
    while count < hops + 1:
        hops_out.write(txt_to_cmd("ip netns exec vrf%d sysctl -w net.ipv4.conf.all.forwarding=1" % count))
        hops_out.write(txt_to_cmd("ip netns exec vrf%d sysctl -w net.ipv4.conf.default.forwarding=1" % count))
        hops_out.write(txt_to_cmd("ip netns exec vrf%d sysctl -w net.ipv4.icmp_ratelimit=0" % count))
        count += 1

def generate_base_sysctl(hops_out):
    hops_out.write(txt_to_cmd("sysctl -w net.ipv4.ip_forward=1"))
    hops_out.write(txt_to_cmd("sysctl -w net.ipv4.conf.all.forwarding=1"))
    hops_out.write(txt_to_cmd("sysctl -w net.ipv4.conf.default.forwarding=1"))
    hops_out.write(txt_to_cmd("sysctl -w net.ipv4.icmp_ratelimit=0"))
    hops_out.write(txt_to_cmd("sysctl -w net.ipv6.conf.all.forwarding=1"))
    hops_out.write(txt_to_cmd("sysctl -w net.ipv6.conf.default.forwarding=1"))
    hops_out.write(txt_to_cmd("sysctl -w net.ipv6.icmp.ratelimit=0"))

def txt_to_cmd(txt):
    cmd = "%s\n" % txt
    return cmd

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='A silly script to generate hops through Linux namespaces')
    parser.add_argument('-4','--ipv4', help='IPv4 Base Allocation', required=False)
    parser.add_argument('-6','--ipv6', help='IPv6 Base Allocation (/64)', required=False)
    parser.add_argument('-f','--file', help='Text file with each line representing a hop', required=True)
    args = vars(parser.parse_args())
    # Base vars
    base_ipv6_subnet = args['ipv6']
    base_ipv4_subnet = args['ipv4']
    txt_file = args['file']
    numhops = 0

    # Open output file handle
    hops_out = open('create_hops.sh','w+')
    numhops = lines_in_file(txt_file)
    if numhops < 1:
        print "ERROR: Text file is empty. Quitting"
        sys.exit(1)
    else:
        print "Total Hops: %d" % numhops
    
    # Create namespaces (VRFs) and veth interfaces
    hops_out.write("#!/bin/sh\n\n")
    generate_base_sysctl(hops_out)
    generate_namespaces(hops_out,numhops)
    generate_veth_interfaces(hops_out,numhops)

    # IPv4
    if base_ipv4_subnet:
        ipv4block = IPNetwork(base_ipv4_subnet,4)
        ipv4subnets = list(ipv4block.subnet(31))
        # Check if IPv4 subnet provided can supply the required number of /31 hops
        if len(ipv4subnets) < numhops:
            print "ERROR: Base IPv4 Subnet %s cannot provide enough IPv4 /31 hops (Required: %d | Available: %d)" % \
                (base_ipv4_subnet,numhops,len(ipv4subnets))
            sys.exit(1)
        generate_ipv4_forward_sysctl(hops_out,numhops)
        generate_veth_ips(hops_out,numhops,ipv4subnets,'31')
        generate_static_routes(hops_out,numhops,ipv4subnets,'32')
        generate_ptr_ipv4(txt_file,base_ipv4_subnet)

    # IPv6
    if base_ipv6_subnet:
        ipv6block = IPNetwork(base_ipv6_subnet,6)
        ipv6subnets = list(ipv6block.subnet(127,255))  # set limit to 255 /127's (Max TTL=255 anyway)
        generate_ipv6_forward_sysctl(hops_out,numhops)
        generate_veth_ips(hops_out,numhops,ipv6subnets,'127')
        generate_static_routes(hops_out,numhops,ipv6subnets,'128')
        generate_ptr_ipv6(txt_file,base_ipv6_subnet)

    # Close file handle
    hops_out.close()
