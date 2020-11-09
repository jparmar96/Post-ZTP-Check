#!/usr/bin/env python
import sys
import argparse
import os
from jsonrpclib import Server
import ipaddress
import subprocess
import json
import time
import re
#start_time = time.time()

def parse_args():
    parser = argparse.ArgumentParser(
        epilog="Example: ./postcheck.py -f /ip-list.txt "
               "-u admin -p password -o output.txt")
    parser.add_argument("-f", "--filename", required=True,
                        help="input file with ip address", metavar="FILE",
                        type=is_valid_file)
    parser.add_argument("-u", "--username", type=str, default="admin",
                        help="Specify username to be used to login to the switches")
    parser.add_argument("-p", "--password", type=str, default="admin",
                        help="Specify password to be used to login to the switches")
    parser.add_argument("-o", "--ofile", type=str, default="output1.txt",
                        help="Specify output file", metavar="FILE" )
    args = parser.parse_args()
    return args

def is_valid_file(arg):
    """Checks if a arg is an actual file"""
    if not os.path.isfile(arg):
        msg = "{0} is not a file or it does not exist".format(arg)
        raise argparse.ArgumentTypeError(msg)
    else:
        return arg

def get_switch_ips(filename):
    with open(filename) as f:
        lines = [line.strip() for line in f]
    return lines

def checkValidIP(ipAddr):
    try:
        if ipaddress.ip_address(unicode(ipAddr)):
            return True
    except ValueError as e:
        return e

def checkSwitchIsUp(ipAddr):
    p = subprocess.Popen('ping -c 5 ' + str(ipAddr), stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    out, err = p.communicate()
    if err:
        raise "Could not issue ping to the IPs"
    elif "5 packets received" not in out:
        return ("No response of ping. Switch might be down or check routing." + "\n\n")
    else:
        return ("Switch is up" + "\n\n")

def getEapiCommandOutput(args, ipAddr):
    try:
        url = "http://{}:{}@{}/command-api".format(args.username, args.password, ipAddr)
        switchd = Server(url)
        try:
            op = switchd.runCmds(1,["show ip interface brief | grep up"],"text")
            return (op[0]['output'] + "\n")
        except:
            return ("Error in output " + "\n")

    except:
        return ("Check EAPI connection. Couldn't issue command to find diff in startup and running configs." + "\n\n")

def pingCheck(intfIP, netw, ipAddr, args):
    url = "http://{}:{}@{}/command-api".format(args.username, args.password, ipAddr)
    switchd = Server(url)
    for ip in ipaddress.IPv4Network(netw):
        if ipaddress.IPv4Address(ip) != ipaddress.IPv4Address(intfIP):
            #print(ip)
            try:
                #print(ip)
                op = switchd.runCmds(1,["ping " + str(ip) + " source " + intfIP],"text")
                op1 = (op[0]['output'] + "\n")
                #print(op1)
                if "5 received" in op1:
                    return "Neighbor IP " + str(ip) + " configured correctly \n"
            except:
                return ("Could not issue ping to the IPs " + "\n")
    return "Neighbor IP for interface IP "  + str(intfIP) + " may not be configured correctly \n"


def main():

    args = parse_args()
    switchIP = get_switch_ips(args.filename)

#    with open(args.ofile, "w+") as f:
    for ipAddr in switchIP:
#            f.write("-*"*75 + "\n")
#            resp = checkValidIP(ipAddr)
#            f.write("\n" + ipAddr + "\n")

#            if not resp == True:                          #IP address is invalid
#                f.write(str(resp) + "\n\n")
#            else:                                        #IP address is Valid, Check is switch is up
#                pingOutput = checkSwitchIsUp(ipAddr)

#                if not pingOutput == "Switch is up" + "\n\n":    #Switch is not up
#                    f.write(pingOutput)
#                else:                                      #Switch is up, check EAPI
#                    f.write("Switch is up" + "\n\n")          #Issue EAPI command to check diff
                output = getEapiCommandOutput(args, ipAddr)
                #f.write(output)

                for line in output.splitlines():
                    #print(line)
                    if "Ethernet" in line or "Port-Channel" in line:
                        print(line)
                        match = re.search("(\d+\.\d+\.\d+\.\d+)/\d+", line)
                        if match:
                            intfIP = match.group(1)
                            #print(intfIP)
                            #print(match.group())
                            netw = ipaddress.ip_network(match.group(), strict=False)
                            #print(netw)
                            output = pingCheck(intfIP, netw, ipAddr, args)
                            print(output)
                            #f.write(output)

#        f.write("-*"*75 + "\n" )


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
