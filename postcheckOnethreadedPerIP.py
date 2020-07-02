#!/usr/bin/env python
import sys
import argparse
import os
from jsonrpclib import Server
import ipaddress
import subprocess
import json
import time
import logging
import threading

start_time = time.time()
threadLock = threading.Lock()

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
    parser.add_argument("-o", "--ofile", type=str, default="output.txt",
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

def progress(i, total):
    len = 100
    percent = (float(i)/float(total)*100)
    sys.stdout.write("   Progress: %.2f%%  "  % (percent) + "[" + "#"*int(percent)  + " "*int(len - percent) + "] \r")
    #sys.stdout.write("Progress: %.2f%%   \r"  % (percent) )
    if not i ==total:
        sys.stdout.flush()
    else:
        print("   Progress: %.2f%%  "  % (percent) + "[" + "#"*int(percent)  + " "*int(len - percent) + "] \r")
        print("   Total running time: %.2s seconds " % (time.time() - start_time))

def getEapiCommandOutput(args, ipAddr):
    try:
        url = "http://{}:{}@{}/command-api".format(args.username, args.password, ipAddr)
        switchd = Server(url)
        op = switchd.runCmds(1,["diff startup-config running-config"],"text")
        if op[0]['output'] == "\n":
            return ("Success. No diff in startup-config and running-config.\n\n")
        else:
            return (op[0]['output'] + "\n")

    except:
        return ("Check EAPI connection. Couldn't issue command to find diff in startup and running configs." + "\n\n")

def thread_function(name, ipAddr, args):
    logging.info("Thread %s: starting", name)
    text = " "

    text += ("\n" + ipAddr + "\n")
    resp = checkValidIP(ipAddr)

    if not resp == True:                          #IP address is invalid
        text += (str(resp) + "\n\n")
    else:                                        #IP address is Valid, Check is switch is up
        pingOutput = checkSwitchIsUp(ipAddr)

        if not pingOutput == "Switch is up" + "\n\n":    #Switch is not up
            text += (pingOutput)
        else:                                      #Switch is up, check EAPI
            text += ("Switch is up" + "\n\n")          #Issue EAPI command to check diff
            output = getEapiCommandOutput(args, ipAddr)
            text += (output)
    logging.info("Thread %s: finishing", name)
    writeToOutputFile(text, args, name)

def writeToOutputFile(text, args, name):
    """ Use lock here and write output of thread into file"""
    threadLock.acquire()
    logging.info("Thread %s: acquired lock", name)
    with open(args.ofile, "a+") as f:
        f.write(text)
        f.write("-*"*75 + "\n" )
    threadLock.release()

def main():

    args = parse_args()
    switchIP = get_switch_ips(args.filename)

    format = "%(asctime)s: %(message)s"
    logging.basicConfig(format=format, level=logging.CRITICAL, datefmt="%H:%M:%S")

    with open(args.ofile, "w+") as f:
        f.write("-*"*75 + "\n" )

    threadNum = 0
    threads = []
    for ipAddr in switchIP:
        """ Start threads here"""
        x = threading.Thread(target=thread_function, args=(threadNum, ipAddr, args))
        threads.append(x)
        x.start()

        threadNum += 1
        #progress(threadNum, len(switchIP) )


    for index, thread in enumerate(threads):
        thread.join()
        logging.info("Main    : thread %d done", index)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
