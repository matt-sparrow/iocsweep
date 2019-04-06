#!/usr/bin/python3

from scapy.all import *
import os
import codecs
import argparse
import sys
import re
import datetime

def check_file_writable(cfwpath):
    if os.path.exists(cfwpath):
        if os.path.isfile(cfwpath):
            return os.access(cfwpath, os.W_OK)
        else:
            return False
    pdir = os.path.dirname(cfwpath)
    if not pdir: pdir = '.'
    return os.access(pdir, os.W_OK)

#All argument parsing options
parser = argparse.ArgumentParser()
parser.add_argument("input", help="Absolute or relative path to packet capture data file.")
parser.add_argument("-d", "--dump-dns", help="Dump DNS data to report file", default=False, action="store_true")
parser.add_argument("-i", "--ioc-file", help="Specify the IoC input file.  Format is 1 IP per line.")
parser.add_argument("-o", "--output", help="Specify the report output file's absolute or relative path.")
args = parser.parse_args()

#Check to make sure the input file exists
if not os.access(args.input, os.R_OK):
    print("Unable to find the specified input file.  Exiting.")
    exit(0)

if not args.ioc_file and not args.dump_dns:
    print("You must specify either to --dump-dns or an --ioc-file to scan the input data for.")
    exit(0)

if args.ioc_file:
    if not os.access(args.ioc_file, os.R_OK):
        print("Unable to read IoC file.  Exiting.")
        exit(0)

if args.output:
    if not check_file_writable(args.output):
        print("Unable to write to specified output file.  Please choose another.")
        exit(0)
    else:
        outfile = args.output

if not args.output:
    if not check_file_writable("./" + os.path.basename(args.input) + "-report.txt"):
        print("Unable to write to default report file.  Please specify an output file with -o.")
        exit(0)

    else:
        outfile = os.path.basename(args.input) + "-report.txt"

starttime = datetime.datetime.now().isoformat()

if args.ioc_file:
    if os.access(args.ioc_file, os.R_OK):
        ioc = []
        regex = r"(?:^|\b(?<!\.))(?:1?\d?\d|2[0-4]\d|25[0-5])(?:\.(?:1?\d?\d|2[0-4]\d|25[0-5])){3}(?=$|[^\w.])"
        print("Reading in the IoC file.")
        with open(args.ioc_file, "r") as fh:
            for line in fh:
                matches = re.findall(regex, line)
                for match in matches:
                    ioc.append(match)
        print("Read in {} IoCs.".format(len(ioc)))

    
pcapfile = args.input
pcapsize = os.path.getsize(pcapfile)
dnsqueries = []
datasize = 0
ioctripped = []

try:
    for pkt in PcapReader(pcapfile):
        datasize += len(pkt)
        pctComplete = (datasize / pcapsize) * 100
        print("{}% Complete".format(str(int(pctComplete))), end='\r')
        if (args.dump_dns == True) and (pkt.haslayer(DNSRR) and isinstance(pkt.an, DNSRR) and pkt.an.rrname.decode() not in dnsqueries):
            dnsqueries.append(pkt.an.rrname.decode())
        if (args.ioc_file) and (pkt.haslayer(IP)):
            if (str(pkt[IP].src) in ioc and str(pkt[IP].src) not in ioctripped):
                ioctripped.append(str(pkt[IP].src))
            if (str(pkt[IP].dst) in ioc and str(pkt[IP].dst) not in ioctripped):
                ioctripped.append(str(pkt[IP].dst))

except:
    print("Unable to start PCAP Reader.  Exiting.")
    exit(0)

endtime = datetime.datetime.now().isoformat()

##############################################
########### Generate Report ##################
##############################################

with open(outfile, "w") as fh:
    try:
        fh.write("[*] Start Time: {}\r\n".format(starttime))
        fh.write("[*] End Time  : {}\r\n".format(endtime))
        if not args.ioc_file:
            fh.write("[*] IoC Scan of packets not conducted.  No IoC file provided.\r\n")
        if not args.dump_dns:
            fh.write("[*] DNS query dump not conducted\r\n")
        if (len(ioctripped) > 0):
            fh.write("[*] IoCs Identified in Traffic: {}\r\n".format(len(ioctripped)))
            for ioc in ioctripped:
                fh.write("[*] IoC Found: {}\r\n".format(ioc))
        if (len(ioctripped) == 0 and args.ioc_file):
            fh.write("[*] No IoCs found in network traffic.\r\n")
        if (len(dnsqueries) == 0 and args.dump_dns):
            fh.write("[*] No DNS queries captured.\r\n")
        if (len(dnsqueries) > 0):
            dnsqueries.sort()
            for query in dnsqueries:
                fh.write("[*] DNS Query: {}\r\n".format(query))

    except:
        print("Unable to write to output file.")
