from __future__ import print_function
import validators
import argparse
import sys
import os
import re 

print("""
+-+-+-+-+-+-+-+-+-
|A|P|E| |v|2|.|0|
+-+-+-+-+-+-+-+-+-
""")

#Parameters
parser = argparse.ArgumentParser(description="")
parser.add_argument('-m',action="store", dest="module", help="module name, it must be recon, scan or httpdiscovery", required=True)
parser.add_argument('-e',action="store", dest="extensions", help="extensions, coma separeted, only for httpdiscovery", default="")
parser.add_argument('-t',action="store", dest="target", help="target, for recon it must be a domain, for scan it must be a domain, subdomain or IP and for http discovery must be an URL", required=True)
parser.add_argument('-o', action="store", dest="outputDir", help="path to place all outputs", required=True)
parser.add_argument('-q', action="store", dest="queued", help="number of threads, each queued will process one resource (IP, subdomain or URL)", required=True)
parameters = parser.parse_args()

#Module selected
module = parameters.module.lower()
isScan = module == "scan"
isRecon = module == "recon"

#Validations
if not module in ["scan", "recon", "httpdiscovery"]:
    print("The argument -m (module) is invalid, it must be recon, scan or httpdiscovery")
    sys.exit()

if isRecon:
    #is recon
    if not validators.domain(parameters.target):
        print("The argument -t (target) is invalid, it must be a domain")
        sys.exit()
else:
    if isScan:
        #is scan
        regexIP = '''^(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.( 
            25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.( 
            25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.( 
            25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)'''
        if not validators.domain(parameters.target) and re.search(regexIP, parameters.target) is None:
            print("The argument -t (target) is invalid, it must be a domain, subdomain or IP .")
    else:
        #is http discover
        if not validators.url(parameters.target):
            print("The argument -t (target) is invalid, it must be an URL.")
            sys.exit()
        
if not os.path.exists(parameters.outputDir):
    print("The argument -o (output dir) is invalid, it must be a valid folder")
    sys.exit()

if not validators.between(int(parameters.queued), min=1, max=50):
    print("The argument -q (queued) is invalid, min 1, max 500")
    sys.exit()

#Parameters parsed
extensions = parameters.extensions
target = parameters.target
queued = parameters.queued
projectPath = parameters.outputDir

#Internal paths
apePath = os.path.dirname(os.path.realpath(__file__))

#Call internal modules
if isScan:
    os.system("python3 '{3}/scan-ape.py' -t '{0}' -o '{1}' -q {2}".format(target, projectPath, queued, apePath))
else:
    if isRecon:
        os.system("python3 '{3}/recon-ape.py' -t '{0}' -o '{1}' -q {2}".format(target, projectPath, queued, apePath))
    else:
        if extensions is not "":
             os.system("python3 '{3}/http-discovery.py' -t '{0}' -o '{1}' -q {2} -e {4}".format(target, projectPath, queued, apePath, extensions))
        else:
             os.system("python3 '{3}/http-discovery.py' -t '{0}' -o '{1}' -q {2}".format(target, projectPath, queued, apePath))
