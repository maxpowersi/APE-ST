from __future__ import print_function
import validators
import argparse
import sys
import os
import datetime
import re

def consoleWritte(msg):
    print('\033[34m--- ' + msg + ' ---\033[0m')

def validateParameters(parameters):
    regexIP = '''^(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)'''

    if not validators.domain(parameters.target) and re.search(regexIP, parameters.target) is None:
        print("The argument -t (target) is invalid, it must be a text file with IPs or subdomains.")
        sys.exit()

    if not os.path.exists(parameters.outputDir):
        print("The argument -o (output dir) is invalid, it must be a valid folder")
        sys.exit()

    if not validators.between(int(parameters.queued), min=1, max=50):
        print("The argument -q (queued) is invalid, min 1, max 500")
        sys.exit()

def createProjectFolder(scanPath, servicesFolder):
    if not os.path.exists(scanPath): os.system("mkdir " + scanPath)
    for servicePath in servicesFolder:
        if not os.path.exists(servicePath): os.system("mkdir " + servicePath)

def initHostScan(scanPath, target, hostCommandsPath, queued, organization):
    f = open(hostCommandsPath)
    for command in f:
        command = command.rstrip()
        command = command.replace("_TARGET_", target)
        command = command.replace("_DOMAIN_", target.replace("/", "").replace(":", "").replace("https", "").replace("http", ""))
        command = command.replace("_OUTPUT_", scanPath)
        command = command.replace("_APP_PATH_", apePath)
        command = command.replace("_THREADS_", queued)
        command = command.replace("_COMPANY_", organization)
        if "Running" not in command: 
            print('\033[93m' + command + '\033[0m')
        os.system(command)
    f.close()

def initServiceScan(commandsFiles, scanPath, target, queued, organization, commandsFolderPath):
    for tup in commandsFiles:
        service =  tup[0]
        commandFileName = tup[1]
        protocol =  tup[2]
        commandFile = os.path.join(commandsFolderPath, commandFileName)
        consoleWritte("Starting scan for service " + protocol)
        f = open(commandFile)
        for command in f:
            command = command.rstrip()
            command = command.replace("_TARGET_", target)
            command = command.replace("_DOMAIN_", target.replace("/", "").replace(":", "").replace("https", "").replace("http", ""))
            command = command.replace("_OUTPUT_", scanPath)
            command = command.replace("_PORT_", "$p")
            command = command.replace("_APP_PATH_", apePath)
            command = command.replace("_THREADS_", queued)
            command = command.replace("_COMPANY_", organization)
            command = command.replace("_PROTOCOL_", protocol)
            if "Running" not in command and command not in ['\n', '\r\n'] and command.strip():
                command = "nmap-parse-output '{3}/host/{2}.tcp.top1000.xml' service '{0}' | cut -d ':' -f2 | while read p; do {1}; done".format(service, command, target, scanPath)
                print('\033[93m' + command + '\033[0m')
            os.system(command)
        f.close()

def initHTTPjsScan(httpJSService, scanPath, target, queued, organization, commandsFolderPath):
    initServiceScan(httpJSService, scanPath, target, queued, organization, commandsFolderPath)

def fixNmapOutput(scanPath, apePath):
    os.system("cd {0}; sh '{1}/nmapConvertFix.sh'".format(os.path.join(scanPath, "host"), apePath))
    with open(os.path.join(scanPath, "nmapToConvert.tmp.txt")) as f:
        for line in f:
            parsedLine = line.split(":")
            toEditFile  = parsedLine[0]
            toEditLine  = int(parsedLine[1])
            toEditFilePath = os.path.join(os.path.join(os.path.join(scanPath, "host"), toEditFile))
            with open(toEditFilePath, 'r') as fileStream:
                data = fileStream.readlines()
                data[toEditLine - 1] = data[toEditLine - 1].replace('name="http"', 'name="https"')
            with open(toEditFilePath, 'w') as fileStream:
                fileStream.writelines(data)
    os.remove(os.path.join(scanPath, "nmapToConvert.tmp.txt"))

#Parameters init
parser = argparse.ArgumentParser(description="")
parser.add_argument('-t',action="store", dest="target", help="subdomain, or IP target.", required=True)
parser.add_argument('-o', action="store", dest="outputDir", help="path to place all outputs", required=True)
parser.add_argument('-q', action="store", dest="queued", help="number of queued, each queued will process one resource (IP or subdomain)", required=True)
parameters = parser.parse_args()

#Validation
validateParameters(parameters)

#Parameters parser
queued = parameters.queued
target = parameters.target
projectPath = parameters.outputDir
organization = target.split(".")[0]

#Paths
apePath = os.path.dirname(os.path.realpath(__file__))
scanPath = os.path.join(projectPath, "scan")
commandsFolderPath = os.path.join(apePath, "commands")

hostCommandsPath = os.path.join(commandsFolderPath, "host.commands")
commandsFiles =  [("ftp", "ftp.commands", "ftp"),
                  ("ssh", "ssh.commands", "ssh"),
                  ("smtp", "smtp.commands", "smtp"),
                  ("domain", "dns.commands", "dns"),
                  ("ms-wbt-server", "rdp.commands", "rdp"),
                  ("telnet", "telnet.commands", "telnet"),
                  ("http", "http.commands", "http"),
                  ("ssl", "https.commands", "https"),
                  ("https", "https.commands", "https"),
                  ("ssl", "http.commands", "https"),
                  ("https", "http.commands", "https")]

httpJSService =  [("https", "http.js.commands", "https"), ("http", "http.js.commands", "http"), ("ssl", "http.js.commands", "https")]

servicesFolder =  [os.path.join(scanPath, "http"),
                   os.path.join(scanPath, "ftp"),
                   os.path.join(scanPath, "ssh"),
                   os.path.join(scanPath, "telnet"),
                   os.path.join(scanPath, "smtp"),
                   os.path.join(scanPath, "dns"),
                   os.path.join(scanPath, "rdp"),
                   os.path.join(scanPath, "https"),
                   os.path.join(scanPath, "http/JS"),
                   os.path.join(scanPath, "https/JS"),
                   os.path.join(scanPath, "http-discovery"),
                   os.path.join(scanPath, "host")]

consoleWritte("Creating project folder")
createProjectFolder(scanPath, servicesFolder)

consoleWritte("Starting host scan")
initHostScan(scanPath, target, hostCommandsPath, queued, organization)

consoleWritte("Patching nmap host scan results for the next pipeline")
fixNmapOutput(scanPath, apePath)

consoleWritte("Starting services scan")
initServiceScan(commandsFiles, scanPath, target, queued, organization, commandsFolderPath)

consoleWritte("Starting http JS scan")
initHTTPjsScan(httpJSService, scanPath, target, queued, organization, commandsFolderPath)

consoleWritte("The scan was finished successfully")