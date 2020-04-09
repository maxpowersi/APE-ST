from __future__ import print_function
import validators
import argparse
import sys
import subprocess
import os
import datetime

def consoleWritte(msg):
    os.system("printf \"\e[92m--- {0} ---\e[0m\n\n\"".format(msg))

def createProjectFolder(scanPath, httpDiscoveryPath):        
    if not os.path.exists(scanPath):
        os.system("mkdir " + scanPath)
    if not os.path.exists(httpDiscoveryPath):
        os.system("mkdir " + httpDiscoveryPath)

def validateParameters(parameters):
    if not os.path.exists(parameters.outputDir):
        print ("The argument -o (output dir) is invalid, it must be a valid path")
        sys.exit()

    if not validators.between(int(parameters.queued), min=1, max=50):
        print("The argument -q (queued) is invalid, min 1, max 500")
        sys.exit()

    if  not validators.url(parameters.target):
        print("The argument -t (target) is invalid, it must be an URL")
        sys.exit()

def initHttpScan(commandsFilePath, target, scanPath, threads, apePath, extensions):
    commandsFile = open(commandsFilePath)
    for command in commandsFile:
        command = command.rstrip()
        command = command.replace("_TARGET_", target)
        command = command.replace("_DOMAIN_", target.replace("/","").replace(":","").replace("https", "").replace("http", ""))
        command = command.replace("_OUTPUT_", scanPath)
        command = command.replace("_APP_PATH_", apePath)
        command = command.replace("_THREADS_", threads)
        if(extensions is not ""):
            command = command.replace("_EXTENSIONS_NOT_DOT", "," + extensions.replace(".", ""))
            command = command.replace("_EXTENSIONS_", "," + extensions)
        else:
            command = command.replace("_EXTENSIONS_NOT_DOT", "")
            command = command.replace("_EXTENSIONS_", "")
        if "echo" not in command:
            print('\033[93m' + command + '\033[0m')
        os.system(command)
    commandsFile.close()

#Parameters
parser = argparse.ArgumentParser(description="")
parser.add_argument('-t',action="store", dest="target", help="taget it must be an URL like http://example.com or https://evil.site.com", required=True)
parser.add_argument('-o', action="store", dest="outputDir", help="path to place all outputs", required=True)
parser.add_argument('-q', action="store", dest="queued", help="number of threads, each queued will process one resource (IP, subdomain or URL)", required=True)
parser.add_argument('-e',action="store", dest="extensions", help="extensions, coma separeted", default="")
parameters = parser.parse_args()

#Validations
validateParameters(parameters)

#Parameters
target = parameters.target
extensions = parameters.extensions
scanPath = os.path.join(parameters.outputDir, "scan")
httpDiscoveryPath = os.path.join(scanPath, "http-discovery")
threads = parameters.queued

#Paths
apePath  =  os.path.dirname(os.path.realpath(__file__))

commandsFolderPath = os.path.join(apePath, "commands")
commandsFilePath = os.path.join(commandsFolderPath, "http.discovery.commands")

createProjectFolder(scanPath, httpDiscoveryPath)

#Init http discovery scan
initHttpScan(commandsFilePath, target, httpDiscoveryPath, threads, apePath, extensions)

#Finish
consoleWritte("The http discovery has finished")
