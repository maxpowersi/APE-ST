
<img  src="https://github.com/maxpowersi/ape/raw/master/logo.png"  width="150"  height="150">

# APE-ST v2.0
APE (in spanish "Asistente de Pentest Externo", "Single Target") is an assistant tool for external pentest. This tool has two modules, recon and scan. Recon module can be used to lunch many tools for recon, and get info (for example subdomains) throug a domain. Scan module, run nmap scan and parse the result in order to run special tools (customizable) for each service. This tool is distributed under the GNU GPLv3 license. This version is diferent from original version, is single target, and threads optimize of other ways.
## Requirements
- python
- pip
- nodejs
- npm
- go
- All tools run in recon and scan module.
## Installation
The setup.sh script will try to install all tools and dependencies. <br/>
```
git clone https://github.com/maxpowersi/APE.git
cd APE
sudo ./setup.sh
```
>Check the default tools in each module, and check that you have all tools and they are accessible by the command line in the path var. Some of the tools can not be installed in this script, you will have to install mannualy and add it to the path.

## Recon module
This module will run all recon tools in the file "recon.commands.txt". By default this module run the following tools:
- The Harvester
- Sublist3r
- OWASP amass
- Subfinder
- knockpy
- assetfinder
- Gitrob
- teh_s3_bucketeers

After run the default tools, APE will create a folder with the domain in scope and a folder inside called "recon". In this folder a file called "subdomains.txt" will be created containing all enumerated subdomains (this file concatenate all files ending in ".subdomain.txt". A file called "ips.txt" will be created with the IP for each subdomain in the "subdomains.txt" file. Finally a file called "ips-unique.txt" will be created, ready to use in APE Scan module or in nmap or masscan.

### Adding new tools
You can add you own tools, editing the file "recon.commands.txt". If the tool added generates subdomains, please the output name must end in ".subdomain.txt" to be included in the output  file "subdomains.txt"
## Scan module
This module will run all host or network scan tools in the file "host.commands.txt". By default this module run nmap and subjack for each host. After run the host scan tools, this module will run each "{service}.commands.txt" file, to scan each target in scope using the output nmap. By default, for each service the following tools will be run:

>Note: Please observe  that (by default) each dictionary used by ncrack is called:
"usernames.{service}.txt and passwords.{service}.txt". For example:
"usernames.ftp.txt" is for ftp service.
### HTTPS
- testssl
- sslscan
### HTTP & HTTPS
The HTTP Scaner is divide in sequencial 3 pipelines.
### First Pipeline (Web App Scan)
- nikto
- getJS
- curl
- wappalyzer
- webscreenshot
- aquatone
- webtech
- waybackurls
- photon
- h2t
- hakrawler
- Goohak
- corsy
- corstest
- dirhunt
- see-surf (SSRF)
- gospider
- injectus (TODO)
- XSStrike
- fockcache
### Second Pipeline (JS Scan)
- retire
- linkfinder
### Last Pipeline (HTTP content discovery)
Must be invoke in a manually way. Please for more information, read the help.
- ohmybackup (short list, searching for backups)
- dirsearch (default list, using most commons extension, directory and no extension)
- dirb (default list, using most commons extension, directory and no extension)
- opendoor (default list, using most commons extension, directory and no extension)
- gobuster (using custom list, most commons extension and no extension)
- gobuster (using custom list, only directory)
### SSH
- ncrack
- ssh-user-enumeration
- ssh-audit
- nmap scripts
	- banner
	- ssh-auth-methods
	- sshv1
	- vuln
	- vulscan
### Telnet
- ncrack
- nmap scripts
	- banner
	- telnet-ntlm-info
	- vuln
	- vulscan
### FTP
- ncrack
- nmap scripts
	- banner
	- ftp-anon
	- ftp-bounce
	- ftp-syst
	- vuln
	- vulscan
### DNS
- nmap scripts
	- banner
	- dns-cache-snoop
	- dns-recursion
	- vuln
	- vulscan
### SMTP
- smtp-user-enum
- OpenReleayMagic
- nmap scripts
	- banner
	- smtp-open-relay
	- smtp-commands
	- vuln
	- vulscan
### RDP
- ncrack
- nmap scripts
	- banner
	- rdp-ntlm-info
	- rdp-vuln-ms12-020
	- vuln
	- vulscan
### SMB
- nmap scripts
	- banner
	- smb-protocols
	- smb-enum-shares
	- smb-vuln-ms17-010
	- smb-enum-users
	- vuln
	- vulscan
### Adding new tools
You can add you own tools, editing the command files.
## Help
```
+-+-+-+-+-+-+-+-+-
|A|P|E| |v|1|.|0|
+-+-+-+-+-+-+-+-+-

usage: ape.py [-h] [-v] -m MODULE -t TARGET -o OUTPUTDIR -q QUEUED

optional arguments:
  -h, --help        show this help message and exit
  -v, --version     show program's version number and exit
  -m MODULE         module name, it must be recon or scan
  -t TARGET         target, for recon it must be a domain, for scan it must be
                    a text file with subdomains or IPs
  -o OUTPUTDIR      path to place all outputs
  -q QUEUED         number of queued or threads, each queued will process one
                    resource (IP or subdomain)
```
## Recon
```
ape.py -m recon -t "domain.com" -o "/home/user/" -q 30
```
## Scan
```
ape.py -m scan -t "/home/user/domain.com/recon/subdomains.txt" -o "/home/user/domain.com/ -q 30
```
## HTTP Content discovery
```
ape.py -m httpdiscovery -t "/home/user/domain.com/urls.txt" -o "/home/user/domain.com/scan/http-discovery" -q 30 [-e .php,.aspx]
```