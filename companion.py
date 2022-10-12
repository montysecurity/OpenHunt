from turtle import pen
from unicodedata import name
from xmlrpc.client import APPLICATION_ERROR
from shodan import Shodan
import vt, requests, json, re, argparse

parser = argparse.ArgumentParser(description="SOC Companion")
parser.add_argument("-K", "--key", type=str, help="VirusTotal API Key")
parser.add_argument("-I", "--ioc", type=str, help="IOC value")
parser.add_argument("-pi", "--parent-images", type=str, help="Rename the ParentImageSHA256 field", default="ParentImageSHA256")
parser.add_argument("-in", "--image-names", type=str, help="Rename the Image field", default="ImageNames")
parser.add_argument("-ih", "--image-hashes", type=str, help="Rename the Image field", default="ImageHashes")
parser.add_argument("-tf", "--target-files", type=str, help="Rename the TargetFileHash field", default="TargetFileHash")
parser.add_argument("-cd", "--contacted-domains", type=str, help="Rename the ContactedDomains field", default="ContactedDomains")
parser.add_argument("-ci", "--contacted-ips", type=str, help="Rename the ContactedIPs field", default="ContactedIPs")
parser.add_argument("-rf", "--referrer-files", type=str, help="Rename the ReferrerFiles field", default="ReferrerFiles")
parser.add_argument("-cf", "--communicating-files", type=str, help="Rename the CommunicatingFiles field", default="CommunicatingFiles")
parser.add_argument("-df", "--downloaded-files", type=str, help="Rename the DownloadedFiles field", default="DownloadedFiles")

args = parser.parse_args()
VT_API_KEY = args.key
IOC = args.ioc
global_PI = args.parent_images
global_IN = args.image_names
global_IH = args.image_hashes
global_TF = args.target_files
global_CD = args.contacted_domains
global_CI = args.contacted_ips
global_RF = args.referrer_files
global_CF = args.communicating_files
global_DF = args.downloaded_files

GLOBAL_SIGMA_TEMPLATE ="""
title: Auto-Generated IOC Rule
id:
status: experimental
description: Artifacts Related to IOC
author: SOC Companion
date: 
references: 
logsource:
    product:
    service:
detection:
    selectionReplaceMe:
        ParentImageSHA256ReplaceMe:
            - 'ParentImageSHA256ReplaceMe'
            - 'ParentImageSHA256ReplaceMe'
            - 'ParentImageSHA256ReplaceMe'
            - 'ParentImageSHA256ReplaceMe'
            - 'ParentImageSHA256ReplaceMe'
            - 'ParentImageSHA256ReplaceMe'
            - 'ParentImageSHA256ReplaceMe'
            - 'ParentImageSHA256ReplaceMe'
            - 'ParentImageSHA256ReplaceMe'
            - 'ParentImageSHA256ReplaceMe'
    selection2ReplaceMe:
        ImageNameReplaceMe:
            - 'ImageNameReplaceMe'
            - 'ImageNameReplaceMe'
            - 'ImageNameReplaceMe'
            - 'ImageNameReplaceMe'
            - 'ImageNameReplaceMe'
            - 'ImageNameReplaceMe'
            - 'ImageNameReplaceMe'
            - 'ImageNameReplaceMe'
            - 'ImageNameReplaceMe'
            - 'ImageNameReplaceMe'
            - 'ImageNameReplaceMe'
    selection3ReplaceMe:
        ImageHashesReplaceMe:
            - 'IOCMD5ReplaceMe'
            - 'IOCSHA1ReplaceMe'
            - 'IOCSHA256ReplaceMe'
    selection4ReplaceMe:
        TargetFileHashReplaceMe:
            - 'TargetFileHashReplaceMe'
            - 'TargetFileHashReplaceMe'
            - 'TargetFileHashReplaceMe'
            - 'TargetFileHashReplaceMe'
            - 'TargetFileHashReplaceMe'
            - 'TargetFileHashReplaceMe'
            - 'TargetFileHashReplaceMe'
            - 'TargetFileHashReplaceMe'
            - 'TargetFileHashReplaceMe'
            - 'TargetFileHashReplaceMe'
            - 'TargetFileHashReplaceMe'
    selection5ReplaceMe:
        ContactedDomainReplaceMe:
            - 'ContactedDomainReplaceMe'
            - 'ContactedDomainReplaceMe'
            - 'ContactedDomainReplaceMe'
            - 'ContactedDomainReplaceMe'
            - 'ContactedDomainReplaceMe'
            - 'ContactedDomainReplaceMe'
            - 'ContactedDomainReplaceMe'
            - 'ContactedDomainReplaceMe'
            - 'ContactedDomainReplaceMe'
            - 'ContactedDomainReplaceMe'
    selection6ReplaceMe:
        ContactedIPsReplaceMe:
            - 'ContactedIPsReplaceMe'
            - 'ContactedIPsReplaceMe'
            - 'ContactedIPsReplaceMe'
            - 'ContactedIPsReplaceMe'
            - 'ContactedIPsReplaceMe'
            - 'ContactedIPsReplaceMe'
            - 'ContactedIPsReplaceMe'
            - 'ContactedIPsReplaceMe'
            - 'ContactedIPsReplaceMe'
            - 'ContactedIPsReplaceMe'
    selection7ReplaceMe:
        ReferrerFilesReplaceMe:
            - 'ReferrerFilesReplaceMe'
            - 'ReferrerFilesReplaceMe'
            - 'ReferrerFilesReplaceMe'
            - 'ReferrerFilesReplaceMe'
            - 'ReferrerFilesReplaceMe'
            - 'ReferrerFilesReplaceMe'
            - 'ReferrerFilesReplaceMe'
            - 'ReferrerFilesReplaceMe'
            - 'ReferrerFilesReplaceMe'
            - 'ReferrerFilesReplaceMe'
    selection8ReplaceMe:
        CommunicatingFilesReplaceMe:
            - 'CommunicatingFilesReplaceMe'
            - 'CommunicatingFilesReplaceMe'
            - 'CommunicatingFilesReplaceMe'
            - 'CommunicatingFilesReplaceMe'
            - 'CommunicatingFilesReplaceMe'
            - 'CommunicatingFilesReplaceMe'
            - 'CommunicatingFilesReplaceMe'
            - 'CommunicatingFilesReplaceMe'
            - 'CommunicatingFilesReplaceMe'
            - 'CommunicatingFilesReplaceMe'
    selection9ReplaceMe:
        DownloadedFilesReplaceMe:
            - 'DownloadedFilesReplaceMe'
            - 'DownloadedFilesReplaceMe'
            - 'DownloadedFilesReplaceMe'
            - 'DownloadedFilesReplaceMe'
            - 'DownloadedFilesReplaceMe'
            - 'DownloadedFilesReplaceMe'
            - 'DownloadedFilesReplaceMe'
            - 'DownloadedFilesReplaceMe'
            - 'DownloadedFilesReplaceMe'
            - 'DownloadedFilesReplaceMe'
    condition: 1 of selection*
    falsepositives:
        - unknown
    tags:
"""

def shodan(IOC):
        #IOC = "120.48.107.143"
        #IOC = "8.8.8.8"
        API = Shodan("")
        try:
            j = API.host(IOC)
        except:
            return 0

        if "146473198" in str(j): #SSL Seral Number
            return 1
        if "2007783223" in str(j): # SSL Hash
            return 1
        if "Cobalt Strike Beacon" in str(j): # Device Product Name
            return 1
        return 0

def virusTotal(VT_API_KEY, IOC):
    API_KEY = VT_API_KEY
    CLIENT = vt.Client(API_KEY)
    SIGMA = GLOBAL_SIGMA_TEMPLATE
    CS_SERVERS = []
    if (len(IOC) == 32 or len(IOC) == 40 or len(IOC) == 64) and "." not in IOC:
        HASH = IOC
        FILE = CLIENT.get_object("/files/" + HASH)
        MD5 = FILE.get("md5")
        SHA1 = FILE.get("sha1")
        SHA256 = FILE.get("sha256")
        NAMES = FILE.get("names")
        if len(NAMES) > 0:
            for NAME in NAMES:
                SIGMA = SIGMA.replace("'ImageNameReplaceMe'", str(NAME), 1)
                SIGMA = SIGMA.replace("ImageNameReplaceMe:", " ImageName:")
                SIGMA = SIGMA.replace("selection2ReplaceMe", "selection2")
        if MD5:
            SIGMA = SIGMA.replace("'IOCMD5ReplaceMe'", MD5)
            SIGMA = SIGMA.replace("ImageHashesReplaceMe", global_IH)
            SIGMA = SIGMA.replace("selection3ReplaceMe", "selection3")
        if SHA1:
            SIGMA = SIGMA.replace("'IOCSHA1ReplaceMe'", SHA1)
            SIGMA = SIGMA.replace("ImageHashesReplaceMe", global_IH)
            SIGMA = SIGMA.replace("selection3ReplaceMe", "selection3")
        if SHA256:
            SIGMA = SIGMA.replace("'IOCSHA256ReplaceMe'", SHA256)
            SIGMA = SIGMA.replace("ImageHashesReplaceMe", global_IH)
            SIGMA = SIGMA.replace("selection3ReplaceMe", "selection3")
        RELATIONSHIPS = ["dropped_files", "execution_parents", "contacted_domains", "contacted_ips"]
        for RELATIONSHIP in RELATIONSHIPS:
            URL = "https://www.virustotal.com/api/v3/files/" + HASH + "/" + RELATIONSHIP + "?limit=100"
            HEADERS = {
                "accept": "application/json",
                "x-apikey": API_KEY
            }
            RESPONSE = requests.get(URL, headers=HEADERS)
            JSON_RESPONSE = json.loads(str(RESPONSE.text))
            RELATIONSHIP_VALUES = []
            MAX = int(JSON_RESPONSE["meta"]["count"])
            if MAX > 10:
                print("More than 10 results for " + RELATIONSHIP + ", stopping at 10")
                MAX = 9
            for i in range(0,MAX):
                RELATIONSHIP_VALUES.append(JSON_RESPONSE["data"][int(i)]["id"])
            if len(RELATIONSHIP_VALUES) > 0:
                for RELATIONSHIP_VALUE in RELATIONSHIP_VALUES:
                    if RELATIONSHIP == "dropped_files":
                        SIGMA = SIGMA.replace("TargetFileHashReplaceMe:", str(global_TF) + ":")
                        SIGMA = SIGMA.replace("selection4ReplaceMe", "selection4")
                        SIGMA = SIGMA.replace("'TargetFileHashReplaceMe'", RELATIONSHIP_VALUE, 1)
                    if RELATIONSHIP == "execution_parents":
                        SIGMA = SIGMA.replace("ParentImageSHA256ReplaceMe:", str(global_PI) + ":")
                        SIGMA = SIGMA.replace("selectionReplaceMe", "selection")
                        SIGMA = SIGMA.replace("'ParentImageSHA256ReplaceMe'", RELATIONSHIP_VALUE, 1)
                    if RELATIONSHIP == "contacted_domains":
                        SIGMA = SIGMA.replace("ContactedDomainReplaceMe:", str(global_CD) + ":")
                        SIGMA = SIGMA.replace("selection5ReplaceMe", "selection5")
                        SIGMA = SIGMA.replace("'ContactedDomainReplaceMe'", "\"" + RELATIONSHIP_VALUE + "\"", 1)
                    if RELATIONSHIP == "contacted_ips":
                        if shodan(RELATIONSHIP_VALUE) == 1:
                            CS_SERVERS.append(RELATIONSHIP_VALUE)
                        SIGMA = SIGMA.replace("ContactedIPsReplaceMe:", str(global_CI) + ":")
                        SIGMA = SIGMA.replace("selection6ReplaceMe", "selection6")
                        SIGMA = SIGMA.replace("'ContactedIPsReplaceMe'", "\"" + RELATIONSHIP_VALUE + "\"", 1)
        for LINE in SIGMA.splitlines():
            if "ReplaceMe" not in LINE:
                print(LINE)
        print()
        if len(CS_SERVERS)> 0:
            print("This hash contacts the following IPs, which are believed to be Cobalt Strike servers")
            for CS_SERVER in CS_SERVERS:
                print("- " + CS_SERVER)
    else:
        # downloaded_files requires Premium
        RELATIONSHIPS = ["referrer_files", "communicating_files"]
        if re.search('[a-zA-Z]', IOC):
            TYPE = "domains"
        else:
            TYPE = "ip_addresses"
        for RELATIONSHIP in RELATIONSHIPS:
            URL = "https://www.virustotal.com/api/v3/" + TYPE + "/" + IOC + "/" + RELATIONSHIP + "?limit=40"
            HEADERS = {
                "accept": "application/json",
                "x-apikey": API_KEY
            }
            RESPONSE = requests.get(URL, headers=HEADERS)
            JSON_RESPONSE = json.loads(str(RESPONSE.text))
            RELATIONSHIP_VALUES = []
            MAX = int(JSON_RESPONSE["meta"]["count"])
            if MAX > 10:
                print("More than 10 results for " + RELATIONSHIP + ", stopping at 10")
                MAX = 9
            for i in range(0,MAX):
                RELATIONSHIP_VALUES.append(JSON_RESPONSE["data"][int(i)]["id"])
            if len(RELATIONSHIP_VALUES) > 0:
                for RELATIONSHIP_VALUE in RELATIONSHIP_VALUES:
                    if RELATIONSHIP == "referrer_files":
                        SIGMA = SIGMA.replace("ReferrerFilesReplaceMe:", str(global_RF) + ":")
                        SIGMA = SIGMA.replace("selection7ReplaceMe", "selection7")
                        SIGMA = SIGMA.replace("'ReferrerFilesReplaceMe'", RELATIONSHIP_VALUE, 1)
                    if RELATIONSHIP == "communicating_files":
                        SIGMA = SIGMA.replace("CommunicatingFilesReplaceMe:", str(global_CF) + ":")
                        SIGMA = SIGMA.replace("selection8ReplaceMe", "selection8")
                        SIGMA = SIGMA.replace("'CommunicatingFilesReplaceMe'", RELATIONSHIP_VALUE, 1)
                    if RELATIONSHIP == "downloaded_files":
                        SIGMA = SIGMA.replace("DownloadedFilesReplaceMe:", str(global_DF) + ":")
                        SIGMA = SIGMA.replace("selection9ReplaceMe", "selection9")
                        SIGMA = SIGMA.replace("'DownloadedFilesReplaceMe'", "\"" + RELATIONSHIP_VALUE + "\"", 1)
        for LINE in SIGMA.splitlines():
            if "ReplaceMe" not in LINE:
               print(LINE)
        print()
        if shodan(IOC) == 1:
            print("The IOC you submitted is believed to be a Cobalt Strike Server")

virusTotal(VT_API_KEY, IOC)
#shodan(IOC)