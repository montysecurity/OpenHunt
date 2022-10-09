from turtle import pen
from unicodedata import name
from shodan import Shodan
import vt, requests, json

global_kql = 1
global_list = 1
gloabal_sigmaIocRule ="""
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
    selection:
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
    selection2:
        ImageReplaceMe:
            - 'ImageReplaceMe'
            - 'ImageReplaceMe'
            - 'ImageReplaceMe'
            - 'ImageReplaceMe'
            - 'ImageReplaceMe'
            - 'ImageReplaceMe'
            - 'ImageReplaceMe'
            - 'ImageReplaceMe'
            - 'ImageReplaceMe'
            - 'ImageReplaceMe'
    selection3:
        HashesReplaceMe:
            - 'IOCMD5ReplaceMe'
            - 'IOCSHA1ReplaceMe'
            - 'IOCSHA256ReplaceMe'
    selection4:
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
    selection5:
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
            - 'ContactedDomainReplaceMe'
    selection6:
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
            - 'ContactedIPsReplaceMe'
    condition: 1 of selection*
    falsepositives:
        - unknown
    tags:
"""

def shodan():
        api = Shodan(str(input("Shodan API Key: ")))
        print(api)

        ioc = str(input("IOC: "))

        def ipv4(ioc):
            ipinfo = api.host(ioc)
            print(ipinfo)
            ipv4(ioc)

def virusTotal():
    #client = vt.Client(input("VTKEY: "))
    apiKey = ""
    client = vt.Client(apiKey)
    hash = "79128b28776eb3fcae5fe10aa06d7215c22df325751afebdbe0049a3010256ce"
    file = client.get_object("/files/" + hash)
    MD5 = file.get("md5")
    SHA1 = file.get("sha1")
    SHA256 = file.get("sha256")
    NAMES = file.get("names")
    SIGMA = gloabal_sigmaIocRule
    if len(NAMES) > 0:
        for NAME in NAMES:
            SIGMA = SIGMA.replace("- 'ImageReplaceMe'", str("- \'"+ str(NAME) + "\'"), 1)
        SIGMA = SIGMA.replace(" ImageReplaceMe:", " Image:")
    if MD5:
        SIGMA = SIGMA.replace("'IOCMD5ReplaceMe'", MD5)
        SIGMA = SIGMA.replace("HashesReplaceMe", "Hashes")
    if SHA1:
        SIGMA = SIGMA.replace("'IOCSHA1ReplaceMe'", SHA1)
        SIGMA = SIGMA.replace("HashesReplaceMe", "Hashes")
    if SHA256:
        SIGMA = SIGMA.replace("'IOCSHA256ReplaceMe'", SHA256)
        SIGMA = SIGMA.replace("HashesReplaceMe", "Hashes")
    URL = "https://www.virustotal.com/api/v3/files/" + hash + "/dropped_files?limit=100"
    HEADERS = {
    "accept": "application/json",
    "x-apikey": apiKey
    }
    RESPONSE = requests.get(URL, headers=HEADERS)
    j = json.loads(str(RESPONSE.text))
    DROPPED_FILE_HASHES = []
    for i in range(0,int(j["meta"]["count"])):
        DROPPED_FILE_HASHES.append(j["data"][int(i)]["id"])
    if len(DROPPED_FILE_HASHES) > 0:
        for HASH in DROPPED_FILE_HASHES:
            SIGMA = SIGMA.replace("'TargetFileHashReplaceMe'", HASH, 1)
        SIGMA = SIGMA.replace("TargetFileHashReplaceMe:", "TargetFileHash:")
    
    URL = "https://www.virustotal.com/api/v3/files/" + hash + "/execution_parents?limit=100"
    HEADERS = {
    "accept": "application/json",
    "x-apikey": apiKey
    }
    RESPONSE = requests.get(URL, headers=HEADERS)
    j = json.loads(str(RESPONSE.text))
    EXECUTION_PARENTS = []
    for i in range(0,int(j["meta"]["count"])):
        EXECUTION_PARENTS.append(j["data"][int(i)]["id"])
    if len(EXECUTION_PARENTS) > 0:
        for HASH in EXECUTION_PARENTS:
            SIGMA = SIGMA.replace("'ParentImageSHA256ReplaceMe'", HASH, 1)
        SIGMA = SIGMA.replace("ParentImageSHA256ReplaceMe:", "ParentImageSHA256:")


    URL = "https://www.virustotal.com/api/v3/files/" + hash + "/contacted_domains?limit=100"
    HEADERS = {
    "accept": "application/json",
    "x-apikey": apiKey
    }
    RESPONSE = requests.get(URL, headers=HEADERS)
    j = json.loads(str(RESPONSE.text))
    CONTACTED_DOMAINS = []
    for i in range(0,int(j["meta"]["count"])):
        CONTACTED_DOMAINS.append(j["data"][int(i)]["id"])
    if len(CONTACTED_DOMAINS) > 0:
        for DOMAIN in CONTACTED_DOMAINS:
            SIGMA = SIGMA.replace("'ContactedDomainReplaceMe'", "\"" + DOMAIN + "\"", 1)
        SIGMA = SIGMA.replace("ContactedDomainReplaceMe:", "Domain:")

    URL = "https://www.virustotal.com/api/v3/files/" + hash + "/contacted_ips?limit=100"
    HEADERS = {
    "accept": "application/json",
    "x-apikey": apiKey
    }
    RESPONSE = requests.get(URL, headers=HEADERS)
    j = json.loads(str(RESPONSE.text))
    CONTACTED_IPS = []
    for i in range(0,int(j["meta"]["count"])):
        CONTACTED_IPS.append(j["data"][int(i)]["id"])
    if len(CONTACTED_IPS) > 0:
        for IP in CONTACTED_IPS:
            SIGMA = SIGMA.replace("'ContactedIPsReplaceMe'", "\"" + IP + "\"", 1)
        SIGMA = SIGMA.replace("ContactedIPsReplaceMe:", "ContactedIPs:")

    for line in SIGMA.splitlines():
        if "ReplaceMe" not in line:
            print(line)

virusTotal()