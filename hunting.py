from turtle import pen
from unicodedata import name
from shodan import Shodan
import vt

global_kql = 1
global_list = 1
gloabal_sigmaIocRule ="""
title: Auto-Generated IOC Rule
id:
status: experimental
description: Detects artifacts related to IOC
author: SOC Companion
date: 
references: 
logsource:
    product:
    service:
detection:
    selection:
        ParentImage|endswith:
            - ReplaceMe
        Image|endswith:
            - ReplaceMe
        Hashes|contains:
            MD5=
            SHA1=
            SHA256=

"""

def shodan():
        api = Shodan(str(input("Shodan API Key: ")))
        print(api)

        ioc = str(input("IOC: "))

        def ipv4(ioc):
            ipinfo = api.host(ioc)
            print(ipinfo)
            ipv4(ioc)

def vt():
    import vt, requests, json
    objectAttrs = ["md5", "sha1", "sha256", "names"]
    #client = vt.Client(input("VTKEY: "))
    client = vt.Client("")
    file = client.get_object("/files/163351e912ba5f7ca674f6017be509eb502be223032b93d89ae538ddc92df9fc")
    md5 = file.get("md5")
    sha1 = file.get("sha1")
    sha256 = file.get("sha256")
    names = file.get("names")
    #print(names)
    print("---------------- IOC NAMES & HASHES --------------------")
    names = str(names).replace("[", "(").replace("]", ")").replace(" '", " @\"").replace("'", "\"")
    print("search in (DeviceProcessEvents, DeviceFileEvents) MD5 =~ {md5} or SHA1 =~ {sha1} or SHA256 =~ {sha256}")
    

    #for objectAttr in objectAttrs:
        #print(objectAttr)
        #if objectAttr == "names":
         #   if len(result) > 1:
          #      print("NAMES:")
           #     for name in result:
            #        print("- " + str(name))
            #elif len(result) == 1:
             #   print("NAME: "+ str(result).strip())
        #if objectAttr != "names":
         #   print(str(objectAttr).upper() + ": " + str(file.get(objectAttr)))
    url = "https://www.virustotal.com/api/v3/files/163351e912ba5f7ca674f6017be509eb502be223032b93d89ae538ddc92df9fc/dropped_files?limit=100"
    headers = {
    "accept": "application/json",
    "x-apikey": ""
    }
    response = requests.get(url, headers=headers)
    j = json.loads(str(response.text))
    hashes = []
    print("------------------- DROPPED FILES (SHA256) -----------------------")
    for i in range(0,int(j["meta"]["count"])):
        hashes.append(j["data"][int(i)]["id"])
    hashes = str(hashes).replace("[", "(").replace("'", "\"").replace("]", ")")
    print("search in (DeviceFileEvents, DeviceProcessEvents) InitiatingProcessSHA256 in~ " + str(hashes) + " or SHA256 in~ " + str(hashes))

vt()