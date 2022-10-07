from unicodedata import name
from shodan import Shodan
import vt

global_kql = 1
global_list = 1

def shodan():
        api = Shodan(str(input("Shodan API Key: ")))
        print(api)

        ioc = str(input("IOC: "))

        def ipv4(ioc):
            ipinfo = api.host(ioc)
            print(ipinfo)
            ipv4(ioc)

def vt():

    def vt_kql(names, ):
        names = str(names).replace("[", "(")
        names = str(names).replace("]", ")")
        names = str(names).replace(" '", " @\"")
        names = str(names).replace("'", "\"")
        print("search in (DeviceFileEvents, DeviceProcessEvents) | where InitiatingProcessFileName in~ " + str(names) + " or FileName in~ " + str(names))

    import vt, requests, json
    objectAttrs = ["md5", "sha1", "sha256", "names"]
    #client = vt.Client(input("VTKEY: "))
    file = client.get_object("/files/163351e912ba5f7ca674f6017be509eb502be223032b93d89ae538ddc92df9fc")
    md5 = file.get("md5")
    sha1 = file.get("sha1")
    sha256 = file.get("sha256")
    names = file.get("names")
    print(md5)
    #print(names)
    vt_kql(names)

    

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
    #print(response.)
    j = json.loads(str(response.text))
    print("DROPPED FILES (SHA256): ")
    for i in range(0,int(j["meta"]["count"])):
        print(j["data"][int(i)]["id"])

vt()