from shodan import Shodan
import vt

def shodan():
        api = Shodan(str(input("Shodan API Key: ")))
        print(api)

        ioc = str(input("IOC: "))

        def ipv4(ioc):
            ipinfo = api.host(ioc)
            print(ipinfo)
            ipv4(ioc)

def vt():
    import vt, requests
    objectAttrs = ["md5", "sha1", "sha256", "names"]
    client = vt.Client(input("VTKEY: "))
    file = client.get_object("/files/163351e912ba5f7ca674f6017be509eb502be223032b93d89ae538ddc92df9fc")
    for objectAttr in objectAttrs:
        print(file.get(objectAttr))
    url = "https://www.virustotal.com/api/v3/files/163351e912ba5f7ca674f6017be509eb502be223032b93d89ae538ddc92df9fc/dropped_files?limit=10"
    headers = {
    "accept": "application/json",
    "x-apikey": str(client)
    }
    response = requests.get(url, headers=headers)
    print(response)

vt()