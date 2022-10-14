from shodan import Shodan
from stix2 import TAXIICollectionSource, MemorySource, Filter
from taxii2client.v20 import Collection
import vt, requests, json, re, argparse, csv, io, tqdm

parser = argparse.ArgumentParser(description="SOC Companion")
parser.add_argument("-m", "--mode", type=str, help="TTP or IOC")
parser.add_argument("-f", "--file", type=str, help="Use CSV file of TTPs insteald of exporting MITRE current info")
parser.add_argument("-c", "--country", type=str, help="Country to focus on in TTP file")
parser.add_argument("-vt", "--virustotal-api-key", type=str, help="VirusTotal API Key")
parser.add_argument("-s", "--shodan-api-key", type=str, help="Shodan API Key")
parser.add_argument("-i", "--ioc", type=str, help="IOC value")
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
MODE = args.mode
TTP_FILE = args.file
VT_API_KEY = args.virustotal_api_key
SHODAN_API_KEY = args.shodan_api_key
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
COUNTRY = args.country
CSV_FILE = args.file

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

def mitre(TTP_FILE, COUNTRY):
    # Adapted from https://github.com/mitre-attack/attack-scripts
    def build_taxii_source():
        """Downloads latest Enterprise or Mobile ATT&CK content from MITRE TAXII Server."""
        # Establish TAXII2 Collection instance for Enterprise ATT&CK collection
        collection_map = {
            "enterprise_attack": "95ecc380-afe9-11e4-9b6c-751b66dd541e",
            "mobile_attack": "2f669986-b40b-4423-b720-4396ca6a462b"
        }
        collection_url = "https://cti-taxii.mitre.org/stix/collections/95ecc380-afe9-11e4-9b6c-751b66dd541e/"
        collection = Collection(collection_url)
        taxii_ds = TAXIICollectionSource(collection)

        # Create an in-memory source (to prevent multiple web requests)
        return MemorySource(stix_data=taxii_ds.query())


    def get_all_techniques(src, source_name, tactic=None):
        """Filters data source by attack-pattern which extracts all ATT&CK Techniques"""
        filters = [
            Filter("type", "=", "attack-pattern"),
            Filter("external_references.source_name", "=", source_name),
        ]
        if tactic:
            filters.append(Filter('kill_chain_phases.phase_name', '=', tactic))

        results = src.query(filters)
        return remove_deprecated(results)


    def filter_for_term_relationships(src, relationship_type, object_id, target=True):
        """Filters data source by type, relationship_type and source or target"""
        filters = [
            Filter("type", "=", "relationship"),
            Filter("relationship_type", "=", relationship_type),
        ]
        if target:
            filters.append(Filter("target_ref", "=", object_id))
        else:
            filters.append(Filter("source_ref", "=", object_id))

        results = src.query(filters)
        return remove_deprecated(results)


    def filter_by_type_and_id(src, object_type, object_id, source_name):
        """Filters data source by id and type"""
        filters = [
            Filter("type", "=", object_type),
            Filter("id", "=", object_id),
            Filter("external_references.source_name", "=", source_name),
        ]
        results = src.query(filters)
        return remove_deprecated(results)


    def grab_external_id(stix_object, source_name):
        """Grab external id from STIX2 object"""
        for external_reference in stix_object.get("external_references", []):
            if external_reference.get("source_name") == source_name:
                return external_reference["external_id"]


    def remove_deprecated(stix_objects):
        """Will remove any revoked or deprecated objects from queries made to the data source"""
        # Note we use .get() because the property may not be present in the JSON data. The default is False
        # if the property is not set.
        return list(
            filter(
                lambda x: x.get("x_mitre_deprecated", False) is False and x.get("revoked", False) is False,
                stix_objects
            )
        )


    def escape_chars(a_string):
        """Some characters create problems when written to file"""
        return a_string.translate(str.maketrans({
            "\n": r"\\n",
        }))


    def do_mapping(ds, fieldnames, relationship_type, type_filter, source_name, sorting_keys, tactic=None):
        """Main logic to map techniques to mitigations, groups or software"""
        all_attack_patterns = get_all_techniques(ds, source_name, tactic)
        writable_results = []

        for attack_pattern in tqdm.tqdm(all_attack_patterns, desc="parsing data for techniques"):
            # Grabs relationships for identified techniques
            relationships = filter_for_term_relationships(ds, relationship_type, attack_pattern.id)

            for relationship in relationships:
                # Groups are defined in STIX as intrusion-set objects
                # Mitigations are defined in STIX as course-of-action objects
                # Software are defined in STIX as malware objects
                stix_results = filter_by_type_and_id(ds, type_filter, relationship.source_ref, source_name)

                if stix_results:
                    row_data = (
                        grab_external_id(attack_pattern, source_name),
                        attack_pattern.name,
                        grab_external_id(stix_results[0], source_name),
                        stix_results[0].name,
                        escape_chars(stix_results[0].description),
                        escape_chars(relationship.description),
                    )

                    writable_results.append(dict(zip(fieldnames, row_data)))

        return sorted(writable_results, key=lambda x: (x[sorting_keys[0]], x[sorting_keys[1]]))


    def main(COUNTRY):
        RUSSIA = ["ALLANITE", "Andariel", "APT28", "APT29"]
        if CSV_FILE:
            filename = CSV_FILE
        else:
            data_source = build_taxii_source()
            source_name = "mitre-attack"
            filename = "groups.csv"
            fieldnames = ("TID", "Technique Name", "GID", "Group Name", "Group Description", "Usage")
            relationship_type = "uses"
            type_filter = "intrusion-set"
            sorting_keys = ("TID", "GID")
            rowdicts = do_mapping(data_source, fieldnames, relationship_type, type_filter, source_name, sorting_keys, None)

            with io.open(filename, "w", newline="", encoding="utf-8") as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(rowdicts)
        
        ttps = []
        with open(filename, newline='', encoding='utf-8') as csvfile:
            for row in csv.reader(csvfile):
                if COUNTRY == "Russia":
                    for group in RUSSIA:
                        if row[3] == group:
                            ttps.append(row[1])
        tmp = set(ttps)
        
        for ttp in tmp:
            print(ttp +  ": " + str(ttps.count(ttp)))
    main(COUNTRY)

def shodan(IOC, SHODAN_API_KEY):
        API = Shodan(SHODAN_API_KEY)
        CS_SIGNATURES = {"SSL Serial Number": "146473198", "SSL Hash": "2007783223", "Product Name": "Cobalt Strike Beacon", "SSL SHA256": "87F2085C32B6A2CC709B365F55873E207A9CAA10BFFECF2FD16D3CF9D94D390C", "Port 50050 open": "50050", "SSL JARM": "07d14d16d21d21d00042d41d00041de5fb3038104f457d92ba02e9311512c2"}
        try:
            j = API.host(IOC)
        except:
            return 0
        
        for CS_SIGNATURE in CS_SIGNATURES:
            if CS_SIGNATURES[CS_SIGNATURE] in str(j):
                return str(IOC + " is believed to be a Cobalt Strike Server because of its " + CS_SIGNATURE)

def virusTotal(VT_API_KEY, SHODAN_API_KEY, IOC):
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
                        C2_STATUS = shodan(RELATIONSHIP_VALUE, SHODAN_API_KEY)
                        if C2_STATUS != None and C2_STATUS != 0:
                            if "Cobalt Strike" in C2_STATUS:
                                CS_SERVERS.append(str(C2_STATUS))
                        SIGMA = SIGMA.replace("ContactedIPsReplaceMe:", str(global_CI) + ":")
                        SIGMA = SIGMA.replace("selection6ReplaceMe", "selection6")
                        SIGMA = SIGMA.replace("'ContactedIPsReplaceMe'", "\"" + RELATIONSHIP_VALUE + "\"", 1)
    else:
        # downloaded_files requires Premium
        RELATIONSHIPS = ["referrer_files", "communicating_files"]
        if re.search('[a-zA-Z]', IOC):
            TYPE = "domains"
        else:
            TYPE = "ip_addresses"
            C2_STATUS = shodan(IOC, SHODAN_API_KEY)
            if C2_STATUS != None and C2_STATUS != 0:
                if "Cobalt Strike" in C2_STATUS:
                    CS_SERVERS.append(str(C2_STATUS))
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
    #for LINE in SIGMA.splitlines():
    #    if "ReplaceMe" not in LINE:
    #       print(LINE)
    #print()
    if len(CS_SERVERS)> 0:
        for CS_SERVER in CS_SERVERS:
            print(CS_SERVER)

if MODE == "ioc":
    virusTotal(VT_API_KEY, SHODAN_API_KEY, IOC)
elif MODE == "ttp":
    mitre(TTP_FILE, COUNTRY)
else:
    print("Incorrect mode")