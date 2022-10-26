from ast import Store
from numpy import append
from shodan import Shodan
from stix2 import TAXIICollectionSource, MemorySource, Filter
from taxii2client.v20 import Collection
from collections import Counter
import vt, requests, json, re, argparse, csv, io, tqdm

parser = argparse.ArgumentParser(description="OpenHunt: Tailored Threat Hunting Information")
parser.add_argument("-m", "--mode", type=str, help="TTP or IOC")
parser.add_argument("-f", "--file", type=str, help="Use CSV file of TTPS insteald of exporting MITRE current info")
parser.add_argument("--origin", action="append", type=str, help="Filter on the threat actors' affiliation or country of origin")
parser.add_argument("--target", action="append", type=str, help="Filter on the threat actors' targets")
parser.add_argument("-l", "--limit", type=int, default=10, help="Top X most common techniques where X is the input (default: 10)")
parser.add_argument("-i", "--ioc", type=str, help="IOC value")
parser.add_argument("--logical-and", action="store_true", default=False, help="Only match on groups that satisfy all of the parameters" )
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
mode = args.mode
ioc = args.ioc
global_PI = args.parent_images
global_IN = args.image_names
global_IH = args.image_hashes
global_TF = args.target_files
global_CD = args.contacted_domains
global_CI = args.contacted_ips
global_RF = args.referrer_files
global_CF = args.communicating_files
global_DF = args.downloaded_files
limit = args.limit
affiliations_from_input = args.origin
filename = args.file
targets_from_input = args.target
logical_and = args.logical_and

keys = json.load(open("json/keys.json"))
virustotal_api_key = str(keys["api_keys"]["virustotal"])
shodan_api_key = str(keys["api_keys"]["shodan"])

sigma_data = ""
sigma_file = open("sigma/template.yaml")
lines = sigma_file.readlines()
for line in lines:
    sigma_data += line

def mitre(affiliations_from_input, targets_from_input, limit, filename):
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


    def main(affiliations_from_input, targets_from_input, logical_and, limit, filename):
        # Source: https://attack.mitre.org/groups/
        # 133 Groups on 10/15/2022
        # File Hash: 79FCC4E1689077298F221F550A41550492A7866BDD1DCFCAF027779E62788134
        groups = []
        strict_groups = []
        ttps = []
        num_args = 0
        mappings = json.load(open("json/mappings.json"))

        if affiliations_from_input != None:
            if len(affiliations_from_input) == 1 and affiliations_from_input[0] == "all":
                affiliations_from_input = mappings["origins"]["countries"]
            num_args += len(affiliations_from_input)
            for affiliation_input in affiliations_from_input:
                for group in mappings["origins"]["countries"][affiliation_input]:
                    groups.append(group)
        
        if targets_from_input != None:
            num_args += len(targets_from_input)
            for target_from_input in targets_from_input:
                for continent in mappings["targets"]["continents"]:
                    if target_from_input == continent:
                        for group in mappings["targets"]["continents"][continent]["groups"]:
                            groups.append(group)
                        print(mappings["targets"]["continents"][continent]["countries_or_regions"])
                        try:
                            if mappings["targets"]["continents"][continent]["countries_or_regions"]:
                                for country_or_region in mappings["targets"]["continents"][continent]["countries_or_regions"]:
                                    print(country_or_region)
                                    for group in mappings["targets"]["continents"][continent]["countries_or_regions"][country_or_region]["groups"]:
                                        groups.append(group)
                        except KeyError:
                            continue
                    else:
                        try:
                            if target_from_input in mappings["targets"]["continents"][continent]["countries_or_regions"]:
                                for country_or_region in mappings["targets"]["continents"][continent]["countries_or_regions"]:
                                    if target_from_input == country_or_region:
                                        for group in mappings["targets"]["continents"][continent]["countries_or_regions"][country_or_region]["groups"]:
                                            groups.append(group)
                        except KeyError:
                            pass
                for sector in mappings["targets"]["sectors"]:
                    if target_from_input == sector:
                        try:
                            for group in mappings["targets"]["sectors"][sector]["groups"]:
                                groups.append(group)
                        except KeyError:
                            pass
                        try:
                            if mappings["targets"]["sectors"][sector]["subsectors"]:
                                for subsector in mappings["targets"]["sectors"][sector]["subsectors"]:
                                    for group in mappings["targets"]["sectors"][sector]["subsectors"][subsector]["groups"]:
                                        groups.append(group)
                        except KeyError:
                            pass
                    else:
                        try:
                            for subsector in mappings["targets"]["sectors"][sector]["subsectors"]:
                                if target_from_input == subsector:
                                    for group in mappings["targets"]["sectors"][sector]["subsectors"][subsector]["groups"]:
                                        groups.append(group)
                        except KeyError:
                            pass

        if logical_and == True:
            for group in groups:
                if groups.count(group) == num_args:
                    strict_groups.append(group)
            groups = set(strict_groups)

        if filename == None:
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
        
        with open(filename, newline='', encoding='utf-8') as csvfile:
            for row in csv.reader(csvfile):
                for group in groups:
                    if group.lower() == row[3].lower():
                        ttps.append(row[1])
        print(str(len(groups)) + " groups match that search\n")
        for element in Counter(ttps).most_common(limit):
                print(str(element).strip("('").strip(")").replace("',", ":"))

    main(affiliations_from_input, targets_from_input, logical_and, limit, filename)

def shodan(ioc, shodan_api_key):
        api = Shodan(shodan_api_key)
        cobalt_strike_sigantures = {"SSL Serial Number": "146473198", "SSL Hash": "2007783223", "Product Name": "Cobalt Strike Beacon", "SSL sha256": "87F2085C32B6A2CC709B365F55873E207A9CAA10BFFECF2FD16D3CF9D94D390C", "Port 50050 open": "50050", "SSL JARM": "07d14d16d21d21d00042d41d00041de5fb3038104f457d92ba02e9311512c2"}
        try:
            j = api.host(ioc)
        except:
            return 0
        
        for signature in cobalt_strike_sigantures:
            if cobalt_strike_sigantures[signature] in str(j):
                return str(ioc + " is believed to be a Cobalt Strike Server because of its " + signature)

def virusTotal(virustotal_api_key, shodan_api_key, ioc, sigma_data):
    client = vt.Client(virustotal_api_key)
    cobalt_strike_servers = []
    if (len(ioc) == 32 or len(ioc) == 40 or len(ioc) == 64) and "." not in ioc:
        hash = ioc
        file = client.get_object("/files/" + hash)
        md5 = file.get("md5")
        sha1 = file.get("sha1")
        sha256 = file.get("sha256")
        names = file.get("names")
        if len(names) > 0:
            for name in names:
                sigma_data = sigma_data.replace("'ImageNameReplaceMe'", str(name), 1)
                sigma_data = sigma_data.replace("ImageNameReplaceMe:", " ImageName:")
                sigma_data = sigma_data.replace("selection2ReplaceMe", "selection2")
        if md5:
            sigma_data = sigma_data.replace("'IOCMD5ReplaceMe'", md5)
            sigma_data = sigma_data.replace("ImageHashesReplaceMe", global_IH)
            sigma_data = sigma_data.replace("selection3ReplaceMe", "selection3")
        if sha1:
            sigma_data = sigma_data.replace("'IOCSHA1ReplaceMe'", sha1)
            sigma_data = sigma_data.replace("ImageHashesReplaceMe", global_IH)
            sigma_data = sigma_data.replace("selection3ReplaceMe", "selection3")
        if sha256:
            sigma_data = sigma_data.replace("'IOCSHA256ReplaceMe'", sha256)
            sigma_data = sigma_data.replace("ImageHashesReplaceMe", global_IH)
            sigma_data = sigma_data.replace("selection3ReplaceMe", "selection3")
        virustotal_relationships = ["dropped_files", "execution_parents", "contacted_domains", "contacted_ips"]
        for relationship in virustotal_relationships:
            url = "https://www.virustotal.com/api/v3/files/" + hash + "/" + relationship + "?limit=100"
            headers = {
                "accept": "application/json",
                "x-apikey": virustotal_api_key
            }
            response = requests.get(url, headers=headers)
            json_response = json.loads(str(response.text))
            relationship_values = []
            count_of_values = int(json_response["meta"]["count"])
            if count_of_values > 10:
                print("More than 10 results for " + relationship + ", stopping at 10")
                count_of_values = 9
            for i in range(0,count_of_values):
                relationship_values.append(json_response["data"][int(i)]["id"])
            if len(relationship_values) > 0:
                for value in relationship_values:
                    if relationship == "dropped_files":
                        sigma_data = sigma_data.replace("TargetFileHashReplaceMe:", str(global_TF) + ":")
                        sigma_data = sigma_data.replace("selection4ReplaceMe", "selection4")
                        sigma_data = sigma_data.replace("'TargetFileHashReplaceMe'", value, 1)
                    if relationship == "execution_parents":
                        sigma_data = sigma_data.replace("ParentImageSHA256ReplaceMe:", str(global_PI) + ":")
                        sigma_data = sigma_data.replace("selectionReplaceMe", "selection")
                        sigma_data = sigma_data.replace("'ParentImageSHA256ReplaceMe'", value, 1)
                    if relationship == "contacted_domains":
                        sigma_data = sigma_data.replace("ContactedDomainReplaceMe:", str(global_CD) + ":")
                        sigma_data = sigma_data.replace("selection5ReplaceMe", "selection5")
                        sigma_data = sigma_data.replace("'ContactedDomainReplaceMe'", "\"" + value + "\"", 1)
                    if relationship == "contacted_ips":
                        c2_status = shodan(value, shodan_api_key)
                        if c2_status != None and c2_status != 0:
                            if "Cobalt Strike" in c2_status:
                                cobalt_strike_servers.append(str(c2_status))
                        sigma_data = sigma_data.replace("ContactedIPsReplaceMe:", str(global_CI) + ":")
                        sigma_data = sigma_data.replace("selection6ReplaceMe", "selection6")
                        sigma_data = sigma_data.replace("'ContactedIPsReplaceMe'", "\"" + value + "\"", 1)
    else:
        # downloaded_files requires Premium
        virustotal_relationships = ["referrer_files", "communicating_files"]
        if re.search('[a-zA-Z]', ioc):
            type = "domains"
        else:
            type = "ip_addresses"
            c2_status = shodan(ioc, shodan_api_key)
            if c2_status != None and c2_status != 0:
                if "Cobalt Strike" in c2_status:
                    cobalt_strike_servers.append(str(c2_status))
        for relationship in virustotal_relationships:
            url = "https://www.virustotal.com/api/v3/" + type + "/" + ioc + "/" + relationship + "?limit=40"
            headers = {
                "accept": "application/json",
                "x-apikey": virustotal_api_key
            }
            response = requests.get(url, headers=headers)
            json_response = json.loads(str(response.text))
            relationship_values = []
            count_of_values = int(json_response["meta"]["count"])
            if count_of_values > 10:
                print("More than 10 results for " + relationship + ", stopping at 10")
                count_of_values = 9
            for i in range(0,count_of_values):
                relationship_values.append(json_response["data"][int(i)]["id"])
            if len(relationship_values) > 0:
                for relationship_value in relationship_values:
                    if relationship == "referrer_files":
                        sigma_data = sigma_data.replace("ReferrerFilesReplaceMe:", str(global_RF) + ":")
                        sigma_data = sigma_data.replace("selection7ReplaceMe", "selection7")
                        sigma_data = sigma_data.replace("'ReferrerFilesReplaceMe'", relationship_value, 1)
                    if relationship == "communicating_files":
                        sigma_data = sigma_data.replace("CommunicatingFilesReplaceMe:", str(global_CF) + ":")
                        sigma_data = sigma_data.replace("selection8ReplaceMe", "selection8")
                        sigma_data = sigma_data.replace("'CommunicatingFilesReplaceMe'", relationship_value, 1)
                    if relationship == "downloaded_files":
                        sigma_data = sigma_data.replace("DownloadedFilesReplaceMe:", str(global_DF) + ":")
                        sigma_data = sigma_data.replace("selection9ReplaceMe", "selection9")
                        sigma_data = sigma_data.replace("'DownloadedFilesReplaceMe'", "\"" + relationship_value + "\"", 1)
    for line in sigma_data.splitlines():
        if "ReplaceMe" not in line:
           print(line)
    print()
    if len(cobalt_strike_servers)> 0:
        for server in cobalt_strike_servers:
            print(server)

if mode == "ioc":
    virusTotal(virustotal_api_key, shodan_api_key, ioc, sigma_data)
elif mode == "ttp":
    mitre(affiliations_from_input, targets_from_input, limit, filename)
else:
    print("Incorrect mode")