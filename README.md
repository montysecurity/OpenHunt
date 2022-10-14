# OpenHunt

Create SIGMA rules using OSINT gathered on provided IOCs

## Requirements

- VirusTotal API Key
- Shodan API Key

## Install

`pip install -r requirements.txt`

## Usage

OpenHunt runs in two different modes (`-m, --mode`). One is called `ttp` and the other is `ioc`.

### TTP Mode

The main functionality of this was ported from [this MITRE ATT&CK script](https://github.com/mitre-attack/attack-scripts/blob/master/scripts/technique_mappings_to_csv.py). Provided a Country with `-c, --country` it parses the current MITRE STIX data for all TTPs used by groups affiliated to that Country and prints them out along with a count of how many threat groups are seen using that Technique. It will write the info to a `groups.csv`.

It is also possible to use `-f, --file` to designate a file to parse. It expects a CSV file exported from the MITRE ATT&CK script mentioned above.

#### Examples

`python .\openhunt.py -m ttp -c russia`
- Pulls current MITRE info on Russia

`python .\openhunt.py -m ttp -c russia -f .\groups.csv`
- References local file that ships with the repo

## IOC Mode

Provided an IOC (MD5, SHA1, SHA256, IP, Domain) it pulls the IOCs relationships via the VirusTotal API and creates a SIGMA rule based on these.

For each IP address seen in the SIGMA rule (whether the IOC itself or a relationship), it looks it up in Shodan and compares it to a number of fingerprints and prints to screen if something is found

Fingerprints Supported:
- Cobalt Strike Servers

If the field names in the Sigma rule do no match the field names in your SIEM/EDR/XDR platform then you can rename them (see `python openhunt.py -h`)

## Credit and Thank You Notes

- [MITRE](https://github.com/mitre-attack/attack-scripts/) for their research and ATT&CK scripts 
- [Bank Security on Medium](https://bank-security.medium.com/hunting-cobalt-strike-servers-385c5bedda7b) for their work on Cobalt Strike fingerprints