# OpenHunt

OpenHunt is designed to aid in lead-driven and lead-less threat hunting. It can be used to identify the moast common techniques used by groups associated with a specific country. It can also be used to collect information from VirusTotal and Shodan for a given IOC. 

## Install

`pip install -r requirements.txt`

## Usage

OpenHunt runs in two different modes (`-m, --mode`). One is called `ttp` and the other is `ioc`.

### TTP Mode

#### TTPs by Country

The main functionality of this was ported from [this MITRE ATT&CK script](https://github.com/mitre-attack/attack-scripts/blob/master/scripts/technique_mappings_to_csv.py). Provided a Country with `-c, --country` it downloads the current MITRE STIX data to `groups.csv` and then parses it for all TTPs used by groups affiliated to the country provided and prints them out along with a count of how many threat groups are seen using that Technique. 

It is also possible to use `-f, --file` to designate a file to parse. It expects a CSV file exported from the MITRE ATT&CK script mentioned above.

##### Countries Supported

The countries you can search for are the ones listed in the [MITRE Groups](https://attack.mitre.org/groups/) info

- Russia
- China
- Iran
- South Korea
- North Korea
- Nigeria
- Vietnam
- Lebanon
- Pakistan

###### Special Cases

- Unknown
- All

#### TTPs by Target

This works very similiarly to `TTPs by Country`. However, instead of looking at the groups by country of origin/affiliation, it only pulls the TTPs for groups that target the country/sector provided with `-t, --target`.

##### Targets Supported

- Countries, Continents, and Regions
    - Africa
    - Asia
    - China
    - Columbia
    - Europe
    - Germany
    - Hong Kong
    - India
    - Iran
    - Isreal
    - Japan
    - Jordan
    - Kuwait
    - Laos
    - Middle East
    - Nepal
    - North America
    - Romania
    - United Kingdom
    - United States
    - Russia
    - Saudia Arabia
    - South America
    - South Korea
    - Taiwan
    - Turkey
    - Vietnam

- Sectors
    - Aerospace
    - Aviation
    - Biotechnology
    - Chemical
    - Construction
    - Defense
    - Eletronics
    - Energy
    - Engineering
    - Financial
    - Government
    - Healthcare
    - Human Rights
    - Humanitarian Aid
    - Hospitality
    - Law
    - Manufacturing
    - Mining
    - Petroleum
    - Semiconductor
    - Technology
    - Telecommunications
    - Transportation
    - Travel
    - Infrastructure
    - Video Game

- Miscellaneous
    - High Profile Persons

#### Examples

`python .\openhunt.py -m ttp -c russia`
- Pulls top 10 most common techniques attributed to Russia affiliated actors using live MITRE info 

`python .\openhunt.py -m ttp -c russia -f .\groups.csv`
- References local file that ships with the repo

`python .\openhunt.py -m ttp -c russia -f .\groups.csv --limit 20`
- Pulls top 20 most common instead of top 10 (default)
- `--limit` is also compatible with live info (omit `-f, --file`)

`python .\openhunt.py -m ttp -t energy -f .\groups.csv`
- Pulls top 10 techniques seen used by groups targeting the energy sector

`python .\openhunt.py -m ttp -t asia -f .\groups.csv`
- Pulls top 10 techniques seen used by groups targeting companies/organizations in Asia

## IOC Mode

Provided an IOC (MD5, SHA1, SHA256, IP, Domain) it pulls the IOCs relationships via the VirusTotal API and creates a SIGMA rule based on these.

For each IP address seen in the SIGMA rule (whether the IOC itself or a relationship), it looks it up in Shodan and compares it to a number of fingerprints and prints to screen if something is found

Fingerprints Supported:
- Cobalt Strike Servers

If the field names in the Sigma rule do not match the field names in your SIEM/EDR/XDR platform then you can rename them (see `python openhunt.py -h`)

#### Requirements

- VirusTotal API Key
- Shodan API Key

#### Examples

`python .\openhunt.py -m ioc -vt {VirusTotal API Key} -s {Shodan API Key} -i 58.33.204.180`

#### Limitations

- Max of 10 values per relationship
- For domains and IPs, the `downloaded_files` relationship is not implemented because it requires a Premium API key

## Credit and Thank You Notes

- [MITRE](https://github.com/mitre-attack/attack-scripts/) for their research and ATT&CK scripts 
- [Bank Security on Medium](https://bank-security.medium.com/hunting-cobalt-strike-servers-385c5bedda7b) for their work on Cobalt Strike fingerprints