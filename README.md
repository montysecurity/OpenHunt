# OpenHunt

OpenHunt is designed to give SOC analysts/threat hunters information that allows them to make more informed hunts. It runs in 2 modes (designated by `-m, --mode`): `ttp` and `ioc`.

TTP mode is used to parse MITRE info for common techniques threat actors use given a country of origin/affiliation (`--origin`) or a region/business sector they have targeted (`--target`).

IOC mode is designed to give you related artifacts to a given IOC using the VirusTotal/Shodan APIs. It focuses on arifacts that can be found in most SIEM/EDR tech stacks such has file hash, name, remote IP, and domain (and a few more).

## Requirements

- Python3
- VirusTotal API Key (free; IOC mode only)
- Shodan API Key (free; IOC mode only)
- Populate `keys.json` with the API keys

## Install

`pip install -r requirements.txt`

## Cheat Sheet

- Get top 10 most common TTPs used out of all MITRE Groups: `python .\openhunt.py -m ttp --origin all -f .\groups.csv`

- Get top 10 most common TTPs used by threat actors affiliated with Russia: `python .\openhunt.py -m ttp --origin Russia -f .\groups.csv`

- Get top 15 most common TTPs used by threat actors targeting government organizations in any country: `python .\openhunt.py -m ttp --target Government --limit 15 -f .\groups.csv`

- Get top 15 most common TTPs used by threat actors targeting any sector in the US or government entities in any country `python .\openhunt.py -m ttp --target "United States" --target Government --limit 15 -f .\groups.csv` 

- Get top 15 most common TTPs used by threat actors targeting the United States and government organizations: `python .\openhunt.py -m ttp --target "United States" --target Government --logical-and --limit 15 -f .\groups.csv`
    - While this may not always be true, the assumption is that if a group targets the United States and Government entities, then they are targeting US Government entities

- Get top 15 most common TTPs used by threat actors targeting United States related government organizations, and print the group names: `python .\openhunt.py -m ttp -v --target "United States" --target Government --logical-and --limit 15 -f .\groups.csv`

- Create Sigma rule for an IOC: `python .\openhunt.py -m ioc -i 041e07fbab534fa6e7baaac93fae7f02e1621ed109b6304b147c9261b888b83d`

- Create Sigma rule for an IOC and rename a field: `python .\openhunt.py -m ioc --contacted-ips dest_ip -i 041e07fbab534fa6e7baaac93fae7f02e1621ed109b6304b147c9261b888b83d`

## Usage

### TTP Mode

#### TTPs by Origin

The main functionality of this was ported from [this MITRE ATT&CK script](https://github.com/mitre-attack/attack-scripts/blob/master/scripts/technique_mappings_to_csv.py). Provided a country with `--origin` it downloads the current MITRE STIX data to `groups.csv` and then parses it for all TTPs used by groups affiliated to the country provided and prints them out along with a count of how many threat groups are seen using that Technique. 

It is also possible to use `-f, --file` to designate a file to parse. It expects a CSV file exported from the MITRE ATT&CK script mentioned above. One is provided with the repo.

##### Countries Supported

The countries you can search for are the ones listed in the [MITRE Groups](https://attack.mitre.org/groups/) info

- Russia
- China
- Iran
- North Korea
- South Korea
- Nigeria
- Vietnam
- Lebanon
- Pakistan

###### Special Cases

- Unknown
- All

#### TTPs by Target

This works very similiarly to *TTPs by Origin*. However, instead of looking at the groups by country of origin/affiliation, it only pulls the TTPs for groups that target the country/sector provided with `--target`.

##### Targets Supported

Targets include the info of those indented below it. So `Asia` includes `China`, which in-turn includes `Hong Kong`. You can also query for indented children on their one (e.g. `--target "Hong Kong"`)

- Africa
    - Rwanda
    - Spain
- Australia
- Asia
    - Afghanistan
    - Cambodia
    - China
        - Hong Kong
    - India
    - Indonesia
    - Middle East
        - Iran
        - Isreal
        - Jordan
        - Kuwait
        - Pakistan
        - Saudi Arabia
        - Turkey
    - Japan
    - Laos
    - Mongolia
    - Myanmar
    - Nepal
    - North Korea
    - Philippines
    - Romania
    - Russia
    - Singapore
    - South Korea
    - Taiwan
    - Vietnam
- Europe
    - Belarus
    - Belgium
    - Spain
    - France
    - Germany
    - Poland
    - Sweden
    - United Kingdom
- South America
    - Argentina
    - Venezuela
- North America
    - Canada
    - United States
    - Caribbean
- Central America
- Latin America

- Aerospace
    - Aviation
- Automotive
- Critical Infrstructure
    - Energy
    - Electrical
    - Power
    - Petroleum
    - Nuclear
    - ICS
    - Telecommunications
- Government
    - Defense
    - Diplomatic
- Financial
    - Gambling
- Supply Chain
    - Manufactoring
    - Semiconductor
    - Maritime
- Healthcare
    - Pharmaceutical
- Technology
    - Biotechnology
    - Gaming
    - Eletronics
- Automotive
- Chemical
- Civil
- Construction
- Education
- Electronics
- Engineering
- Human Rights
- Humanitarian Aid
- Hospitality
    - Travel
- Legal
- Media
- Mining
- NGOs
- Non-profits
- Public Organizations
- Religious Organizations
- Research Organizations
- Restaurants
- Retail
- Satellite Communications
- Trade
- Transportation
- Weapons

- Individuals
    - Emirati Persons
    - Turkish Persons
    - English Speakers
    - Italian Speakers
    - Persian Speakers
    - Japanese Speakers
    - German Speakers
    - Infectious Disease Researchers
    - Journalists
    - Leaders in International Affairs
    - Minority Rights Activists
    - High Profile Persons
    - Experts in Various Un-Named Fields


- Organisation for the Prohibition of Chemical Weapons
- Presedential Elections of France
- Presedential Elections of the United States
- United States Anti-Doping Agency
- Syrian Opposition
- Think Tanks
- World Health Organization
- World Anti-Doping Agency
- United Nations

#### Combining Filters

Combining filters may not be intuitive at first.

For example, take the command `python .\openhunt.py -m ttp --target "United States" --target Russia --target Government -f .\groups.csv`. In plain English, this filter means "show me all groups that target any organization in the United States, any organization in Russia, and Government targets in any country". This is different from saying they target "United States and Russian Government" entities.

To search for techniques related to groups that target "United States and Russian Government" entities, add `--logical-and`: `python .\openhunt.py -m ttp --target "United States" --target Russia --target Government --logical-and  -f .\groups.csv`

## IOC Mode

Provided an IOC (MD5, SHA1, SHA256, IP, Domain) it pulls the IOCs relationships via the VirusTotal API and creates a SIGMA rule based on these.

For each IP address seen in the SIGMA rule (whether the IOC itself or a relationship), it looks it up in Shodan and compares it to a number of fingerprints and prints to screen if something is found.

Fingerprints Supported:
- Cobalt Strike Servers (Default Values)

If the field names in the Sigma rule do not match the field names in your SIEM/EDR platform then you can rename them (see `python openhunt.py -h`).

#### Requirements

- VirusTotal API Key
- Shodan API Key

#### Limitations

- Max of 10 values per relationship
- For domains and IPs, the `downloaded_files` relationship is not implemented because it requires a Premium API key

## Is the MITRE information up-to-date?

This script was built using MITRE v11. MITRE v12 came out in the midst of development which replaced some groups with campaigns.

Working on updating the script to support MITRE v12. The `groups.csv` with this repo was downloaded using v11. It is recommended to use it as downloading v12 may cause unintended bugs. 

Last Update: October 2022 (prior to v12)

Checksum: 79FCC4E1689077298F221F550A41550492A7866BDD1DCFCAF027779E62788134

To update the MITRE TTP info from MITRE at execution, just omit `-f, --file` (not recommended until the script supports v12). This updates the techniques mapped to groups on MITREs side and writes it to `groups.csv`. If MITRE adds a new group or modifies their description on [here](https://attack.mitre.org/groups/), that will not be reflected in the script until the script is updated.

An easy way to see if the the MITRE Groups information is up-to-date is by hashing the MITRE groups page.

`Invoke-WebRequest -UseBasicParsing https://attack.mitre.org/groups/ -OutFile tmp.html; Get-FileHash tmp.html; Remove-Item tmp.html`

It should match the checksum above.

As MITRE releases more information, I plan on keeping the script and `groups.csv` current; I will update the date and checksum above each time MITRE info changes.

## Credit and Thank You Notes

- [MITRE](https://attack.mitre.org/) for their research and [ATT&CK scripts](https://github.com/mitre-attack/attack-scripts/)
- [Bank Security on Medium](https://bank-security.medium.com/hunting-cobalt-strike-servers-385c5bedda7b) for their work on Cobalt Strike fingerprints

## Planned Fixes and Enhancements

- Update to support MITRE v12
- Add more fingerprints for Shodan to check against