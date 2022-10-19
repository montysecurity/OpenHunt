# OpenHunt

OpenHunt is designed to give SOC analysts/threat hunters information that allows them to make more informed hunts. It runs in 2 modes (designated by `-m, --mode`): `ttp` and `ioc`.

TTP mode is used to parse MITRE info for common techniques threat actors use given a country of origin/affiliation (`--origin`) or a region/business sector they have targeted (`--target`).

IOC mode is designed to give you related artifacts to a given IOC using the VirusTotal/Shodan APIs. It focuses on arifacts that can be found in most SIEM/EDR tech stacks such has file hash, name, remote IP, and domain (and a few more).

## Install

`pip install -r requirements.txt`

## Cheat Sheet

- Get top 10 most common TTPs used out of all MITRE Groups: `python .\openhunt.py -m ttp --origin all -f .\groups.csv`

- Get top 10 most common TTPs used by threat actors affiliated with Russia: `python .\openhunt.py -m ttp --origin Russia -f .\groups.csv`

- Get top 15 most common TTPs used by threat actors targeting government organizations: `python .\openhunt.py -m ttp --target Government --limit 15 -f .\groups.csv`

- Get top 10 most common TTPs used by any group from any `--origin` targeting any sector in `--target`: `python .\openhunt.py -m ttp --origin Russia --origin China --origin "Middle East" --target Aviation --target "United States" -f .\groups.csv`
    - e.g. this returns the techniques of any group affiliated with Russia, China, or the Middle East if they have been documented targeting *either* any organization in the US *or* the Aviation industry in any country. For more information read *Combining Filters* below.

- Create Sigma rule for an IOC: `python .\openhunt.py -m ioc -vt {VirusTotal API Key} -s {Shodan API Key} -i 041e07fbab534fa6e7baaac93fae7f02e1621ed109b6304b147c9261b888b83d`

- Create Sigma rule for an IOC and rename a field: `python .\openhunt.py -m ioc --contacted-ips dest_ip -vt {VirusTotal API Key} -s {Shodan API Key} -i 041e07fbab534fa6e7baaac93fae7f02e1621ed109b6304b147c9261b888b83d`

## Usage

### TTP Mode

#### TTPs by Origin

The main functionality of this was ported from [this MITRE ATT&CK script](https://github.com/mitre-attack/attack-scripts/blob/master/scripts/technique_mappings_to_csv.py). Provided a country with `--origin` it downloads the current MITRE STIX data to `groups.csv` and then parses it for all TTPs used by groups affiliated to the country provided and prints them out along with a count of how many threat groups are seen using that Technique. 

It is also possible to use `-f, --file` to designate a file to parse. It expects a CSV file exported from the MITRE ATT&CK script mentioned above.

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

- Countries, Continents, and Regions
    - Afghanistan
    - Africa
    - Argentina
    - Australia
    - Asia
    - Belarus
    - Belgium
    - Cambodia
    - Canada
    - Caribbean
    - Central America
    - China
    - Columbia
    - Europe
    - France
    - Germany
    - Hong Kong
    - India
    - Indonesia
    - Iran
    - Isreal
    - Japan
    - Jordan
    - Kuwait
    - Latin America
    - Laos
    - Mongolia
    - Middle East
    - Myanmar
    - Nepal
    - North America
    - North Korea
    - Pakistan
    - Philippines
    - Poland
    - Romania
    - Russia
    - Rwanda
    - Saudia Arabia
    - Singapore
    - Spain
    - South America
    - South Korea
    - Sweden
    - Taiwan
    - Turkey
    - Ukraine
    - United Kingdom
    - United Nations
    - United States
    - Venezuela
    - Vietnam

- Sectors
    - Aerospace
    - Automotive
    - Aviation
    - Biotechnology
    - Chemical
    - Civil
    - Construction
    - Critical Infrstructure
    - Defense
    - Diplomatic
    - Education
    - Electrical
    - Electronics
    - Energy
    - Engineering
    - Financial
    - Gambling
    - Government
    - Healthcare
    - Human Rights
    - Humanitarian Aid
    - Hospitality
    - Gaming
    - Legal
    - Manufacturing
    - Maritime
    - Media
    - Mining
    - NGOs
    - Non-Profits
    - Nuclear
    - Power
    - Public
    - Petroleum
    - Pharmaceutical
    - Religious Organizations
    - Research
    - Restaurant
    - Retail
    - Satellite Communications
    - Semiconductor
    - Supply Chain
    - Technology
    - Telecommunications
    - Trade
    - Transportation
    - Travel
    - ICS
    - Infrastructure
    - Weapons

- Miscellaneous
    - Emirati Persons
    - English Speakers
    - Experts in Various Un-Named Fields
    - German Speakers
    - High Profile Persons
    - Individuals
    - Italian Speakers
    - Infectious Disease Researchers
    - Japanese Speakers
    - Journalists
    - Leaders in International Affairs
    - Minority Rights Activists
    - Organisation for the Prohibition of Chemical Weapons
    - Persian-speaking Indivduals
    - Presedential Elections of France
    - Presedential Elections of the United States
    - United States Anti-Doping Agency
    - Syrian Opposition
    - Think Tanks
    - Turkish Individuals
    - World Health Organization
    - World Anti-Doping Agency

#### Combining Filters

Combining filters may not be intuitive at first.

For example, take the command `python .\openhunt.py -m ttp --target "United States" --target Russia --target Government -f .\groups.csv`. In plain English, this filter means "show me all groups that target any organization in the United States, any organization in Russia, and Government targets in any country". This is different from saying they target "United States and Russian Government" entities.

I plan on implementing a way to strictly combine filters later so you can ask it to show only groups that target specific sectors of specific countries.

## IOC Mode

Provided an IOC (MD5, SHA1, SHA256, IP, Domain) it pulls the IOCs relationships via the VirusTotal API and creates a SIGMA rule based on these.

For each IP address seen in the SIGMA rule (whether the IOC itself or a relationship), it looks it up in Shodan and compares it to a number of fingerprints and prints to screen if something is found

Fingerprints Supported:
- Cobalt Strike Servers (Default Values)

If the field names in the Sigma rule do not match the field names in your SIEM/EDR platform then you can rename them (see `python openhunt.py -h`)

#### Requirements

- VirusTotal API Key
- Shodan API Key

#### Examples

`python .\openhunt.py -m ioc -vt {VirusTotal API Key} -s {Shodan API Key} -i 58.33.204.180`

#### Limitations

- Max of 10 values per relationship
- For domains and IPs, the `downloaded_files` relationship is not implemented because it requires a Premium API key

## Is the MITRE information up-to-date?

Last Update: October 2022

Checksum: 79FCC4E1689077298F221F550A41550492A7866BDD1DCFCAF027779E62788134

To update the MITRE TTP info from MITRE at execution, just omit `-f, --filter`. This updates the techniques mapped to groups on MITREs side and writes it to `groups.csv`. If MITRE adds a new group or modifies their description on [here](https://attack.mitre.org/groups/), that will not be reflected in the script until the script is updated.

An easy way to see if the the MITRE Groups information is up-to-date is by hashing the MITRE groups page.

`Invoke-WebRequest -UseBasicParsing https://attack.mitre.org/groups/ -OutFile tmp.html; Get-FileHash tmp.html; Remove-Item tmp.html`

It should have match the checksum above.

As MITRE releases more information, I plan on keeping the script current and will update the date and checksum above.

## Credit and Thank You Notes

- [MITRE](https://attack.mitre.org/) for their research and [ATT&CK scripts](https://github.com/mitre-attack/attack-scripts/)
- [Bank Security on Medium](https://bank-security.medium.com/hunting-cobalt-strike-servers-385c5bedda7b) for their work on Cobalt Strike fingerprints

## Planned Fixes and Enhancements

- Group targets (e.g. all groups seen targeting Pakistan will be added to the list of groups targeting the Middle East) (for business sectors too)
- Add a way to strictly combine filters (group targeted X sector in Y region)