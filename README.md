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
    - e.g. this returns the techniques of any group affiliated with Russia, China, or the Middle East if they have been documented targeting *either* any organization in the US *or* the Aviation industry industry in any country. For more information read *Combining Filters* below.



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

This works very similiarly to `TTPs by Country`. However, instead of looking at the groups by country of origin/affiliation, it only pulls the TTPs for groups that target the country/sector provided with `--filter`.

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

`python .\openhunt.py -m ttp --filter energy -f .\groups.csv`
- Pulls top 10 techniques seen used by groups targeting the energy sector

`python .\openhunt.py -m ttp --filter asia -f .\groups.csv`
- Pulls top 10 techniques seen used by groups targeting companies/organizations in Asia

`python .\openhunt.py -m ttp --filter "United States" --filter Russia --filter Government -f .\groups.csv`
- Pulls top 10 techniques seen used by groups targeting United States-based, Russia-based, and Government related targets

#### Combining Filters

Combining filters may not be intuitive at first.

For example, take the command above `python .\openhunt.py -m ttp --target "United States" --target Russia --target Government -f .\groups.csv`. In plain English, this filter means "show me all groups that target any organization in the United States, any organization in Russia, and Government targets in any country". This is different from saying they target "United States and Russian Government" entities.

I plan on implementing a way to strictly combine filters later so you can ask it to show only groups that target specific sectors of specific countries.

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

## Is this information up-to-date?

Last Update: October 2022
Checksum: 79FCC4E1689077298F221F550A41550492A7866BDD1DCFCAF027779E62788134

To update the MITRE TTP info from MITRE at execution, just omit `-f, --filter`. This updates the techniques mapped to groups on MITREs side and writes it to `groups.csv`. If MITRE adds a new group or modifies their description on [here](https://attack.mitre.org/groups/), that will not be reflected in the script until the script is updated.

An easy way to see if the the MITRE Groups information is up-to-date is by hashing the MITRE groups page.

`Invoke-WebRequest -UseBasicParsing https://attack.mitre.org/groups/ -OutFile tmp.html; Get-FileHash tmp.html; Remove-Item tmp.html`

It should have match the checksum above.

As MITRE releases more information, I plan on keeping the script current and will update the date and checksum above.

## Credit and Thank You Notes

- [MITRE](https://github.com/mitre-attack/attack-scripts/) for their research and ATT&CK scripts 
- [Bank Security on Medium](https://bank-security.medium.com/hunting-cobalt-strike-servers-385c5bedda7b) for their work on Cobalt Strike fingerprints