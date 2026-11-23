SNAKE THREAT ANALYSIS

A defensive and educational project that studies the publicly documented architecture, covert communications and detection opportunities for the SNAKE (Uroburos) cyber espionage implant, attributed by US agencies to Russia's FSB Center 16 (Turla).

This repository contains no malware and no offensive code. It is built for SOC analysts, threat hunters and students.


OVERVIEW

- Plain-language threat analysis report in PDF form
- Low-confidence YARA hunting rules for triage sweeps
- Suricata hunting rules and Zeek log-hunting commands
- Analysis notes covering architecture, host artifacts, network hunting methodology and MITRE ATT&CK mapping


PROJECT STRUCTURE

SNAKE
- README.txt
- SNAKE_Threat_Analysis_Report.pdf
- yara_rules
  - snake_hunting.yar
- network_signatures
  - snake_suricata_hunting.rules
  - zeek_hunting_commands.txt
- analysis_notes
  - architecture_notes.txt
  - host_artifact_checklist.txt
  - network_hunting_methodology.txt
  - mitre_attack_mapping.txt


GETTING STARTED

Requirements: Python 3.7 or newer. Works on Windows, macOS and Linux.

Build the project files with the generator script:

  pip install fpdf2
  python build_snake_project.py

On Windows you can also use: py build_snake_project.py

The script creates the SNAKE folder next to itself and writes the report, README and all detection content.


HOW TO USE THE DETECTION CONTENT

1. Read the report first.
2. Validate every indicator against CISA advisory AA23-129A before deploying anything.
3. Run the YARA rules against triage images or memory dumps, not the whole estate on a first pass.
4. Load the Suricata rules in alert-only mode and measure noise for at least a week.
5. Use the Zeek commands on historical logs to look for relay behavior between internal hosts. These use Unix tools, so run them on Linux, macOS, WSL or Git Bash.


CONFIDENCE AND LIMITATIONS

All detection content is labelled with a confidence level. Content marked LOW is a hunting lead and will produce false positives. The implant was disrupted by the FBI in 2023 (Operation MEDUSA), so older indicators may no longer be active. This project is not a substitute for validated threat intelligence feeds.


MITRE ATT&CK COVERAGE

- T1543.003 Windows Service persistence
- T1055 Process Injection
- T1027 Obfuscated Files or Information
- T1573 Encrypted Channel
- T1090 Proxy (peer-to-peer relay)
- T1071.001 Web Protocols
- T1560 Archive Collected Data


REFERENCES

- CISA Joint Advisory AA23-129A: Hunting Russian Intelligence Snake Malware
- US Department of Justice announcement on Operation MEDUSA, May 2023
- MITRE ATT&CK group page for Turla


LEGAL AND ETHICAL USE

For defensive research, education and authorized security monitoring only. Only analyze systems and networks you own or are authorized to assess.


AUTHOR

Rushikesh Kulkarni
Aspiring SOC Analyst
InfoSecLabs SOC Academy: 395+ labs and CTF modules completed


LICENSE

MIT License
