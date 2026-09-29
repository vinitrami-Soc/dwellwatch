# Threat model

DwellWatch is built around one attack chain: a help-desk-led ransomware intrusion, as run against
UK retailers in 2025. This page says what that chain is, where it comes from, how DwellWatch
watches each stage, and what it does not cover.

## Why this chain

- **Marks & Spencer.** Its chairman told the Business and Trade Sub-Committee on 8 July 2025 that
  the attackers got in on 17 April through social engineering: they impersonated someone, through
  a third party. M&S expected the attack to cost it about £300m in profit. The attack is attributed
  to the Scattered Spider collective and DragonForce ransomware.
  ([Oral evidence, HC 835](https://committees.parliament.uk/oralevidence/16268/html/))
- **Co-op.** The same weeks, and the same method as reported: attackers posing as employees talked
  the IT help desk into resetting passwords, then took personal data on a significant number of
  current and past members.
  ([report](https://www.claimsjournal.com/news/national/2025/05/06/330435.htm))
- **The NCSC's advice afterwards** was to "review helpdesk password reset processes, including how
  the helpdesk authenticates staff members credentials before resetting passwords, especially those
  with escalated privileges".
  ([Incidents impacting retailers](https://www.ncsc.gov.uk/blog-post/incidents-impacting-retailers))
- **Not only retailers.** The NCSC's 2025 Annual Review reports a record 204 nationally
  significant incidents, up from 89 the year before, with ransomware the most disruptive threat.
  Schools, NHS suppliers and small firms face the same chain.
  ([NCSC Annual Review 2025](https://www.ncsc.gov.uk/files/ncsc-annual-review-2025.pdf))

## Who runs it

The primary source is the joint advisory on Scattered Spider,
[CISA AA23-320A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-320a), published in
November 2023 and updated on 29 July 2025. It describes a group that targets large companies and
their contracted IT help desks, and in its update:

- impersonates employees to get help desks to reset passwords and transfer or reset MFA, and poses
  as IT staff to get employees to hand over codes or install remote access software;
- uses legitimate remote access tools, then steals credentials and data for extortion;
- most recently deploys DragonForce ransomware, including against VMware ESXi servers;
- is best countered, the advisory says, by phishing-resistant MFA (FIDO or PKI), application
  controls that limit which remote access software can run, strict limits on remote desktop, and
  offline backups whose restore is tested.

## The six stages

Stages 1 to 5 happen during dwell time; stage 6 is the backstop. The rules for each stage, and
what each misses, are in the [detection catalogue](detection-catalogue.md).

| # | Stage | ATT&CK | What DwellWatch watches | Main blind spot |
|---|---|---|---|---|
| 1 | Help-desk reset abuse: an impersonated employee gets a password or MFA reset | T1656, T1078, T1098, T1556 | Security 4724 (a password reset by another account), adds to privileged groups | The phone call itself, and MFA resets, which live in the identity provider (Entra ID, Okta), not in Windows logs. The [help-desk checklist](helpdesk-checklist.md) is the control |
| 2 | Remote tooling and discovery | T1219, T1087, T1482 | Remote access tools starting, domain trust and account discovery, AdFind and SharpHound | Discovery through tools that look like administration, and remote access tools not on the list |
| 3 | Credential theft | T1003.001, T1003.003, T1003.006 | LSASS read or dumped, NTDS.dit and registry hives copied, DCSync by an account that is not a domain controller | Dumps done in memory by tooling that never touches disk or the command line |
| 4 | Lateral movement | T1021, T1021.001, T1021.002, T1047, T1550.002 | PsExec and Impacket, remote WMI, RDP, pass-the-hash, an account reaching two hosts from a new source | WinRM and PowerShell remoting, remote services and tasks, DCOM |
| 5 | Backup destruction | T1490 | vssadmin, wbadmin, bcdedit, wmic, PowerShell and encoded PowerShell deleting shadow copies and recovery | Backups deleted from the backup console or the cloud, not from Windows |
| 6 | Encryption (backstop) | T1486 | Ransom notes, the same note written into many folders, canary files, disk encryption tools | Encryption of ESXi hosts and storage appliances, which DwellWatch does not see |

The alert that matters is the combination: [correlation](../README.md#when-a-signal-becomes-an-incident)
raises an incident when two stages appear on one host or account within 24 hours.

## Out of scope

- **The phone call and the email.** Social engineering happens between people. The
  [help-desk checklist](helpdesk-checklist.md) addresses the call; phishing email is
  [PhishHawk](https://github.com/vinitrami-Soc/phishhawk)'s job.
- **Identity providers and SaaS.** MFA resets, new MFA devices and sign-ins from unusual places
  are in Entra ID, Okta or Google logs. The NCSC's advice to watch "risky logins" applies there.
- **Hypervisors.** DragonForce encrypts ESXi. DwellWatch watches Windows hosts only.
- **Exfiltration.** The data theft that comes before encryption, often to cloud storage, is not
  detected here.
- **Building attack tooling.** DwellWatch emulates with Atomic Red Team and replays published
  recordings; it contains no encryptor, keylogger or command and control.

The [small-business readiness page](smb-readiness.md) turns this chain into the controls a firm
without a security team can put in place.
