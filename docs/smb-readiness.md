# Could it happen to us? Ransomware readiness for a small business

The attacks on M&S and Co-op in 2025 did not need clever hacking. Someone phoned an IT help desk,
pretended to be a member of staff and was given a new password. From there they looked around,
stole more passwords, deleted the backups and encrypted the systems. None of those steps needs a
big target: the NCSC is clear that no organisation is exempt, and a small firm has fewer people to
notice.

This page is for an owner, an office manager or whoever looks after IT, with or without an IT
provider. It follows the same six steps DwellWatch detects ([the threat model](threat-model.md)) and
maps each one to the government-backed baseline for small organisations,
[Cyber Essentials](https://www.ncsc.gov.uk/cyberessentials/overview), and to the few things
Cyber Essentials does not cover but this attack needs.

## Ten questions to answer this week

| # | Question | If the answer is no | Stops step |
|---|---|---|---|
| 1 | If someone rang pretending to be a colleague, would we (or our IT provider) call them back on a number we already hold before resetting anything? | Adopt the [help-desk checklist](helpdesk-checklist.md), and ask your IT provider to confirm they follow it | 1 |
| 2 | Does everyone use multi-factor authentication (a code or app prompt) for email and every cloud service? | Turn it on everywhere it is offered; Cyber Essentials requires it | 1, 4 |
| 3 | Do people who administer IT have a separate admin account, used only for admin work? | Create one; take admin rights off everyday accounts | 1, 3, 4 |
| 4 | Is remote desktop (RDP) closed to the internet, with remote access only through a VPN or a managed tool? | Close it at the firewall or router | 2, 4 |
| 5 | Are critical and high-risk security updates installed within 14 days, on computers, servers, phones, routers and firewalls? | Turn on automatic updates; ask your provider for a monthly report | 2, 3 |
| 6 | Is only approved software allowed to run, including remote access tools such as AnyDesk or TeamViewer? | Decide which remote access tool you use and block the rest | 2 |
| 7 | Is at least one copy of your backups offline or unchangeable, and have you restored from it in the last year? | Add an offline or immutable copy and test a restore | 5 |
| 8 | Would you find out if someone's password was reset, or a new administrator added, when you did not expect it? | Turn on alerts for both in Microsoft 365 or Google Workspace, sent to two people | 1, 3 |
| 9 | Are old accounts of people who have left switched off? | Remove them; check monthly | 1, 4 |
| 10 | Are the phone numbers of your IT provider, insurer, bank and key staff written down somewhere other than your computers? | Print them; an attacker may be reading your email | all |

## The five Cyber Essentials controls, against this attack

**1. Firewalls.** Every internet connection sits behind a firewall with the default password changed,
and only the services you mean to offer are open. *Against this attack:* remote desktop left open to
the internet is a common front door. *Check:* ask your provider which ports are open to the internet,
and why.

**2. Secure configuration.** Remove software and accounts you do not use, change default passwords,
and turn on multi-factor authentication for cloud services wherever it is offered. *Against this
attack:* a reset password is worth much less when the attacker still needs the person's phone.
*Check:* in your email and file-sharing admin page, is multi-factor on for every account?

**3. Security update management.** Supported software only, with critical and high-risk updates
installed within 14 days. *Against this attack:* remote access tools and servers with known holes
are the easy way in and the easy way around. *Check:* are any computers on an unsupported version
of Windows?

**4. User access control.** Everyone has their own account, with only the access their job needs;
administrator accounts are separate and used only for administration. *Against this attack:* this is
the control the help-desk trick goes after. The attacker wants an account with power, and every
account without it is a dead end. *Check:* who has administrator rights today, and does each of them
need it?

**5. Malware protection.** Anti-malware kept up to date, or only approved applications allowed to
run. *Against this attack:* blocking unapproved remote access tools and credential-stealing tools
takes away the attacker's next steps. *Check:* is Microsoft Defender (or your provider's tool) on,
updated and reporting on every computer?

Certification is a self-assessment (Cyber Essentials) or an independent audit (Cyber Essentials
Plus). It is a baseline, not a guarantee: it would have made each step of the retail attacks harder,
but it does not cover the three things below.

## What Cyber Essentials does not cover, and this attack needs

- **The help desk.** Whoever resets passwords, in-house or at your IT provider, needs a way to
  verify the caller that cannot be defeated by knowing names and dates of birth. The
  [help-desk checklist](helpdesk-checklist.md) is one page; ask your provider to sign up to it.
- **Backups the attacker cannot delete.** Ransomware crews delete backups before they encrypt; it is
  step 5 of the chain, and DwellWatch has six rules for it. Keep one copy offline or immutable,
  and test a restore at least once a year.
- **Someone noticing.** Every step leaves a trace in Windows and in your cloud admin logs. If you
  have an IT provider with a security monitoring service, DwellWatch's rules (for Wazuh, Splunk or
  Microsoft Sentinel, in [`converted/`](../converted)) catch these steps, and its correlation turns
  them into one alert. If you do not, the alerts in question 8 are the minimum.

## If it happens

Disconnect affected computers from the network but leave them switched on, call your IT provider and
your insurer from a phone, not a work computer, and report it to the NCSC. Do not use email or chat
to coordinate: assume the attacker can read them. The NCSC's
[small business guide](https://www.ncsc.gov.uk/collection/small-business-guide) covers backups,
passwords and phishing in more detail.
