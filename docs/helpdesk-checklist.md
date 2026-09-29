# Service desk: verifying who is asking

**For every request to reset a password, reset or re-enrol MFA, change a phone number or email on an
account, or add someone to a group.** By phone, chat, email or in person; staff or contractor.

In 2025 attackers got into M&S and Co-op by phoning the IT help desk as an employee and asking for a
password reset. They knew names, employee IDs and the answers to security questions: all of it can be
researched or bought. This page is the check that stops that call. Print it; keep it by the phone.

## Every request

- [ ] **Call back, never continue.** End the call and ring the person on the number held in the HR
  directory. Never on a number the caller gives, and never trust caller ID or a chat display name.
- [ ] **Verify with something that cannot be looked up.** Not name, date of birth, employee ID,
  manager's name or security questions. Instead: approve a prompt on the device they have already
  enrolled, or a video call with photo ID matched to HR's record.
- [ ] **Two independent checks, at least one that a voice cannot fake.** A callback plus a video ID
  check, or a callback plus a prompt on the enrolled device.
- [ ] **Reset one thing per request.** Password *and* MFA in one call is a red flag; so is "I have a
  new phone".

## Privileged accounts: administrators, IT staff, executives, finance

- [ ] **No reset of a password or MFA without a second approver:** a named person in IT security or
  the account owner's line manager, who is neither the caller nor you. Record their name on the ticket.
- [ ] **MFA re-enrolment in person or on video, with photo ID.** Never over a voice call alone.

## Group and access changes

- [ ] **Manager confirmation by callback** for any addition to a group. The manager is called on the
  directory number, not put through by the requester.
- [ ] **Security team approval** for Domain Admins, Enterprise Admins, cloud admin roles, backup
  operators and remote access groups.

## Red flags: stop and escalate

- Urgency or seniority: "I'm the director, I'm locked out before a board meeting."
- Travelling, new phone, lost phone, cannot take a callback.
- The caller knows internal jargon and names, and still will not verify.
- A request to install remote access software, read out a code, or turn MFA off "for now".

Pressure is the attack. Saying "I'll call you back on your directory number" is always allowed.

## After any reset

- [ ] **Tell the person through a second channel:** an email to them and their manager saying a reset
  was made, with the security team's number to call if it was not them.
- [ ] **Log it:** who asked, how they were verified, who approved, and the time. Security reviews
  every privileged reset the same day. (Windows records each reset as event 4724;
  [DwellWatch](../README.md) links it to whatever that account does next.)

## Never

- Install remote access software, or read out a one-time code, because a caller asked.
- Disable MFA, even temporarily.
- Reset a privileged account on your own authority.

## If you think it was an attack

Do not tip the caller off. Note the time, the number and what was asked. Report it to security on
the incident number, not by email or chat, which an attacker in the network may be reading, and name
the account so its resets and sign-ins can be checked.

## Outsourced service desks

The contract should require every step on this page, the provider should not be able to reset a
privileged account without your approver at all, and you should audit a sample of its resets every
month. At M&S the way in was through a third party.

---

<sub>DwellWatch's checklist, built from how the attacks worked and what the authorities advised:
[CISA advisory AA23-320A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-320a)
(Scattered Spider, updated July 2025) on impersonating employees to help desks for password and MFA
resets, [the NCSC's advice after the retail incidents](https://www.ncsc.gov.uk/blog-post/incidents-impacting-retailers)
("review helpdesk password reset processes … especially those with escalated privileges"), and
[M&S's evidence to Parliament](https://committees.parliament.uk/oralevidence/16268/html/). The
attack chain is in the [threat model](threat-model.md).</sub>
