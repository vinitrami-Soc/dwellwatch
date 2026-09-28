"""Stage 1 (help-desk reset abuse): one account resetting another's password, and an account being
put into a group that controls the domain or its hosts.

The planted events pin down each rule's edges. The attack_data tests replay real Security logs
from Splunk's Attack Range: every reset in them must fire once, every add to a privileged group
must fire, and an add to a group that grants nothing must not.
"""

from collections import Counter

import pytest

from dwellwatch.models import Severity, Stage
from dwellwatch.replay import load_events, load_rule, load_rules, replay

from conftest import ROOT, dataset, security_event

STAGE1 = ROOT / "sigma" / "stage1_helpdesk"
RESET = load_rule(STAGE1 / "password_reset_by_another_account.yml")
GROUP = load_rule(STAGE1 / "privileged_group_member_added.yml")
DOMAIN = "S-1-5-21-3623811015-3361044348-30300820"


def fires(rule, event):
    return len(replay([event], [rule])) == 1


def account_event(event_id, *, target="jdoe", subject="helpdesk1"):
    return security_event(event_id, TargetUserName=target, TargetDomainName="LAB", TargetSid=f"{DOMAIN}-1105",
                          SubjectUserName=subject, SubjectDomainName="LAB")


def group_add(group, sid, event_id=4728, *, subject="helpdesk1"):
    return security_event(event_id, TargetUserName=group, TargetDomainName="LAB", TargetSid=sid,
                          MemberName="CN=jdoe,CN=Users,DC=lab,DC=local", MemberSid=f"{DOMAIN}-1105",
                          SubjectUserName=subject, SubjectDomainName="LAB")


# --- password reset ---------------------------------------------------------------------------


def test_a_reset_names_the_account_that_was_reset():
    [signal] = replay([account_event(4724)], [RESET])
    assert signal.stage is Stage.HELPDESK_RESET
    assert signal.attack_technique == "T1098"
    assert signal.severity is Severity.MEDIUM
    # The caller now holds jdoe's password, so jdoe is the account to follow, not the help desk.
    assert (signal.host, signal.user) == ("DC01.lab.local", "LAB\\jdoe")


@pytest.mark.parametrize("event_id", [
    4723,  # a user changing their own password: they already knew the old one
    4738,  # "user account changed", logged alongside every reset; counting it would double each reset
    4720,  # account created
    4722,  # account enabled
])
def test_the_reset_rule_stays_quiet_on_other_account_events(event_id):
    assert not fires(RESET, account_event(event_id, subject="jdoe" if event_id == 4723 else "helpdesk1"))


# --- privileged group -------------------------------------------------------------------------


@pytest.mark.parametrize("event", [
    group_add("Domain Admins", f"{DOMAIN}-512"),
    group_add("Enterprise Admins", f"{DOMAIN}-519", 4756),
    group_add("Schema Admins", f"{DOMAIN}-518", 4756),
    group_add("Administrators", "S-1-5-32-544", 4732),
    group_add("Backup Operators", "S-1-5-32-551", 4732),
    group_add("DnsAdmins", f"{DOMAIN}-1101", 4732),  # no well-known SID: matched by name
    group_add("Admins du domaine", f"{DOMAIN}-512"),  # a localised name: matched by SID
    group_add("Domain Admins", "ATTACKRANGE\\Domain Admins"),  # the SID rendered as a name, as in attack_data
], ids=lambda event: f"{event['EventID']}-{event['TargetUserName']}")
def test_the_group_rule_fires_on_privileged_groups(event):
    assert fires(GROUP, event)


@pytest.mark.parametrize("event", [
    group_add("Remote Desktop Users", "S-1-5-32-555", 4732),
    group_add("Users", "S-1-5-32-545", 4732),
    group_add("None", "AR-WIN-2\\None"),  # a workstation's default group, in attack_data
    group_add("Helpdesk-Tier1", f"{DOMAIN}-1512"),  # its RID ends in 512 but is not 512
    group_add("Domain Admins", f"{DOMAIN}-512", 4729),  # a member removed, not added
    group_add("Domain Admins", f"{DOMAIN}-512", 4737),  # the group itself changed
], ids=lambda event: f"{event['EventID']}-{event['TargetUserName']}")
def test_the_group_rule_stays_quiet_on_other_groups_and_changes(event):
    assert not fires(GROUP, event)


def test_a_group_add_names_the_account_that_made_it():
    # The target of a group event is the group; the account to follow is the one using its rights.
    [signal] = replay([group_add("Domain Admins", f"{DOMAIN}-512")], [GROUP])
    assert signal.user == "LAB\\helpdesk1"
    assert signal.severity is Severity.HIGH


# --- real replayed data (datasets/fetch.sh) --------------------------------------------------


def signals_by_rule(relative):
    events = list(load_events(dataset(relative)))
    return events, replay(events, load_rules())


def test_every_reset_in_a_bulk_reset_run_fires_once():
    events, signals = signals_by_rule(
        "T1098/windows_multiple_passwords_changed/windows_multiple_passwords_changed.log")
    ids = Counter(event.get("EventID") for event in events)
    assert len(events) == 345
    assert (ids["4724"], ids["4738"]) == (40, 40)  # one 4738 per reset, which is why 4738 has no rule
    assert Counter(s.rule_id for s in signals) == {RESET.id: 40}
    assert len({s.user for s in signals}) == 40  # each signal names a different reset account
    assert {s.host for s in signals} == {"ar-win-dc.attackrange.local"}


def test_account_manipulation_run_fires_on_resets_and_domain_admin_adds():
    events, signals = signals_by_rule("T1098/account_manipulation/xml-windows-security.log")
    group_adds = [event for event in events if event.get("EventID") == "4728"]
    assert len(events) == 430
    # Four adds: three to Domain Admins (one of them an account adding itself) and one to a
    # workstation's "None" group, which grants nothing and must stay quiet.
    assert sorted(event["TargetUserName"] for event in group_adds) == ["Domain Admins"] * 3 + ["None"]
    assert Counter(s.rule_id for s in signals) == {RESET.id: 21, GROUP.id: 3}
    assert {s.user for s in signals if s.rule_id == GROUP.id} == {"ATTACKRANGE\\Administrator",
                                                                   "ATTACKRANGE\\unpriv2"}


@pytest.mark.parametrize("relative, host", [
    ("T1098/dnsadmins_member_added/windows-security.log", "ar-win-dc.attackrange.local"),
    ("T1136.001/atomic_red_team/xml-windows-security.log", "ar-win-2.attackrange.local"),
])
def test_dnsadmins_and_local_administrators_adds_fire(relative, host):
    _, signals = signals_by_rule(relative)
    assert [(s.rule_id, s.host, s.user) for s in signals] == [(GROUP.id, host, "ATTACKRANGE\\Administrator")]
