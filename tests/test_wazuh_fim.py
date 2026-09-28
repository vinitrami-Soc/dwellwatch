"""The hand-written Wazuh FIM rules for stage 6 (wazuh/), checked against Wazuh 4.14.8's source.

No Wazuh manager runs in CI, so these pin what can be checked offline: the rule IDs, the parents,
the FIM field names Wazuh's decoder gives rules, the patterns (compiled with PCRE2, as Wazuh's
type="pcre2" does), and that the agent config tags what the rules read. How the frequency rule
counts is taken from Wazuh's source and stated in the rule file; it is to be confirmed on the
lab's manager.
"""

import re
import xml.etree.ElementTree as ET

import pcre2
import pytest
import yaml

from conftest import ROOT

RULES = ET.parse(ROOT / "wazuh" / "dwellwatch_fim_rules.xml").getroot()
AGENT = ET.parse(ROOT / "wazuh" / "agent_syscheck.xml").getroot()
BY_ID = {int(rule.get("id")): rule for rule in RULES.iter("rule")}
BASE, BURST, CANARY = 106900, 106910, 106920

# Wazuh's built-in FIM rules for files (ruleset/rules/0015-ossec_rules.xml): 550 checksum changed,
# 553 deleted, 554 added. The one other built-in rule under them is 99901, level 14 (known-malware hash).
FIM_FILE_RULES = {550, 553, 554}
# Some of the names src/analysisd/decoders/syscheck.c gives FIM values in rules (4.14.8).
FIM_FIELDS = {"file", "tag", "process_id", "process_name", "user_name", "sha256", "size", "uname", "mtime"}


def pattern(rule, field):
    [element] = [f for f in rule.findall("field") if f.get("name") == field]
    assert element.get("type") == "pcre2"
    return pcre2.compile(element.text)


def test_the_ids_are_in_the_block_reserved_for_them_and_nothing_else_uses_them():
    assert sorted(BY_ID) == [BASE, BURST, CANARY]
    blocks = yaml.safe_load((ROOT / "sigma" / "wazuh-ids.yml").read_text(encoding="utf-8")).values()
    assert not any(start <= rule_id < start + 10 for start in blocks for rule_id in BY_ID)
    generated = {int(r.get("id")) for path in (ROOT / "converted" / "wazuh").glob("*.xml")
                 for r in ET.parse(path).getroot().iter("rule")}
    assert not generated & set(BY_ID)


def test_the_rules_hang_off_wazuhs_fim_rules_and_the_burst_counts_the_base():
    for rule_id in (BASE, CANARY):
        assert {int(s) for s in BY_ID[rule_id].findtext("if_sid").split(",")} == FIM_FILE_RULES
    assert int(BY_ID[BURST].findtext("if_matched_sid")) == BASE


def test_only_field_names_the_fim_decoder_provides_are_used():
    used = {f.get("name") for f in RULES.iter("field")} | {f.text for f in RULES.iter("same_field")}
    assert used <= FIM_FIELDS
    for rule in RULES.iter("rule"):
        for name in re.findall(r"\$\((\w+)\)", rule.findtext("description")):
            assert name in FIM_FIELDS


def test_the_burst_is_50_changes_by_one_process_in_a_minute():
    burst = BY_ID[BURST]
    frequency, timeframe = int(burst.get("frequency")), int(burst.get("timeframe"))
    assert frequency + 2 == 50 and timeframe == 60  # Wazuh fires on the (frequency + 2)th event
    assert "50 files" in burst.findtext("description") and "within a minute" in burst.findtext("description")
    assert [f.text for f in burst.findall("same_field")] == ["process_id"]
    assert int(burst.get("ignore")) == timeframe


def test_the_canary_rule_outranks_every_sibling_and_maps_to_encryption():
    levels = {rule_id: int(rule.get("level")) for rule_id, rule in BY_ID.items()}
    assert levels[CANARY] == 15 > 14 > levels[BASE]  # 14: Wazuh's malware-hash rule 99901
    for rule_id in (BURST, CANARY):
        assert BY_ID[rule_id].findtext("mitre/id") == "T1486"
        assert "dwellwatch_stage6" in BY_ID[rule_id].findtext("group")


def test_the_canary_token_is_the_one_the_sigma_rule_uses():
    sigma = yaml.safe_load((ROOT / "sigma" / "stage6_encryption" / "canary_file_touched.yml").read_text())
    token = sigma["detection"]["selection"]["TargetFilename|contains"]
    canary = pattern(BY_ID[CANARY], "file")
    assert token == "dwellwatch-canary"
    for path in ["c:\\shares\\finance\\dwellwatch-canary-q3-budget.xlsx",  # Wazuh reports Windows paths lower-case
                 "C:\\Shares\\Finance\\DwellWatch-Canary-Q3-Budget.xlsx.lockbit"]:
        assert canary.search(path), path
    for path in ["c:\\shares\\finance\\q3-budget.xlsx", "c:\\shares\\dwellwatch\\canary.docx"]:
        assert not canary.search(path), path


@pytest.mark.parametrize("tags, watched", [
    ("dwellwatch", True), ("shares,dwellwatch", True), ("dwellwatch,pci", True),
    ("dwellwatch2", False), ("not-dwellwatch", False), ("", False),
])
def test_the_base_rule_reads_the_dwellwatch_tag_exactly(tags, watched):
    assert bool(pattern(BY_ID[BASE], "tag").search(tags)) is watched


def test_the_agent_watches_its_folders_with_who_data_and_the_tag_the_rules_read():
    directories = AGENT.findall("syscheck/directories")
    assert directories
    base_tag = pattern(BY_ID[BASE], "tag")
    for directory in directories:
        assert directory.get("whodata") == "yes", directory.text  # the burst rule needs process_id
        assert base_tag.search(directory.get("tags")), directory.text
