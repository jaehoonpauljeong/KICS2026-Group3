# Current draft we are ignoring the massive "condition" for now since:
# - its difficult to deal with as it is subjective (since natural language usually will miss out details and cause 
#   the LLM to hallucinate) (even if the fields take in a fixed set of identity references like for the "device-type" 
#   field its "computer", "mobile", etc.)... 
# - it also requires you to have an extensive "gold-dataset" which is presently unavailable for intent-to-policy mappings, 
#   where you can properly evaluate whether or not the generated "condition" field's subfields are the expected output 
#   based on the natural language intent

# The only solutions I can think of is:
# - the original paper's on few-shot examples (selected through cosine similarity) to produce better quality "conditions" 
#   field separately + slotting that condition field into the hypothesis JSON schema, but that requires a larger dataset 
#   of intent-to-policy mapping (unless you want me to present as it is "working" then I'll work on the produced fields 
#   can alr... I can try get it to mimic the original paper's LLM outputs?)

# - alternatively, another idea I had is to do like a prompt-engineered Mixture of Experts (MoE) with LLMs, where there are 
#   2 hypothesis LLMs, one that expertises in only the "condition" field, while the other expertises in any other fields in 
#   the ECA model. Then the output of these 2 hypothesis LLMs will then be passed into the complete hypothesis JSON schema and 
#   then the rest of the pipeline will stay the same (but this idea will leave to future improvements unfortunately... I don't 
#   think I wanna do this for this paper...)

# - hence I will just focus on testing/checking the other fields of the ECA model (I'm ignoring the "endpoint-groups" and 
#   "threat-prevention" as well, but these 2 sections I believe can be hardcoded to fill based on the YANG data model schema based 
#   on the generated "condition" field by LLMs anyway so I don't think they matter too much)

# - Otherwise, have to wait until someone creates this extensive "gold-dataset" for intent-to-policy mappings


# ////////////////////////////////////////////////////////////////////////////////


# To overcome these challenges, my testing avoids the "condition", "endpoint-groups" and "threat-prevention" fields, and 
# should hence test the remaining fields (at least those with a fixed set of outputs 
# (i.e. identityref)) (from top 
# to bottom of the YANG data model):
# - namespace (dosen't matter too much)
# - name (can be anything human-readable so dosen't matter too much)
# - language (dosen't matter too much)
# - priority-usage
# - resolution strategy

# In a rule:
# - name (can be anything human-readable so dosen't matter too much)
# - priority
# - event (system-event and system-alarm)
# - Primary action (main highlight) (action, limit)
# - Secondary action
# - Log action


# I will need to generate synthetic dataset of intent to policy with the inputs and expected outputs for these fields 
# to check accuracy of the generated policies between my project and the original paper:
# - generate some testcases focusing on priority-usage and priority (in a rule)
# - generate some testcases focusing on resolution strategy

# In a rule:
# - generate some testcases focusing on event (with just system-event)
# - generate some testcases focusing on event (with just system-alarm)
# - generate some testcases focusing on event (with both system-event and system-alarm)
# - generate some testcases focusing on Primary action (main highlight) (with just action)
# - generate some testcases focusing on Primary action (main highlight) (with action and limit)
# - generate some testcases focusing on Secondary action
# - generate some testcases focusing on Log action

import csv
import re
import os
import xml.etree.ElementTree as ET
import matplotlib.pyplot as plt

from main_v4 import run_pipeline
from original_main import generate_policy

NS = {"ns": "urn:ietf:params:xml:ns:yang:ietf-i2nsf-cons-facing-interface"}

def sanitize_xml(s: str) -> str:
    if not s:
        return ""
    # strip code fences / markdown
    s = re.sub(r"^```(?:xml|XML)?\s*|\s*```$", "", s.strip(), flags=re.MULTILINE)
    # keep only the part from the first '<' to the last '>'
    if "<" in s and ">" in s:
        s = s[s.find("<") : s.rfind(">") + 1]
    # remove zero-width and non-XML friendly control chars
    s = re.sub(r"[\u200B-\u200D\uFEFF]", "", s)
    return s.strip()

def findtext_ns(root, path):
    """Namespace-aware findtext using the default I2NSF namespace."""
    return root.findtext(path, namespaces=NS)

def save_xml_dump(idx, which, text, intent=None, expected=None):
    """
    Write a debug dump for the XML output.
    Also prepend XML comments that record the natural-language intent and the
    expected-output summary for this test case.
    """
    os.makedirs("xml_dumps", exist_ok=True)
    path = os.path.join("xml_dumps", f"test_{idx:03d}_{which}.xml.txt")

    # XML comments cannot contain `--`, replace with an em dash so logs are safe.
    def _clean_for_xml_comment(s: str) -> str:
        return (s or "").replace("--", "—")

    with open(path, "w", encoding="utf-8") as f:
        header_lines = []
        if intent:
            header_lines.append(f"<!-- intent: { _clean_for_xml_comment(intent) } -->")
        if expected:
            header_lines.append(f"<!-- expected: { _clean_for_xml_comment(expected) } -->")

        if header_lines:
            f.write("\n".join(header_lines) + "\n")

        f.write(text if text is not None else "")

    # Console preview
    preview = ((text or "").strip().replace("\n", " "))
    if len(preview) > 200:
        preview = preview[:200] + "…"
    print(f"  [{which}] raw XML preview: {preview}")
    print(f"  [{which}] full XML saved to: {path}")
    if intent or expected:
        print(f"  [{which}] intent logged above XML body.")
        print(f"  [{which}] expected logged above XML body.")

# Read test cases from CSV file (assumes the CSV is saved as 'test_cases.csv')
test_cases = []
with open('comparison_testing_intent_to_policy_dataset.csv', newline='') as csvfile:
    reader = csv.DictReader(csvfile)
    for row in reader:
        test_cases.append(row)

# Pre-compile regex patterns to extract expected field values
pattern_primary   = re.compile(r'primary-action:\s*([^,]+)')
pattern_limit     = re.compile(r'limit\s*->\s*([^,]+)')
pattern_secondary = re.compile(r'secondary-action\s*->\s*log-action:\s*([^,]+)')
pattern_sys_event = re.compile(r'system-event:\s*([^,]+)')
pattern_sys_alarm = re.compile(r'system-alarm:\s*([^,]+)')

# Counters for passes/fails per pipeline
passes_pipeline1 = fails_pipeline1 = 0
passes_pipeline2 = fails_pipeline2 = 0

# Iterate over each test case
for idx, case in enumerate(test_cases, start=1):
    intent = case['intent']
    expected_xml = case['expected_xml_output']
    
    # Parse expected fields from the expected output string
    expected_fields = {}
    m = pattern_primary.search(expected_xml)
    if m:
        expected_fields['primary-action'] = m.group(1).strip()
    m = pattern_limit.search(expected_xml)
    if m:
        expected_fields['limit'] = m.group(1).strip()
    m = pattern_secondary.search(expected_xml)
    if m:
        expected_fields['secondary-action'] = m.group(1).strip()
    m = pattern_sys_event.search(expected_xml)
    if m:
        expected_fields['system-event'] = m.group(1).strip()
    m = pattern_sys_alarm.search(expected_xml)
    if m:
        expected_fields['system-alarm'] = m.group(1).strip()
    
    # Generate XML outputs using the two pipelines
    hypothesis, resolved, xml_out1 = run_pipeline(intent)
    xml_out2 = generate_policy(intent, "gpt-4o-mini")

    # LOG RAW OUTPUTS
    save_xml_dump(idx, "pipeline1", xml_out1, intent=intent, expected=expected_xml)
    save_xml_dump(idx, "pipeline2", xml_out2, intent=intent, expected=expected_xml)

    # Sanitize before parsing
    xml_out1_clean = sanitize_xml(xml_out1)
    xml_out2_clean = sanitize_xml(xml_out2)
    
    # Parse the generated XML outputs and extract relevant fields
    output_fields1 = {}
    output_fields2 = {}
    differences1 = []
    differences2 = []
    
    # Pipeline 1 output parsing
    output_fields1, differences1 = {}, []
    try:
        root1 = ET.fromstring(xml_out1_clean)
    except ET.ParseError as e:
        differences1.append(f"Output is not valid XML: {e}")
        root1 = None

    if root1 is not None:
        # Use ns: prefixes!
        prim = findtext_ns(root1, './/ns:primary-action/ns:action')
        if prim:
            output_fields1['primary-action'] = prim.strip()
            if prim.strip() == 'rate-limit':
                lim = findtext_ns(root1, './/ns:primary-action/ns:limit')
                if lim:
                    output_fields1['limit'] = lim.strip()

        sec = findtext_ns(root1, './/ns:secondary-action/ns:log-action')
        if sec:
            output_fields1['secondary-action'] = sec.strip()

        has_event1 = root1.find('.//ns:event', namespaces=NS) is not None

        sevt = findtext_ns(root1, './/ns:event/ns:system-event')
        if sevt:
            output_fields1['system-event'] = sevt.strip()

        salarm = findtext_ns(root1, './/ns:event/ns:system-alarm')
        if salarm:
            output_fields1['system-alarm'] = salarm.strip()

    expects_any_event = ('system-event' in expected_fields) or ('system-alarm' in expected_fields)
    if expects_any_event and not has_event1:
        differences1.append("Missing <event> wrapper (expected system-event/system-alarm)")
    if not expects_any_event and has_event1:
        differences1.append("Unexpected <event> wrapper (no system-event/system-alarm expected)")
    
    # Pipeline 2 output parsing
    output_fields2, differences2 = {}, []
    try:
        root2 = ET.fromstring(xml_out2_clean)
    except ET.ParseError as e:
        differences2.append(f"Output is not valid XML: {e}")
        root2 = None

    if root2 is not None:
        # Use ns: prefixes!
        prim = findtext_ns(root2, './/ns:primary-action/ns:action')
        if prim:
            output_fields2['primary-action'] = prim.strip()
            if prim.strip() == 'rate-limit':
                lim = findtext_ns(root2, './/ns:primary-action/ns:limit')
                if lim:
                    output_fields2['limit'] = lim.strip()

        sec = findtext_ns(root2, './/ns:secondary-action/ns:log-action')
        if sec:
            output_fields2['secondary-action'] = sec.strip()

        has_event2 = root2.find('.//ns:event', namespaces=NS) is not None

        sevt = findtext_ns(root2, './/ns:event/ns:system-event')
        if sevt:
            output_fields2['system-event'] = sevt.strip()

        salarm = findtext_ns(root2, './/ns:event/ns:system-alarm')
        if salarm:
            output_fields2['system-alarm'] = salarm.strip()

    expects_any_event = ('system-event' in expected_fields) or ('system-alarm' in expected_fields)
    if expects_any_event and not has_event2:
        differences2.append("Missing <event> wrapper (expected system-event/system-alarm)")
    if not expects_any_event and has_event2:
        differences2.append("Unexpected <event> wrapper (no system-event/system-alarm expected)")
    
    # Compare expected vs output fields for pipeline 1
    fields_all_1 = set(expected_fields.keys()) | set(output_fields1.keys())
    for field in fields_all_1:
        exp_val = expected_fields.get(field)
        out_val = output_fields1.get(field)
        if exp_val is None and out_val is not None:
            differences1.append(f"Unexpected field {field} (output has {out_val})")
        elif exp_val is not None and out_val is None:
            differences1.append(f"Missing field {field} (expected {exp_val})")
        elif exp_val is not None and out_val is not None:
            if out_val != exp_val:
                differences1.append(f"{field} mismatch (expected {exp_val}, got {out_val})")
    
    # Compare expected vs output fields for pipeline 2
    fields_all_2 = set(expected_fields.keys()) | set(output_fields2.keys())
    for field in fields_all_2:
        exp_val = expected_fields.get(field)
        out_val = output_fields2.get(field)
        if exp_val is None and out_val is not None:
            differences2.append(f"Unexpected field {field} (output has {out_val})")
        elif exp_val is not None and out_val is None:
            differences2.append(f"Missing field {field} (expected {exp_val})")
        elif exp_val is not None and out_val is not None:
            if out_val != exp_val:
                differences2.append(f"{field} mismatch (expected {exp_val}, got {out_val})")
    
    # Update pass/fail counters
    if differences1:
        fails_pipeline1 += 1
    else:
        passes_pipeline1 += 1
    if differences2:
        fails_pipeline2 += 1
    else:
        passes_pipeline2 += 1
    
    # Log results for this test case
    print(f"Test case {idx}: {intent}")
    if differences1:
        print("  Pipeline 1 (KG+LLM): FAIL")
        for diff in differences1:
            print(f"    - {diff}")
    else:
        print("  Pipeline 1 (KG+LLM): PASS")
    if differences2:
        print("  Pipeline 2 (LLM-only): FAIL")
        for diff in differences2:
            print(f"    - {diff}")
    else:
        print("  Pipeline 2 (LLM-only): PASS")

# After all tests, generate summary bar chart
pipelines = ['KG+LLM', 'LLM-only']
pass_counts = [passes_pipeline1, passes_pipeline2]
fail_counts = [fails_pipeline1, fails_pipeline2]

x = [0, 1]  # two pipeline indices
width = 0.35
fig, ax = plt.subplots()
ax.bar([i - width/2 for i in x], pass_counts, width, label='Passed', color='green')
ax.bar([i + width/2 for i in x], fail_counts, width, label='Failed', color='red')
ax.set_xticks(x)
ax.set_xticklabels(pipelines)
ax.set_ylabel('Number of Test Cases')
ax.set_title('Test Case Results by Pipeline')
ax.legend()

plt.tight_layout()
plt.show()
