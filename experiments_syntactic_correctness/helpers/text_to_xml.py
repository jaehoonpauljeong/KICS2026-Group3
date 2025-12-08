# # For generated_policies_baseline.txt
# import os
# import re

# INPUT_FILE = "generated_policies_baseline.txt"   # file that contains the ```xml ... ``` blocks
# OUTPUT_DIR = "xml_policies_baseline"   # folder to write individual .xml files

# os.makedirs(OUTPUT_DIR, exist_ok=True)

# with open(INPUT_FILE, "r", encoding="utf-8") as f:
#     content = f.read()

# # Find all ```xml ... ``` blocks (non-greedy)
# pattern = re.compile(r"```xml\s*(.*?)```", re.DOTALL | re.IGNORECASE)
# matches = pattern.findall(content)

# if not matches:
#     print("No ```xml blocks found in the input file.")
# else:
#     for idx, inner in enumerate(matches, start=1):
#         block = inner.strip()

#         # Remove any existing XML declaration to avoid duplicates
#         block = re.sub(r"^\s*<\?xml[^>]*>\s*", "", block, flags=re.IGNORECASE)

#         # Construct final XML content with the requested declaration
#         final_xml = '<?xml version="1.0" encoding="UTF-8" ?>\n' + block + "\n"

#         filename = f"policy_{idx}.xml"
#         filepath = os.path.join(OUTPUT_DIR, filename)

#         # Write (this will overwrite existing policy_N files if present)
#         with open(filepath, "w", encoding="utf-8") as out:
#             out.write(final_xml)

#         print(f"Saved: {filepath}")

#     print(f"\nDone! Extracted {len(matches)} XML files into '{OUTPUT_DIR}'")


# //////////////////////////////////////////////////////////


# For generated_policies_ensemble.txt
# import os
# import re

# INPUT_FILE = "generated_policies_ensemble.txt"
# OUTPUT_DIR = "xml_policies_ensemble"
# INDENT = " " * 4   # 4 spaces total shift for namespace, body and footer

# os.makedirs(OUTPUT_DIR, exist_ok=True)

# with open(INPUT_FILE, "r", encoding="utf-8") as f:
#     content = f.read()

# # Capture ```xml ... ``` blocks
# pattern = re.compile(r"```xml\s*(.*?)```", re.DOTALL | re.IGNORECASE)
# matches = pattern.findall(content)

# if not matches:
#     print("No ```xml blocks found in the input file.")
# else:
#     for idx, inner in enumerate(matches, start=1):
#         block = inner.strip()

#         # Remove any existing XML declaration to avoid duplicates
#         block = re.sub(r"^\s*<\?xml[^>]*>\s*", "", block, flags=re.IGNORECASE)

#         # Try to extract inner content between <i2nsf-cfi-policy>...</i2nsf-cfi-policy>
#         m = re.search(r"<\s*i2nsf-cfi-policy\b([^>]*)>(.*?)<\s*/\s*i2nsf-cfi-policy\s*>",
#                       block, flags=re.IGNORECASE | re.DOTALL)
#         if m:
#             attrs = m.group(1).strip()           # attributes from original opening tag (if any)
#             inner_body = m.group(2).strip()      # inner body of the policy
#             if attrs:
#                 opening_lines = [
#                     '<i2nsf-cfi-policy',
#                     f'{attrs}>'    # <-- don't include leading spaces here
#                 ]
#             else:
#                 opening_lines = ['<i2nsf-cfi-policy>']
#         else:
#             # No outer wrapper found — use the whole block as body and canonical header
#             inner_body = block
#             opening_lines = [
#                 '<i2nsf-cfi-policy',
#                 'xmlns="urn:ietf:params:xml:ns:yang:ietf-i2nsf-cons-facing-interface">'
#             ]

#         # Ensure the canonical namespace line is present if not found already
#         if not any("xmlns=" in line for line in opening_lines):
#             if len(opening_lines) == 1 and opening_lines[0].endswith('>'):
#                 opening_lines = [opening_lines[0][:-1], 'xmlns="urn:ietf:params:xml:ns:yang:ietf-i2nsf-cons-facing-interface">']
#             else:
#                 opening_lines = opening_lines[:-1] + ['xmlns="urn:ietf:params:xml:ns:yang:ietf-i2nsf-cons-facing-interface">']

#         # Build final output with XML decl (no indent), then opening tag (first line no indent,
#         # subsequent opening lines indented), then indented body, then indented footer
#         xml_decl = '<?xml version="1.0" encoding="UTF-8" ?>'

#         lines = [xml_decl]

#         # Write opening tag lines: first line NOT indented, remaining opening lines INDENT + stripped content
#         for i_ol, ol in enumerate(opening_lines):
#             if i_ol == 0:
#                 lines.append(ol.rstrip())            # NO indent for the first opening line
#             else:
#                 # strip any existing leading whitespace from ol, then add INDENT
#                 lines.append(INDENT + ol.lstrip().rstrip())

#         # Prepare inner body lines — preserve internal indentation but shift them right by INDENT
#         inner_lines = inner_body.splitlines()
#         for il in inner_lines:
#             lines.append(INDENT + il.rstrip())

#         # Indent footer as well
#         footer = "</i2nsf-cfi-policy>"
#         lines.append(INDENT + footer)

#         final_text = "\n".join(lines).rstrip() + "\n"

#         # Save to file
#         filename = f"policy_{idx}.xml"
#         filepath = os.path.join(OUTPUT_DIR, filename)
#         with open(filepath, "w", encoding="utf-8") as out:
#             out.write(final_text)

#         print(f"Saved: {filepath}")

#     print(f"\nDone! Extracted {len(matches)} XML files into '{OUTPUT_DIR}'")


# //////////////////////////////////////////////////////////////////


# For generated_policies_ensemble2.txt
# import os
# import re

# INPUT_FILE = "generated_policies_ensemble2.txt"
# OUTPUT_DIR = "xml_policies_ensemble"

# os.makedirs(OUTPUT_DIR, exist_ok=True)

# with open(INPUT_FILE, "r", encoding="utf-8") as f:
#     content = f.read()

# # Normalize newlines
# content = content.replace("\r\n", "\n").replace("\r", "\n")

# # Split on any XML declaration (keep declaration with each part using lookahead)
# parts = re.split(r'(?=<\?xml[^>]*\?>)', content, flags=re.IGNORECASE | re.DOTALL)
# # Remove empty/whitespace-only parts
# parts = [p.strip() for p in parts if p.strip()]

# if not parts:
#     print("No XML declarations found. Nothing to split.")
# else:
#     for i, part in enumerate(parts, start=1):
#         # ensure trailing newline
#         text = part.rstrip() + "\n"
#         filename = f"policy_{i}.xml"
#         path = os.path.join(OUTPUT_DIR, filename)
#         with open(path, "w", encoding="utf-8") as out:
#             out.write(text)
#         print(f"Saved: {path}")
#     print(f"\nDone — {len(parts)} files written to '{OUTPUT_DIR}'")


# //////////////////////////////////////////////////////////////////


# For generated_policies_ensemble3.txt
import os
import re

INPUT_FILE = "generated_policies_ensemble6_gpt_4o_mini_3.txt"
OUTPUT_DIR = "xml_policies_ensemble6_gpt_4o_mini_3"

os.makedirs(OUTPUT_DIR, exist_ok=True)

with open(INPUT_FILE, "r", encoding="utf-8") as f:
    content = f.read()

# Normalize newlines
content = content.replace("\r\n", "\n").replace("\r", "\n")

# Primary split: on a line that is exactly 4 spaces (i.e. '\n    \n')
parts = re.split(r'\n {4}\n', content)

# If that didn't split anything meaningful (only 1 part), fallback to splitting on ```xml ... ```
if len(parts) <= 1:
    # find all ```xml ... ``` blocks (non-greedy)
    tb_pattern = re.compile(r'```xml\s*(.*?)\s*```', re.DOTALL | re.IGNORECASE)
    tb_matches = tb_pattern.findall(content)
    if tb_matches:
        # use the inner content of the triple-backtick blocks
        parts = [m for m in tb_matches]
    else:
        # last fallback: split on XML declaration (keep declaration)
        parts = re.split(r'(?=<\?xml[^>]*\?>)', content, flags=re.IGNORECASE | re.DOTALL)
        parts = [p for p in parts if p.strip()]

# Clean and write parts
written = 0
for idx, raw in enumerate(parts, start=1):
    p = raw.strip()

    if not p:
        continue

    # Remove leading ```xml (with optional whitespace/newline)
    p = re.sub(r'^\s*```xml\s*', '', p, flags=re.IGNORECASE)

    # Remove trailing triple backticks (```), possibly with trailing whitespace/newline
    p = re.sub(r'\s*```\s*$', '', p)

    # Final trim
    p = p.strip() + "\n"

    filename = f"policy_{idx}.xml"
    outpath = os.path.join(OUTPUT_DIR, filename)
    with open(outpath, "w", encoding="utf-8") as out:
        out.write(p)

    written += 1
    print(f"Saved: {outpath}")

print(f"\nDone — {written} files written to '{OUTPUT_DIR}'")
