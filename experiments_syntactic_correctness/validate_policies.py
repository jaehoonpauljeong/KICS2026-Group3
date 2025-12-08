import subprocess
import os
from datetime import datetime

# Paths
yang_modules_dir = "yang-modules"
xml_policies_dir = "xml_policies"
main_schema = os.path.join(yang_modules_dir, "ietf-i2nsf-cons-facing-interface@2023-05-15.yang")
log_file = "validation_results.log"

def validate_policies():
    total_pass = 0
    total_fail = 0
    results = []        # store pass/fail summary
    error_details = []  # store error messages

    # Start fresh log file
    with open(log_file, "w") as f:
        f.write(f"YANG Validation Results - {datetime.now()}\n")
        f.write("=" * 60 + "\n\n")

    # Loop through XML policy files
    for xml_file in os.listdir(xml_policies_dir):
        if xml_file.endswith(".xml"):
            xml_path = os.path.join(xml_policies_dir, xml_file)

            cmd = ["yanglint", "-p", yang_modules_dir, main_schema, xml_path]
            result = subprocess.run(cmd, capture_output=True, text=True)
            output = (result.stdout + result.stderr).strip()

            if result.returncode != 0 or "err" in output.lower() or "YANGLINT[E]" in output:
                msg = f"[FAIL] {xml_file}"
                results.append(msg)
                error_details.append(f"{msg}\nError:\n{output}\n")
                total_fail += 1
            else:
                msg = f"[PASS] {xml_file}"
                results.append(msg)
                total_pass += 1

    # Print results summary
    for r in results:
        print(r)

    # Print error details after all files are processed
    if error_details:
        print("\nDetailed Errors:")
        print("=" * 60)
        for detail in error_details:
            print(detail)

    # Summary
    summary = f"Validation Summary: {total_pass} passed, {total_fail} failed."
    print("\n" + summary)

    # Write everything to log
    with open(log_file, "a") as f:
        for r in results:
            f.write(r + "\n")
        f.write("\n")
        for detail in error_details:
            f.write(detail + "\n")
        f.write("=" * 60 + "\n")
        f.write(summary + "\n")

if __name__ == "__main__":
    validate_policies()
