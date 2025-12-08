from openai import OpenAI

# Configuration: API key and model
OPENAI_API_KEY = "YOUR-OPENAPI-KEY-HERE"
client = OpenAI(api_key=OPENAI_API_KEY)
DEFAULT_MODEL = "gpt-4o-mini"

def call_openai(system_prompt: str, user_content: str, model: str = DEFAULT_MODEL) -> str:
    """Helper function to call the OpenAI ChatCompletion API and return the response text."""
    response = client.chat.completions.create(
        model=model,
        messages=[
            {"role":"system","content":system_prompt},
            {"role":"user","content":user_content}
        ],
        temperature=0
    )
    return response.choices[0].message.content.strip()

def restate_intent(policy_intent: str, model: str = DEFAULT_MODEL) -> str:
    """Restate the policy intent in 'IF ... THEN ...' format."""
    system_prompt = (
        "You are a helpful assistant specialized in interpreting security policies. "
        "Restate the user's policy intent as a single conditional statement in the form: "
        "'IF <condition(s)> THEN <action(s)>.'"
    )
    return call_openai(system_prompt, policy_intent, model=model)

def extract_event_action(original_intent: str, restated_intent: str, model: str = DEFAULT_MODEL) -> str:
    """Phase 1: Extract event trigger(s) and action(s) from the policy."""
    system_prompt = (
        "You are an I2NSF policy expert focusing on events and actions. "
        "From the policy description and its IF-THEN restatement, list the event(s) that trigger the policy and the action(s) taken."
    )
    user_content = f"Original: {original_intent}\nRestated: {restated_intent}"
    return call_openai(system_prompt, user_content, model=model)

def extract_conditions(original_intent: str, restated_intent: str, model: str = DEFAULT_MODEL) -> str:
    """Phase 2: Extract any additional conditions (firewall, context, etc.) from the policy."""
    system_prompt = (
        "You are an I2NSF policy expert focusing on conditions. "
        "Identify all conditions (e.g., source/destination, time, location, protocol) in the policy apart from the main event trigger."
    )
    user_content = f"Original: {original_intent}\nRestated: {restated_intent}"
    return call_openai(system_prompt, user_content, model=model)

def extract_endpoint_groups_threat_feeds(original_intent: str, restated_intent: str, model: str = DEFAULT_MODEL) -> str:
    """Phase 3: Identify any endpoint groups, threat feed or list references in the policy."""
    system_prompt = (
        "You are an I2NSF threat intelligence assistant. "
        "Determine if the policy references any endpoints groups, threat feeds or known malicious lists. Provide the name if so, or 'None' if none."
    )
    user_content = f"Original: {original_intent}\nRestated: {restated_intent}"
    return call_openai(system_prompt, user_content, model=model)

def extract_metadata(original_intent: str, restated_intent: str, model: str = DEFAULT_MODEL) -> str:
    """Phase 4: Suggest metadata (policy name, rule name, language, priority, resolution strategy) for the policy."""
    system_prompt = (
        "You are an I2NSF policy metadata assistant. "
        "Provide a policy name, rule name, language tag (e.g., en-US), priority usage (e.g., priority-by-order), "
        "and resolution strategy (e.g., fmr for First Matching Rule) suitable for this policy. "
        "Use descriptive names based on the intent and avoid spaces (use '_' or '-')."
    )
    user_content = f"Original: {original_intent}\nRestated: {restated_intent}"
    return call_openai(system_prompt, user_content, model=model)

def schema_readiness_check(event_action: str, conditions: str, endpoint_groups_and_threat_feeds: str, metadata: str, yang_data: str, model: str = DEFAULT_MODEL) -> str:
    """Phase 5: Check the extracted components against the YANG data model for validity."""
    system_prompt = (
        "You are an I2NSF schema expert. "
        "Using the provided policy components (events, actions, conditions, endpoint groups, threat feeds, metadata) and the YANG model reference, "
        "verify all references and values are valid. List any issues or say 'All good' if everything is valid."
    )
    user_content = (
        f"Events & Actions: {event_action}\n"
        f"Conditions: {conditions}\n"
        f"Endpoint groups and Threat Feeds: {endpoint_groups_and_threat_feeds}\n"
        f"Metadata: {metadata}\n\n"
        f"YANG Data Model:\n{yang_data}"
    )
    return call_openai(system_prompt, user_content, model=model)

def compose_final_policy(original_intent: str, restated_intent: str, 
                         event_action: str, conditions: str, endpoint_groups_and_threat_feeds: str, metadata: str, schema_notes: str, yang_data: str, 
                         model: str = DEFAULT_MODEL) -> str:
    """Compose the final XML policy from all components and the YANG data model reference."""
    system_prompt = (
        "You are an expert I2NSF policy composer. "
        "Given the policy intent (original and restated), extracted events, conditions, actions, endpoint groups, threat feeds, metadata, and YANG model, "
        "output a complete I2NSF XML policy that is valid and includes all these elements."

        "Additional notes:"
        "- Details of the sources and destinations should fall under the endpoint-groups section.\n"
        "- Details of the sources and destinations such as IPv4, IPv6 and MAC addresses should NOT fall under the event-action-conditions (ECA) section. It should only store the name of the endpoint-group as an identifier to the record in the endpoint-groups section.\n"
        "- If details of the sources and destinations are missing in the intent, put a name for the endpoint-group under the event-action-conditions (ECA) section as a placeholder, but omit its record in the endpoint-group section.\n"
        "- Do not include logging unless explicitly told to in the intent.\n"
    )
    user_content = (
        f"Policy Intent (Original): {original_intent}\n"
        f"Policy Intent (Restated): {restated_intent}\n\n"
        f"{event_action}\n\n"
        f"{conditions}\n\n"
        f"Endpoint groups and Threat Feeds: {endpoint_groups_and_threat_feeds}\n\n"
        f"{metadata}\n\n"
        f"Schema Check: {schema_notes}\n\n"
        f"YANG Data Model:\n{yang_data}"
    )
    return call_openai(system_prompt, user_content, model=model)

# Main function to demonstrate end-to-end usage
def main(policy_intent):
    print("Original Policy Intent:", policy_intent, "\n")
    
    # Step 1: Restate intent in IF/THEN form
    restated = restate_intent(policy_intent)
    print("Restated Intent:", restated, "\n")
    
    # Step 2: Phase 1 - Event & Action extraction
    event_action = extract_event_action(policy_intent, restated)
    print("Extracted Events & Actions:", event_action, "\n")
    
    # Step 3: Phase 2 - Condition extraction
    conditions = extract_conditions(policy_intent, restated)
    print("Extracted Conditions:", conditions, "\n")
    
    # Step 4: Phase 3 - Threat feed extraction
    feeds = extract_endpoint_groups_threat_feeds(policy_intent, restated)
    print("Extracted Threat Feeds:", feeds, "\n")
    
    # Step 5: Phase 4 - Metadata extraction
    metadata = extract_metadata(policy_intent, restated)
    print("Extracted Metadata:", metadata, "\n")
    
    # Load YANG data model reference from CSV file
    yang_data = ""
    try:
        with open("YANG data model.csv", "r") as f:
            yang_data = f.read()
    except FileNotFoundError:
        yang_data = "(YANG data model CSV content goes here)"
    # Step 6: Phase 5 - Schema readiness check
    schema_notes = schema_readiness_check(event_action, conditions, feeds, metadata, yang_data)
    print("Schema Readiness Check:", schema_notes, "\n")
    
    # Step 7: Final composition of the XML policy
    final_policy_xml = compose_final_policy(policy_intent, restated, event_action, conditions, feeds, metadata, schema_notes, yang_data)
    print("Generated I2NSF XML Policy:\n", final_policy_xml)

# Run the main function if this script is executed (for demonstration purposes)
if __name__ == "__main__":
    # policy_intent = "Block packets coming from Buenos Aires, Argentina but allow packets coming from Lima, Peru."
    policy_intent = "Mitigate Flood Attacks on a Company Web Server."
    main(policy_intent)
