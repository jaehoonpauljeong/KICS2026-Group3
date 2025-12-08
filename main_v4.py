from openai import OpenAI
import csv
import re

# Configuration: API key and model
OPENAI_API_KEY = "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"
client = OpenAI(api_key=OPENAI_API_KEY)
DEFAULT_MODEL = "gpt-4o-mini"

def call_openai(system_prompt: str, user_content: str, model: str = DEFAULT_MODEL) -> str:
    """Helper function to call the OpenAI ChatCompletion API and return the response text."""
    response = client.chat.completions.create(
        model=model,
        messages=[
            {"role":"system","content":system_prompt},
            {"role":"user","content":user_content}
        ]
        # temperature=0
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

        "Regarding action(s), check if the intent asks for a secondary logging action. Include it if and ONLY if the intent asked for logging."
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
        "You are an I2NSF threat intelligence assistant.\n"
        "Determine if the policy references any endpoints groups, threat feeds or known malicious lists\n."
		"- Always try to infer minimal, generic endpoint-group names from the intent (even if not explicit).\n"
		"- If no addresses are provided in the intent, fabricate a placeholder IPv4 address range from the TEST-NET blocks (RFC 5737) so it is safe (non-routable): 192.0.2.0/24, 198.51.100.0/24, or 203.0.113.0/24."

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
    example_policy = """
<?xml version="1.0" encoding="UTF-8"?>
<endpoint-groups xmlns="urn:ietf:params:xml:ns:yang:ietf-i2nsf-cons-facing-interface">
  <url-group>
    <name>sns-websites</name>
    <url>https://facebook.com</url>
    <url>https://twitter.com</url>
    <url>https://instagram.com</url>
  </url-group>
</endpoint-groups>

<threat-prevention xmlns="urn:ietf:params:xml:ns:yang:ietf-i2nsf-cons-facing-interface">
	<threat-feed-list>
		<name>sns-phishing-domains</name>
		<ioc>malicious.example</ioc>
		<ioc>hash:abcd1234</ioc>
		<format>stix</format>
	</threat-feed-list>
</threat-prevention>

<i2nsf-cfi-policy xmlns="urn:ietf:params:xml:ns:yang:ietf-i2nsf-cons-facing-interface">
  <name>security_policy_for_blocking_sns</name>
  <rules>
    <name>block_access_to_sns_during_office_hours</name>
    <condition>
      <firewall>
        <source>employees</source>
      </firewall>
      <url-category>
        <url-name>sns-websites</url-name>
      </url-category>
      <context>
        <time>
          <start-date-time>2021-03-11T09:00:00.00Z</start-date-time>
          <end-date-time>2021-12-31T18:00:00.00Z</end-date-time>
          <period>
            <start-time>09:00:00Z</start-time>
            <end-time>18:00:00Z</end-time>
            <day>monday</day>
            <day>tuesday</day>
            <day>wednesday</day>
            <day>thursday</day>
            <day>friday</day>
          </period>
          <frequency>weekly</frequency>
        </time>
      </context>
    </condition>
    <action>
      <primary-action>
        <action>drop</action>
      </primary-action>
    </action>
  </rules>
</i2nsf-cfi-policy>
    """

    ietf_context = """
    The I2NSF schema follows an Event-Condition-Action (ECA) model. XML policies can have the following headers:

  +--rw i2nsf-cfi-policy* [name]
  |  +--rw name                   string
  |  +--rw language?              string
  |  +--rw priority-usage?        identityref
  |  +--rw resolution-strategy?   identityref
  |  +--rw rules* [name]
     |  +--rw name         string
     |  +--rw priority?    uint8
     |  +--rw event
     |  |  +--rw system-event*   identityref
     |  |  +--rw system-alarm*   identityref 
     |  +--rw condition
	 |	|  +--rw firewall
		 |  |  +--rw source*                     union
		 |  |  +--rw destination*                union
		 |  |  +--rw transport-layer-protocol?   identityref
		 |  |  +--rw range-port-number* [start end]
		 |  |  |  +--rw start    inet:port-number
		 |  |  |  +--rw end      inet:port-number
		 |  |  +--rw icmp
		 |  |     +--rw message*   identityref
	 |	|  +--rw ddos
		 |  |  +--rw rate-limit
		 |  |     +--rw packet-rate-threshold?   uint64
		 |  |     +--rw byte-rate-threshold?     uint64
		 |  |     +--rw flow-rate-threshold?     uint64
	 |	|  +--rw anti-virus
		 |  |  +--rw profile*   string
		 |  |  +--rw exception-files*   string
	 |	|  +--rw payload
		 |  |  +--rw content*   -> /threat-prevention/payload-content/name
	 |	|  +--rw url-category
		 |  |  +--rw url-name?   -> /endpoint-groups/url-group/name
	 |	|  +--rw voice
		 |  |  +--rw source-id*        -> /endpoint-groups/voice-group/name
		 |  |  +--rw destination-id*   -> /endpoint-groups/voice-group/name
		 |  |  +--rw user-agent*       string
	 |  |  +--rw context
		 |  |  +--rw time
		 |  |  |  +--rw start-date-time?   yang:date-and-time
		 |  |  |  +--rw end-date-time?     yang:date-and-time
		 |  |  |  +--rw period
		 |  |  |  |  +--rw start-time?   time
		 |  |  |  |  +--rw end-time?     time
		 |  |  |  |  +--rw day*          day
		 |  |  |  |  +--rw date*         int8
		 |  |  |  |  +--rw month* [start end]
		 |  |  |  |     +--rw start    string
		 |  |  |  |     +--rw end      string
		 |  |  |  +--rw frequency?         enumeration
		 |  |  +--rw application
		 |  |  |  +--rw protocol*   identityref
		 |  |  +--rw device-type
		 |  |  |  +--rw device*   identityref
		 |  |  +--rw users
		 |  |  |  +--rw user* [id]
		 |  |  |  |  +--rw id      uint32
		 |  |  |  |  +--rw name?   string
		 |  |  |  +--rw group* [id]
		 |  |  |     +--rw id      uint32
		 |  |  |     +--rw name?   string
		 |  |  +--rw geographic-location
		 |  |     +--rw source
		 |  |     |  +--rw country?   -> /endpoint-groups/location-group/country
		 |  |     |  +--rw region?    -> /endpoint-groups/location-group/region
		 |  |     |  +--rw city?      -> /endpoint-groups/location-group/city
		 |  |     +--rw destination
		 |  |        +--rw country?   -> /endpoint-groups/location-group/country
		 |  |        +--rw region?    -> /endpoint-groups/location-group/region
		 |  |        +--rw city?      -> /endpoint-groups/location-group/city
	 |  |  +--rw threat-feed
		 |  |  +--rw name*   -> /threat-prevention/threat-feed-list/name
     |  +--rw action
	 |  |  +--rw primary-action
		 |	|  +--rw action    identityref
		 |	|  +--rw limit?    decimal64
	 |	|  +--rw secondary-action
         |	|  +--rw log-action?   identityref
	 +--rw endpoint-groups
	 |  +--rw user-group* [name]
	 |  |  +--rw name                              string
	 |     +--rw mac-address*                      yang:mac-address
	 |     +--rw (match-type)
		 |     +--:(ipv4)
		 |     |  +--rw (ipv4-range-or-prefix)?
		 |     |     +--:(prefix)
		 |     |     |  +--rw ipv4-prefix*          inet:ipv4-prefix
		 |     |     +--:(range)
		 |     |        +--rw range-ipv4-address* [start end]
		 |     |           +--rw start    inet:ipv4-address-no-zone
		 |     |           +--rw end      inet:ipv4-address-no-zone
		 |     +--:(ipv6)
		 |        +--rw (ipv6-range-or-prefix)?
		 |           +--:(prefix)
		 |           |  +--rw ipv6-prefix*          inet:ipv6-prefix
		 |           +--:(range)
		 |              +--rw range-ipv6-address* [start end]
		 |                 +--rw start    inet:ipv6-address-no-zone
		 |                 +--rw end      inet:ipv6-address-no-zone
	 |  +--rw device-group* [name]
	 |  |  +--rw name                              string
		|  +--rw (match-type)
		 |  |  +--:(ipv4)
		 |  |  |  +--rw (ipv4-range-or-prefix)?
		 |  |  |     +--:(prefix)
		 |  |  |     |  +--rw ipv4-prefix*          inet:ipv4-prefix
		 |  |  |     +--:(range)
		 |  |  |        +--rw range-ipv4-address* [start end]
		 |  |  |           +--rw start    inet:ipv4-address-no-zone
		 |  |  |           +--rw end      inet:ipv4-address-no-zone
		 |  |  +--:(ipv6)
		 |  |     +--rw (ipv6-range-or-prefix)?
		 |  |        +--:(prefix)
		 |  |        |  +--rw ipv6-prefix*          inet:ipv6-prefix
		 |  |        +--:(range)
		 |  |           +--rw range-ipv6-address* [start end]
		 |  |              +--rw start    inet:ipv6-address-no-zone
		 |  |              +--rw end      inet:ipv6-address-no-zone
		|  +--rw application-protocol*             identityref
	 |  +--rw location-group* [country region city]
	 |  |  +--rw country                           string
		|  +--rw region                            string
		|  +--rw city                              string
		|  +--rw (match-type)
		 |     +--:(ipv4)
		 |     |  +--rw (ipv4-range-or-prefix)?
		 |     |     +--:(prefix)
		 |     |     |  +--rw ipv4-prefix*          inet:ipv4-prefix
		 |     |     +--:(range)
		 |     |        +--rw range-ipv4-address* [start end]
		 |     |           +--rw start    inet:ipv4-address-no-zone
		 |     |           +--rw end      inet:ipv4-address-no-zone
		 |     +--:(ipv6)
		 |        +--rw (ipv6-range-or-prefix)?
		 |           +--:(prefix)
		 |           |  +--rw ipv6-prefix*          inet:ipv6-prefix
		 |           +--:(range)
		 |              +--rw range-ipv6-address* [start end]
		 |                 +--rw start    inet:ipv6-address-no-zone
		 |                 +--rw end      inet:ipv6-address-no-zone
	 |  +--rw url-group* [name]
	 |  |  +--rw name    string
	 |	|  +--rw url*    inet:uri
	 |  +--rw voice-group* [name]
	 |  |  +--rw name      string
	 |  |  +--rw sip-id*   inet:uri
	 +--rw threat-prevention
     |  |  +--rw name      string
     |  |  +--rw ioc*      string
     |  |  +--rw format    identityref
    """

    system_prompt = (
        "You are an expert I2NSF policy composer. "
        "Given the policy intent (original and restated), extracted events, conditions, actions, endpoint groups, threat feeds, metadata, and YANG model, "
        "output a complete I2NSF XML policy that is valid and includes all these elements."

        "Additional notes:"
        "- If required, a standalone <endpoint-groups> document (with the I2NSF CFI namespace declared on the root element). This document MUST contain all endpoint groups referenced by the policy (url-group, user-group, device-group, etc)\n."
        "- If required, a standalone <threat-prevention> document (with the I2NSF CFI namespace declared on the root element). This document contains all threat feeds referenced by the policy\n."
        "- A standalone <i2nsf-cfi-policy> document (with the I2NSF CFI namespace declared on the root element) that references endpoint groups by name only (e.g., <source>employees</source> or <url-name>sns-websites</url-name>)\n."
        "- Details of the sources and destinations should fall under the endpoint-groups section.\n"
        "- Details of the sources and destinations such as IPv4, IPv6 and MAC addresses should NOT fall under the event-action-conditions (ECA) section. It should only store the name of the endpoint-group as an identifier to the record in the endpoint-groups section.\n"
        "- If details of the sources and destinations are missing in the intent, put a name for the endpoint-group under the event-action-conditions (ECA) section as a placeholder and in the standalone <endpoint-groups> document, along with a placeholder IPv4 addresses range in the standalone <endpoint-groups> document.\n"
        "- Do not include logging unless explicitly told to in the intent.\n"
		"- If you specify a <period> (with days/times), you MUST include a <frequency> (only-once, daily, weekly, monthly, yearly). The default frequency is 'only-once' which causes validation failures when used with recurring time periods.\n"
    )
    user_content = (
        f"Policy Intent (Original): {original_intent}\n"
        f"Policy Intent (Restated): {restated_intent}\n\n"
        f"{event_action}\n\n"
        f"{conditions}\n\n"
        f"Endpoint groups and Threat Feeds: {endpoint_groups_and_threat_feeds}\n\n"
        f"{metadata}\n\n"
        f"Schema Check: {schema_notes}\n\n"
        f"I2NSF schema:\n{ietf_context}\n\n"
        f"YANG Data Model:\n{yang_data}\n\n"
        f"Example of a correct policy:\n{example_policy}"
    )
    return call_openai(system_prompt, user_content, model=model)

def validate_policy(original_intent: str, policy_xml: str, schema_csv_text: str, model: str = DEFAULT_MODEL) -> str:
    ietf_context = """
    The I2NSF schema follows an Event-Condition-Action (ECA) model. XML policies can have the following headers:

  +--rw i2nsf-cfi-policy* [name]
  |  +--rw name                   string
  |  +--rw language?              string
  |  +--rw priority-usage?        identityref
  |  +--rw resolution-strategy?   identityref
  |  +--rw rules* [name]
     |  +--rw name         string
     |  +--rw priority?    uint8
     |  +--rw event
     |  |  +--rw system-event*   identityref
     |  |  +--rw system-alarm*   identityref 
     |  +--rw condition
	 |	|  +--rw firewall
		 |  |  +--rw source*                     union
		 |  |  +--rw destination*                union
		 |  |  +--rw transport-layer-protocol?   identityref
		 |  |  +--rw range-port-number* [start end]
		 |  |  |  +--rw start    inet:port-number
		 |  |  |  +--rw end      inet:port-number
		 |  |  +--rw icmp
		 |  |     +--rw message*   identityref
	 |	|  +--rw ddos
		 |  |  +--rw rate-limit
		 |  |     +--rw packet-rate-threshold?   uint64
		 |  |     +--rw byte-rate-threshold?     uint64
		 |  |     +--rw flow-rate-threshold?     uint64
	 |	|  +--rw anti-virus
		 |  |  +--rw profile*   string
		 |  |  +--rw exception-files*   string
	 |	|  +--rw payload
		 |  |  +--rw content*   -> /threat-prevention/payload-content/name
	 |	|  +--rw url-category
		 |  |  +--rw url-name?   -> /endpoint-groups/url-group/name
	 |	|  +--rw voice
		 |  |  +--rw source-id*        -> /endpoint-groups/voice-group/name
		 |  |  +--rw destination-id*   -> /endpoint-groups/voice-group/name
		 |  |  +--rw user-agent*       string
	 |  |  +--rw context
		 |  |  +--rw time
		 |  |  |  +--rw start-date-time?   yang:date-and-time
		 |  |  |  +--rw end-date-time?     yang:date-and-time
		 |  |  |  +--rw period
		 |  |  |  |  +--rw start-time?   time
		 |  |  |  |  +--rw end-time?     time
		 |  |  |  |  +--rw day*          day
		 |  |  |  |  +--rw date*         int8
		 |  |  |  |  +--rw month* [start end]
		 |  |  |  |     +--rw start    string
		 |  |  |  |     +--rw end      string
		 |  |  |  +--rw frequency?         enumeration
		 |  |  +--rw application
		 |  |  |  +--rw protocol*   identityref
		 |  |  +--rw device-type
		 |  |  |  +--rw device*   identityref
		 |  |  +--rw users
		 |  |  |  +--rw user* [id]
		 |  |  |  |  +--rw id      uint32
		 |  |  |  |  +--rw name?   string
		 |  |  |  +--rw group* [id]
		 |  |  |     +--rw id      uint32
		 |  |  |     +--rw name?   string
		 |  |  +--rw geographic-location
		 |  |     +--rw source
		 |  |     |  +--rw country?   -> /endpoint-groups/location-group/country
		 |  |     |  +--rw region?    -> /endpoint-groups/location-group/region
		 |  |     |  +--rw city?      -> /endpoint-groups/location-group/city
		 |  |     +--rw destination
		 |  |        +--rw country?   -> /endpoint-groups/location-group/country
		 |  |        +--rw region?    -> /endpoint-groups/location-group/region
		 |  |        +--rw city?      -> /endpoint-groups/location-group/city
	 |  |  +--rw threat-feed
		 |  |  +--rw name*   -> /threat-prevention/threat-feed-list/name
     |  +--rw action
	 |  |  +--rw primary-action
		 |	|  +--rw action    identityref
		 |	|  +--rw limit?    decimal64
	 |	|  +--rw secondary-action
         |	|  +--rw log-action?   identityref
	 +--rw endpoint-groups
	 |  +--rw user-group* [name]
	 |  |  +--rw name                              string
	 |     +--rw mac-address*                      yang:mac-address
	 |     +--rw (match-type)
		 |     +--:(ipv4)
		 |     |  +--rw (ipv4-range-or-prefix)?
		 |     |     +--:(prefix)
		 |     |     |  +--rw ipv4-prefix*          inet:ipv4-prefix
		 |     |     +--:(range)
		 |     |        +--rw range-ipv4-address* [start end]
		 |     |           +--rw start    inet:ipv4-address-no-zone
		 |     |           +--rw end      inet:ipv4-address-no-zone
		 |     +--:(ipv6)
		 |        +--rw (ipv6-range-or-prefix)?
		 |           +--:(prefix)
		 |           |  +--rw ipv6-prefix*          inet:ipv6-prefix
		 |           +--:(range)
		 |              +--rw range-ipv6-address* [start end]
		 |                 +--rw start    inet:ipv6-address-no-zone
		 |                 +--rw end      inet:ipv6-address-no-zone
	 |  +--rw device-group* [name]
	 |  |  +--rw name                              string
		|  +--rw (match-type)
		 |  |  +--:(ipv4)
		 |  |  |  +--rw (ipv4-range-or-prefix)?
		 |  |  |     +--:(prefix)
		 |  |  |     |  +--rw ipv4-prefix*          inet:ipv4-prefix
		 |  |  |     +--:(range)
		 |  |  |        +--rw range-ipv4-address* [start end]
		 |  |  |           +--rw start    inet:ipv4-address-no-zone
		 |  |  |           +--rw end      inet:ipv4-address-no-zone
		 |  |  +--:(ipv6)
		 |  |     +--rw (ipv6-range-or-prefix)?
		 |  |        +--:(prefix)
		 |  |        |  +--rw ipv6-prefix*          inet:ipv6-prefix
		 |  |        +--:(range)
		 |  |           +--rw range-ipv6-address* [start end]
		 |  |              +--rw start    inet:ipv6-address-no-zone
		 |  |              +--rw end      inet:ipv6-address-no-zone
		|  +--rw application-protocol*             identityref
	 |  +--rw location-group* [country region city]
	 |  |  +--rw country                           string
		|  +--rw region                            string
		|  +--rw city                              string
		|  +--rw (match-type)
		 |     +--:(ipv4)
		 |     |  +--rw (ipv4-range-or-prefix)?
		 |     |     +--:(prefix)
		 |     |     |  +--rw ipv4-prefix*          inet:ipv4-prefix
		 |     |     +--:(range)
		 |     |        +--rw range-ipv4-address* [start end]
		 |     |           +--rw start    inet:ipv4-address-no-zone
		 |     |           +--rw end      inet:ipv4-address-no-zone
		 |     +--:(ipv6)
		 |        +--rw (ipv6-range-or-prefix)?
		 |           +--:(prefix)
		 |           |  +--rw ipv6-prefix*          inet:ipv6-prefix
		 |           +--:(range)
		 |              +--rw range-ipv6-address* [start end]
		 |                 +--rw start    inet:ipv6-address-no-zone
		 |                 +--rw end      inet:ipv6-address-no-zone
	 |  +--rw url-group* [name]
	 |  |  +--rw name    string
	 |	|  +--rw url*    inet:uri
	 |  +--rw voice-group* [name]
	 |  |  +--rw name      string
	 |  |  +--rw sip-id*   inet:uri
	 +--rw threat-prevention
     |  |  +--rw name      string
     |  |  +--rw ioc*      string
     |  |  +--rw format    identityref
    """

    system_prompt = (
        "You are an I2NSF policy validator assistant. "
        "Given an I2NSF policy XML, the user's intent, I2NSF schema and a YANG schema CSV reference, validate the I2NSF XML policy if it:\n"
        "- Conforms to the I2NSF schema (e.g. if found <context> under <firewall> then shift it to the correct position, correct leafrefs, etc.)\n"
        "- If present, ensure standalone <endpoint-groups> document comes first, then, if present, the <threat-prevention> document (if present), then finally the <i2nsf-cfi-policy> document\n"
        "- If there is an <endpoint-groups> and/or <threat-prevention> section, split it each into a seperate section.\n"           
        "- Ensure all fields is in the same order as specified by the I2NSF schema\n"
        "- Does NOT invent limits, IPs, CIDRs, MACs, URLs, or SIP URIs not present in the intent\n"
        "- If found <context> under <firewall> then shift it to the correct position according to the I2NSF schema.\n"
        "- If under an endpoint-group in the <endpoint-groups> document, there is both a IPv4 addresses field and IPv6 addresses field, remove the IPv6 addresses field since there can only be either one of them.\n"
        "- If under an endpoint-group in the <endpoint-groups> document, there is both a IPv4/IPv6 addresses range and prefix field, remove the prefix field since there can only be either one of them.\n"
        "- Does not include <log-action> unless the intent explicitly asked for logging.\n" 
        "- Ensure the secondary-action field only contain the sub-field, log-action, and only consists of logging actions. It should NOT contain primary actions.\n" 
        "- There should only be 1 primary-action field per rule\n."
        "- Do not add any additional </policy> fields.\n"
        "- If there is an event field, remove it.\n"               
        "- If there is a protocol, application-protocol or transport-layer-protocol field, remove it.\n"                                         
        
        "If there is no issues with the initial I2NSF policy XML, then return it as is, else, return the corrected XML."

        "Generate only the XML. Do not give additional text."
    )
    # "- Uses endpoint-group names under firewall source/destination; define endpoint-groups only if the intent provides details; else leave placeholders and omit unknown details.\n"


    user_content = (
        f"Intent:\n{original_intent}\n\n"
        f"CurrentPolicyXML:\n{policy_xml}\n\n"
        f"I2NSF schema:\n{ietf_context}\n\n"
        "YANG CSV:\n" + schema_csv_text
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
    print("Extracted Endpoint Groups and Threat Feeds:", feeds, "\n")
    
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

    # Step 8: Validate final composition of the XML policy
    validated_final_policy_xml = validate_policy(policy_intent, final_policy_xml, yang_data)
    print("\nValidated Generated I2NSF XML Policy:\n", validated_final_policy_xml)

    return validated_final_policy_xml

# Run the main function if this script is executed (for demonstration purposes)
if __name__ == "__main__":
    # policy_intent = "Block packets coming from Buenos Aires, Argentina but allow packets coming from Lima, Peru."
    # policy_intent = "Mitigate Flood Attacks on a Company Web Server."
    # policy_intent = "Permit packets coming from Lima, Peru."
    # policy_intent =  "Permit access to Youtube, X and Instagram during school hours to all PCs within 128.0.0.0-128.0.0.255 IPv4 ranges."	
    # policy_intent =  "Block SNS Access during Business Hours."
    policy_intent =  "Copy all outgoing email traffic to the monitoring system for inspection (and still forward it)."
    main(policy_intent)
    
	# input_csv = "comparison_testing_intent_dataset.csv"       # CSV with 1 column: "intent"
	# output_txt = "generated_policies_ensemble6_gpt_4o_mini_3.txt"

	# with open(input_csv, newline="", encoding="utf-8") as csvfile:
	# 	reader = csv.DictReader(csvfile)
		
	# 	with open(output_txt, "w", encoding="utf-8") as outfile:
	# 		for row in reader:
	# 			intent = row["intent"].strip()
	# 			if not intent:
	# 				continue
				
	# 			print(f"Generating policy for intent: {intent}")
	# 			xml_policy = main(intent)
				
	# 			# Write XML policy followed by two newlines
	# 			outfile.write(xml_policy + "\n\n\n\n")

	# print(f"All policies generated and saved to {output_txt}")