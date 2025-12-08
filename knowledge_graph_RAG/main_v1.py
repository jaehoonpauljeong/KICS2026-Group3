from neo4j import GraphDatabase
import openai
import os
import json

# Add this after your OpenAI client setup
NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "password")

driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
client = openai.OpenAI(api_key=OPENAI_API_KEY)
model = "gpt-4o-mini"

def LLM_generate_structural_hypothesis(intent):
    # Examples to guide the model
    example_intent1 = "Block my son's computers from malicious websites."
    example_hypothesis1 = """
{
  "policy": {
    "name": "block_sons_computers_malicious_sites",
    "priority_usage": "priority-by-order",
    "resolution_strategy": "fmr"
  },
  "rules": [
    {
      "name": "block_malicious_sites",
      "condition": {
        "firewall": {
          "source": ["son's computers"]
        },
        "url_category": {
          "url_group": "malicious websites"
        }
      },
      "action": {
        "primary": "block"
      }
    }
  ]
}
    """

    example_intent2 = "Block malicious VoIP/VoCN packets coming to a company."
    example_hypothesis2 = """
{
  "policy": {
    "name": "block_malicious_voice_traffic",
    "priority_usage": "priority-by-order",
    "resolution_strategy": "fmr"
  },
  "rules": [
    {
      "name": "block_malicious_voice",
      "condition": {
        "voice": {
          "destination_id": ["company"]
        }
      },
      "action": {
        "primary": "block"
      }
    }
  ]
}
    """

    prompt = f"""
You are an intent parsing engine for a network security policy system. Your sole purpose is to extract structured data from a user's natural language command. You are an expert in the I2NSF Consumer-Facing Interface (CFI) YANG data model.

TASK:
Analyze the user's intent and output a JSON hypothesis that maps their words to the correct slots in the policy schema. Your output must be a valid JSON object that conforms to the SCHEMA provided.

INSTRUCTIONS:
1. EXTRACTION, NOT RESOLUTION: Your job is to find the user's *intent* and map it to the right *slot names*. Use the raw text values from the user's input. DO NOT resolve synonyms, infer IDs, or guess group names. If the user says "block", your output should contain "block", not "stop".
2. USE THE SCHEMA: Structure your output exactly according to the provided SCHEMA. Only include fields that are mentioned or can be reasonably inferred from the intent.
3. DEFAULTS: If the user does not specify a value for a required field like `policy.resolution_strategy`, use the default value specified in the SCHEMA.
4. CONDITIONAL LOGIC: If the user's intent implies multiple rules (e.g., "allow X but block Y"), you MUST represent this as multiple objects in the `rules` array.

EXAMPLES:
    Here are a few examples for reference:
    Input: {example_intent1}
    Output: {example_hypothesis1}

    Input: {example_intent2}
    Output: {example_hypothesis2}

    Input: {example_intent3}
    Output: {example_hypothesis3}

    Input: {example_intent4}
    Output: {example_hypothesis4}

SCHEMA:
{{
  "policy": {{
    "name": "string | null",         // If not specified, generate a name based on intent
    "priority_usage": "string",      // MUST be one of: ["priority-by-order", "priority-by-number"]
    "resolution_strategy": "string"  // MUST be one of: ["fmr", "lmr", "pmre", "pmrn"]. Default: "fmr"
  }},
  "rules": [
    {{
      "name": "string | null",       // If not specified, generate a name like 'rule_1'
      "priority": "integer | null",  // Only include if the user specifies a number.
      "condition": {{
        "firewall": {{
          "source": ["array of raw string group names"],
          "destination": ["array of raw string group names"],
          "transport": "raw string protocol name", // e.g., "tcp", "udp"
          "port_ranges": [{{"start": "number", "end": "number"}}] // ONLY if user specifies ranges
        }},
        "url_category": {{
          "url_group": "raw string group name"
        }},
        "voice": {{
          "source_id": ["array of raw string group names"],
          "destination_id": ["array of raw string group names"],
          "user_agent": ["array of raw strings"]
        }},
        "context": {{
          "time": {{
            "start_datetime": "ISO8601 string | null",
            "end_datetime": "ISO8601 string | null",
            "frequency": "string | null", // "only-once", "daily", "weekly", "monthly", "yearly"
            "period": {{
              "start_time": "HH:MM:SSZ | null",
              "end_time": "HH:MM:SSZ | null",
              "day": ["array of days: Mon, Tue, Wed, Thu, Fri, Sat, Sun"],
              "date": ["array of integers 1-31"],
              "month": ["array of strings MM-DD"]
            }}
          }},
          "application": {{
            "protocol": ["array of raw string protocol names"] // e.g., "http", "https"
          }},
          "device_type": {{
            "device": ["array of raw string device types"] // e.g., "computer", "phone"
          }},
          "users": {{
            "user": ["array of raw user names or IDs"],
            "group": ["array of raw group names"]
          }},
          "geo": {{
            "source": {{"country": "string", "region": "string", "city": "string"}},
            "destination": {{"country": "string", "region": "string", "city": "string"}}
          }}
        }},
        "threat_feed": {{
          "name": ["array of raw string feed names"]
        }},
        "payload": {{
          "content": ["array of raw string content names"]
        }},
        "ddos": {{
          "packet_rate_threshold": "number | null",
          "byte_rate_threshold": "number | null",
          "flow_rate_threshold": "number | null"
        }}
        // ... other condition types can be omitted if not present
      }},
      "action": {{
        "primary": "raw string action name", // e.g., "allow", "block", "rate limit", "log"
        "limit": "number | null",            // ONLY include if primary is "rate limit"
        "secondary": "raw string action name | null" // e.g., "log"
      }}
    }}
  ]
}}

Now, generate the SCHEMA for the following intent:
Intent: {intent}
    """
    
    response = openai.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": "You are an intent parsing engine for a network security policy system. Your sole purpose is to extract structured data from a user's natural language command. You are an expert in the I2NSF Consumer-Facing Interface (CFI) YANG data model."},
            {"role": "user", "content": prompt}
        ]
    )
    
    return response.choices[0].message.content


# ///////////////////////////////////////////////////////////////////////////////////


# Using the Knowledge Graph to handle the "Retrieve" part of Retrieval Augmented Generation (RAG) and organise them into a
# slot schema via cosine similarity
def retrieve_schema_slots_from_knowledge_graph(raw_text: str, target_labels: list, top_k: int = 3):
    """
    Queries the Neo4j KG for the best matches to `raw_text` within nodes with `target_labels`.
    Returns a list of candidate nodes with their similarity scores.
    """
    # Define which properties to search on. This is flexible.
    search_properties = ["name", "display_name", "machine_name"]
    
    # Construct the label part of the query (e.g., ":UserGroup:DeviceGroup")
    labels_str = ":".join(target_labels)
    
    # This is a parameterized query for security and performance
    query = f"""
    MATCH (candidate{labels_str})
    WHERE candidate.embedding IS NOT NULL
    AND (
        // Search across the specified properties
        any(prop in $search_properties WHERE toLower(coalesce(candidate[prop], '')) CONTAINS toLower($raw_text))
        OR
        // Search via connected Lexeme nodes (synonyms)
        EXISTS {{
            MATCH (candidate)<-[:REFERS_TO]-(l:Lexeme)
            WHERE toLower(l.text) CONTAINS toLower($raw_text)
        }}
    )
    WITH candidate, 
         // Calculate similarity. Use the most relevant property for the vector.
         apoc.ml.vector.similarity.cosine(candidate.embedding, $query_embedding) AS similarity
    RETURN candidate, similarity
    ORDER BY similarity DESC
    LIMIT $top_k
    """
    
    # Generate an embedding for the query text
    # You need an OpenAI (or other) function for this
    query_embedding = get_text_embedding(raw_text) 
    
    with driver.session() as session:
        result = session.run(query, 
                            raw_text=raw_text,
                            search_properties=search_properties,
                            target_labels=target_labels,
                            query_embedding=query_embedding,
                            top_k=top_k)

        return [{"node": record["candidate"], "score": record["similarity"]} for record in result]

# Helper function to get an embedding
def get_text_embedding(text):
    response = client.embeddings.create(
        model="text-embedding-3-small",
        input=text
    )
    return response.data[0].embedding


def resolve_hypothesis_simple(hypothesis_data):
    resolved_data = json.loads(json.dumps(hypothesis_data)) # Deep copy

    # Resolve Action
    primary_action = hypothesis_data["rules"][0]["action"]["primary"]
    candidates = retrieve_schema_slots_from_knowledge_graph(primary_action, ["Identity", "PrimaryAction"], top_k=1)
    if candidates:
        resolved_data["rules"][0]["action"]["primary"] = candidates[0]['node']['machine_name']

    # Resolve Source Group
    source_groups = hypothesis_data["rules"][0]["condition"]["firewall"]["source"]
    resolved_sources = []
    for group_name in source_groups:
        candidates = retrieve_schema_slots_from_knowledge_graph(group_name, ["UserGroup", "DeviceGroup"], top_k=1)
        if candidates:
            resolved_sources.append(candidates[0]['node']['name'])
    resolved_data["rules"][0]["condition"]["firewall"]["source"] = resolved_sources

    # Resolve URL Group
    url_group = hypothesis_data["rules"][0]["condition"]["url_category"]["url_group"]
    candidates = retrieve_schema_slots_from_knowledge_graph(url_group, ["URLGroup"], top_k=1)
    if candidates:
        resolved_data["rules"][0]["condition"]["url_category"]["url_group"] = candidates[0]['node']['name']

    return resolved_data


# ///////////////////////////////////////////////////////////////////////////////////


def LLM_compose_policy(resolved_schema, model="gpt-4o-mini"):
    """
    Converts resolved slots schema into an XML security policy.
    Includes examples and IETF draft content for context.
    """

    # Examples to guide the model
    example_schema1 = """
{
  "policy": {
    "name": "block_sons_computers_malicious_sites",
    "resolution_strategy": "fmr"
  },
  "rules": [
    {
      "name": "block_malicious_sites",
      "condition": {
        "firewall": {
          "source": ["kids-devices"]
        },
        "url_category": {
          "url_group": "known-bad-urls"
        }
      },
      "action": {
        "primary": "drop"
      }
    }
  ]
}
    """
    example_policy_output1 = """
<?xml version="1.0" encoding="UTF-8" ?>
<i2nsf-cfi-policy
    xmlns="urn:ietf:params:xml:ns:yang:ietf-i2nsf-cfi-policy">
    <name>block_web_security_policy</name>
    <rules>
        <name>block_web</name>
        <condition>
            <firewall-condition>
                <source>Son's_PC</source>
            </firewall-condition>
            <url-condition>
                <url-name>malicious_websites</url-name>
            </url-condition>
        </condition>
        <actions>
            <primary-action>
                <action>drop</action>
            </primary-action>
        </actions>
    </rules>
</i2nsf-cfi-policy>
    """

    example_schema2 = """
{
  "policy": {
    "name": "block_malicious_voice_traffic",
    "resolution_strategy": "fmr"
  },
  "rules": [
    {
      "name": "block_malicious_voice",
      "condition": {
        "voice": {
          "source_id": ["known-malicious-voip-ids"]
        },
        "firewall": {
          "destination": ["corp-sip-servers"]
        }
      },
      "action": {
        "primary": "drop"
      }
    }
  ]
}
    """
    example_policy_output2 = """
<?xml version="1.0" encoding="UTF-8" ?>
<i2nsf-cfi-policy
    xmlns="urn:ietf:params:xml:ns:yang:ietf-i2nsf-cons-facing-interface">
    <name>
        security_policy_for_blocking_malicious_voip_packets
    </name>
    <rules>
        <name>Block_malicious_voip_and_vocn_packets</name>
        <condition>
            <voice>
                <source-id>malicious-id</source-id>
            </voice>
            <firewall>
                <destination>employees</destination>
            </firewall>
        </condition>
        <action>
            <primary-action>
                <action>drop</action>
            </primary-action>
        </action>
    </rules>
</i2nsf-cfi-policy>
    """
    # Load additional context from I2NSF's official IETF draft
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

    # Combine all elements into the prompt
    prompt = f"""
    You are a I2NSF security policy formatter. From the provided schema that states the following policy model facts, write valid 
    I2NSF XML using ONLY the provided values in the schema.

    Here is a few examples for reference on how valid I2NSF XML looks like:
    Intent: {example_schema1}
    Policy: {example_policy_output1}

    Intent: {example_schema2}
    Policy: {example_policy_output2}

    Additional context:
    {ietf_context}

    Now, generate the XML using the provided schema:
    Schema: {resolved_schema}

    Output:
    """
    
    response = openai.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": "You are a I2NSF security policy formatter. From the provided schema that states the following policy model facts, write valid I2NSF XML using ONLY the provided values in the schema."},
            {"role": "user", "content": prompt}
        ]
    )
    
    return response.choices[0].message.content

# Example usage
# policy_text = "Block packets coming from Buenos Aires, Argentina but allow packets coming from Lima, Peru."
policy_text = "Block access to social media for all employees from 09:00 to 18:00 on weekdays, but always allow it for the marketing group and log attempts."

xml_policy = LLM_compose_policy(policy_text, model)

print("Generated XML Policy:")
print(xml_policy)