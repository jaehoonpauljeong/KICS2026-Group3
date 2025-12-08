# --------- imports & clients ----------
from neo4j import GraphDatabase
from openai import OpenAI
import os, json, re, math

# ---- HARD-CODED SETTINGS (local dev only) ----
NEO4J_URI = "bolt://127.0.0.1:7687"   # try "neo4j://localhost:7687" or "bolt://localhost:7687"
NEO4J_USER = "neo4j"
NEO4J_PASSWORD = "jetwei1217"

OPENAI_API_KEY = "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"              # your key

# ---- clients ----
driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
client = OpenAI(api_key=OPENAI_API_KEY)

EMBED_MODEL = "text-embedding-3-large"    # using larger model since it classifies words in a vector space more distinctly instead of the smaller "text-embedding-3-small" model
CHAT_MODEL = "gpt-4o-mini"


# --------- utils ----------
def _strip_code_fences(s: str) -> str:
    # removes ```json ... ``` or ``` ... ```
    return re.sub(r"^```(?:json)?\s*|\s*```$", "", s.strip(), flags=re.IGNORECASE)

def _json_loose(s: str):
    s = _strip_code_fences(s)
    return json.loads(s)

def _cosine(a, b):
    # simple cosine in python (fallback if APOC not available)
    dot = sum(x*y for x,y in zip(a,b))
    na = math.sqrt(sum(x*x for x in a))
    nb = math.sqrt(sum(x*x for x in b))
    return 0.0 if na==0 or nb==0 else dot/(na*nb)

def get_text_embedding(text: str):
    emb = client.embeddings.create(model=EMBED_MODEL, input=text)
    return emb.data[0].embedding

def elementId(node):
    """Helper function to get elementId from a node"""
    return node.id if hasattr(node, 'id') else str(node)


# --------- 0) one-time: embed your KG nodes so retrieval works ----------
def bootstrap_identity_embeddings(label: str):
    with driver.session() as session:
        rows = list(session.run(f"""
            MATCH (n:Identity:{label})
            RETURN elementId(n) AS id,
                   coalesce(n.display_name,'') AS display_name,
                   coalesce(n.machine_name,'') AS machine_name,
                   coalesce(n.description,'')  AS description
        """))
        for r in rows:
            blob = " ".join([r["display_name"], r["machine_name"], r["description"]]).strip()
            if not blob:
                continue
            emb = get_text_embedding(blob)
            session.run("MATCH (n) WHERE elementId(n)=$id SET n.embedding=$emb", id=r["id"], emb=emb)

def bootstrap_all_identities():
    for lbl in ["PrimaryAction", "SecondaryAction", "SystemEvent", "SystemAlarm"]:
        bootstrap_identity_embeddings(lbl)




# --------- 1) LLM: generate structural hypothesis ----------
def LLM_generate_structural_hypothesis(intent: str):

    example_intent1 = "Block my son's computer from malicious websites."
    example_output1 = """
{
  "policy": {
    "name": "block_web_security_policy",
    "priority-usage": "priority-by-order",
    "resolution-strategy": "fmr",
    "namespace": "urn:ietf:params:xml:ns:yang:ietf-i2nsf-cons-facing-interface"
  },
  "rules": [
    {
      "name": "block_web",
      "condition": {
        "firewall": {
          "source": ["son's_computer"]
        },
        "url-category": {
          "url-name": "malicious_websites"
        }
      },
      "action": {
        "primary-action": "block"
      }
    }
  ]
}
    """


    schema_block = """
{
  "policy": {
    "name":        { "type": "string",  "required": true },
    "language":    { "type": "string",  "required": false, "default": null },
    "priority-usage": {
      "type": "enum",
      "required": false,
      "possible values": ["priority-by-order", "priority-by-number"],
      "default": "priority-by-order"
    },
    "resolution-strategy": {
      "type": "enum",
      "required": false,
      "possible values": ["fmr", "lmr", "pmre", "pmrn"],
      "default": "fmr"
    },
    "namespace": {
      "type": "constant",
      "required": true,
      "value": "urn:ietf:params:xml:ns:yang:ietf-i2nsf-cons-facing-interface"
    }
  },

  "rules": [
    {
      "name":     { "type": "string", "required": true },
      "priority": { "type": "integer", "required": false, "default": null },

      "event": {
        "system-event": { "type": "array<string:identityref>", "required": false,  "possible values": ["access-violation", "configuration-change", "session-table-event", "traffic-flows"], "default": [] },
        "system-alarm": { "type": "array<string:identityref>", "required": false, "possible values": ["memory-alarm", "cpu-alarm", "disk-alarm", "hardware-alarm", "interface-alarm"], "default": [] }
      },

      "condition": {
        "firewall": {
          "source":   { "type": "array<union>", "required": false, "default": [] },
          "destination": { "type": "array<union>", "required": false, "default": [] },
          "transport-layer-protocol": { "type": "enum", "required": false, "possible values": ["tcp", "udp", "icmp"], "default": null },
          "range-port-number": {
            "type": "array<object>",
            "required": false,
            "default": [],
            "schema": { "start": "integer (1..65535)", "end": "integer (1..65535)" }
          },
          "icmp": {
            "message": { "type": "array<string:identityref>", "required": false, "default": [] }
          }
        },

        "ddos": {
          "rate-limit": {
            "packet-rate-threshold": { "type": "integer", "required": false, "default": null },
            "byte-rate-threshold":   { "type": "integer", "required": false, "default": null },
            "flow-rate-threshold":   { "type": "integer", "required": false, "default": null }
          }
        },

        "anti-virus": {
          "profile":         { "type": "array<string>", "required": false, "default": [] },
          "exception-files": { "type": "array<string>", "required": false, "default": [] }
        },

        "payload": {
          "content": { "type": "array<ref:/threat-prevention/payload-content/name>", "required": false, "default": [] }
        },

        "url-category": {
          "url-name": { "type": "ref:/endpoint-groups/url-group/name", "required": false, "default": null }
        },

        "voice": {
          "source-id":      { "type": "string", "required": false, "default": [] },
          "destination-id": { "type": "string", "required": false, "default": [] },
          "user-agent":     { "type": "array<string>", "required": false, "default": [] },
        },

        "context": {
          "time": {
            "start-date-time": { "type": "string:ISO8601", "required": false, "default": null },
            "end-date-time":   { "type": "string:ISO8601", "required": false, "default": null },
            "period": {
              "start-time": { "type": "string:HH:MM:SSZ", "required": false, "default": null },
              "end-time":   { "type": "string:HH:MM:SSZ", "required": false, "default": null },
              "day":        { "type": "array<enum:Mon..Sun>", "required": false, "default": [] },
              "date":       { "type": "array<int:1..31>", "required": false, "default": [] },
              "month":      {
                "type": "array<object>",
                "required": false,
                "default": [],
                "schema": { "start": "string", "end": "string" }
              }
            },
            "frequency": { "type": "enum", "required": false, "default": null }
          },

          "application": { "protocol": { "type": "string", "required": false, "default": [] } },
          "device-type": { "device":   { "type": "string", "required": false, "default": [] } },

          "users": {
            "user":  { "type": "array<object>", "required": false, "default": [], "schema": { "id": "uint32", "name": "string|null" } },
            "group": { "type": "array<object>", "required": false, "default": [], "schema": { "id": "uint32", "name": "string|null" } }
          },

          "geographic-location": {
            "source": {
              "country": { "type": "string", "required": false, "default": null },
              "region":  { "type": "string",  "required": false, "default": null },
              "city":    { "type": "string",    "required": false, "default": null }
            },
            "destination": {
              "country": { "type": "string", "required": false, "default": null },
              "region":  { "type": "string",  "required": false, "default": null },
              "city":    { "type": "string",    "required": false, "default": null }
            }
          }
        },

        "threat-feed": {
          "name": { "type": "string", "required": false, "default": [] }
        }
      },

      "action": {
        "primary-action": { "type": "string:identityref", "required": true },
        "limit":          { "type": "number", "required": false, "default": null },

        "secondary-action": {
          "type": "object",
          "required": false,
          "default": null,
          "schema": {
            "log-action": { "type": "string:identityref", "required": false, "default": null }
          }
        }
      }
    }
  ]
}
"""

# You are an expert in XML schema and I2NSF security policies. Analyze the context and extract raw strings from the following natural 
# language input into a hypothesis JSON schema that will later be used to craft as a XML security policy compliant with the I2NSF 
# schema. Use the Event-Condition-Action (ECA) format. Use the provided example and hypothesis JSON schema format as context. 

# Ensure you conform to the structure and instructions provided in the schema, and add the appropiate strings to the correct slots
# from the natural language input in the hypothesis JSON schema depending of the needs of the user.
    prompt = f"""
You are an intent parsing engine for a network security policy system. Your sole purpose is to interpret, analyze and extract raw 
strings from a user's natural language intent, and output a hypothesis JSON schema that maps their words to the correct slots in the policy 
schema based on the context of the intent. Your output must conform to the structure and instructions provided in the schema.

You are also an expert in the I2NSF Consumer-Facing Interface (CFI) YANG data model.

Hypothesis JSON schema:
{schema_block}

Note: If event.system-event or event.system-alarm is present in the schema, output them only inside an <event> block (never inside <condition>).

Examples:
1. Intent: {example_intent1}
   Hypothesis JSON schema: {example_output1}

Now produce the hypothesis JSON schema for:
Intent: {intent}
"""

    resp = client.chat.completions.create(
        model=CHAT_MODEL,
        messages=[
            {"role":"system","content":"You are an XML schema and I2NSF policy expert."},
            {"role":"user","content":prompt}
        ],
        temperature=0
    )
    return _json_loose(resp.choices[0].message.content)


# --------- 2) KG retrieval (fixed Cypher + optional vector scoring) ----------
def retrieve_schema_slots_from_knowledge_graph(raw_text: str, target_labels: list, top_k: int = 3, use_apoc: bool = True):
    """
    Searches nodes with the given labels by:
      - substring match over name/display_name/machine_name
      - lexeme hits
      - (optional) cosine with stored `embedding` using APOC
    """
    labels_str = ":".join(target_labels)
    query = f"""
    MATCH (candidate:{labels_str})
    OPTIONAL MATCH (candidate)<-[:REFERS_TO]-(l:Lexeme)
    WITH candidate, collect(l.text) AS lexes
    WITH candidate, lexes,
         toLower(coalesce(candidate.name,'')) AS nm,
         toLower(coalesce(candidate.display_name,'')) AS dn,
         toLower(coalesce(candidate.machine_name,'')) AS mn
    WITH candidate, lexes, nm, dn, mn,
         (nm CONTAINS toLower($raw_text) OR
          dn CONTAINS toLower($raw_text) OR
          mn CONTAINS toLower($raw_text) OR
          any(x IN lexes WHERE toLower(x) CONTAINS toLower($raw_text))) AS hit
    WHERE hit
    RETURN candidate, candidate.embedding AS embedding, lexes, nm, dn, mn
    """
    
    with driver.session() as session:
        rows = list(session.run(query, raw_text=raw_text))

    if not rows:
        print(f"No results found for '{raw_text}' with labels {target_labels}")
        return []

    # Log initial retrieval results
    print(f"\n=== RETRIEVAL LOG for '{raw_text}' ({target_labels}) ===")
    print(f"Initial matches found: {len(rows)}")
    
    for i, r in enumerate(rows):
        node = r["candidate"]
        lexes = r["lexes"]
        print(f"  Match {i+1}: {node.get('name', 'N/A')} (id: {elementId(node)})")
        print(f"    Names: name='{r['nm']}', display='{r['dn']}', machine='{r['mn']}'")
        print(f"    Lexemes: {lexes if lexes else 'None'}")

    # Calculate query embedding and rank results
    q_emb = get_text_embedding(raw_text)
    scored = []
    
    for r in rows:
        node = r["candidate"]
        emb = r["embedding"]
        sim = _cosine(q_emb, emb) if emb else 0.0
        
        # Collect all relevant text for this node
        node_texts = [
            r['nm'], r['dn'], r['mn']
        ] + (r["lexes"] or [])
        node_texts = [t for t in node_texts if t]  # Remove empty strings
        
        scored.append({
            "node": dict(node), 
            "score": sim,
            "texts": node_texts,
            "raw_node": node  # Keep the original node for logging
        })

    # Sort by similarity score
    scored.sort(key=lambda x: x["score"], reverse=True)
    
    # Log scoring results
    print(f"\nCosine similarity ranking results:")
    for i, item in enumerate(scored):
        node = item["raw_node"]
        print(f"  Rank {i+1}: score={item['score']:.4f}")
        print(f"    Node: {node.get('name', 'N/A')} (id: {elementId(node)})")
        print(f"    Node's embedding was generated from this text: {item['texts']}")
    
    print(f"Top {top_k} results selected")
    print("=== END RETRIEVAL LOG ===\n")
    
    return scored[:top_k]


# --------- 3) simple resolver using KG ----------
def resolve_primary_action(user_value: str, verbose: bool = True):
    return resolve_identity_value("PrimaryAction", user_value, verbose)

def resolve_secondary_action(user_value: str, verbose: bool = True):
    return resolve_identity_value("SecondaryAction", user_value, verbose)

def resolve_system_event(user_value: str, verbose: bool = True):
    return resolve_identity_value("SystemEvent", user_value, verbose)

def resolve_system_alarm(user_value: str, verbose: bool = True):
    return resolve_identity_value("SystemAlarm", user_value, verbose)

def _dedupe_preserve(seq):
    seen, out = set(), []
    for x in seq:
        if x not in seen:
            out.append(x); seen.add(x)
    return out

def resolve_list_logged(values, resolver_fn, banner: str):
    """Resolve a list of identityrefs with pretty logging like Primary/Secondary."""
    values = values or []
    if not values:
        return []

    out = []
    for v in values:
        r = resolver_fn(v, verbose=True)  # <-- prints the nice table for each value
        if r:
            out.append(r["machine_name"])

    return _dedupe_preserve(out)

def resolve_identity_value(label: str, user_value: str, verbose: bool = True):
    """
    Resolve a free-text identityref to canonical machine_name using your KG:
      1) Exact machine_name match (case-insensitive).
      2) Else cosine rank over all (:Identity:<Label>) embeddings.

    Prints a consistent retrieval table for BOTH cases.
    Returns: dict with machine_name, display_name, description, _match, _score (or None)
    """
    val = (user_value or "").strip().lower()

    def _print_header():
        if verbose:
            print(f"\n--- {label} Retrieval ---")
            print(f"Query: '{user_value}'")
            print("------------------------------------------------------------------------")

    def _print_rows(rows):
        # rows: list of dicts {machine_name, display_name, score, reason}
        if not verbose:
            return
        # Align with your other tables
        print(f"{'Rank':<4} {'machine_name':<22} {'display_name':<28} {'score':>8}  reason")
        print("------------------------------------------------------------------------")
        for i, r in enumerate(rows, start=1):
            score_str = "—" if r["score"] is None else f"{r['score']:.4f}"
            print(f"{i:<4} {r['machine_name']:<22} {r['display_name']:<28} {score_str:>8}  {r['reason']}")
        # No footer line here; keep consistent with your examples

    with driver.session() as session:
        # 1) Direct machine_name match
        rec = session.run(f"""
            MATCH (n:Identity:{label})
            WHERE toLower(n.machine_name) = $v
            RETURN elementId(n) AS id, n AS node
            LIMIT 1
        """, v=val).single()

        if rec:
            node = dict(rec["node"])
            node["_element_id"] = rec["id"]
            node["_match"] = "direct_machine_name"
            node["_score"] = None

            _print_header()
            _print_rows([{
                "machine_name": node.get("machine_name", ""),
                "display_name": node.get("display_name", ""),
                "score": None,  # em dash in printout
                "reason": "direct"
            }])
            if verbose:
                print(f"Selected: {node.get('machine_name')}  (reason: direct_machine_name)")
            return node

        # 2) Cosine over all candidates
        rows = list(session.run(f"""
            MATCH (n:Identity:{label})
            RETURN elementId(n) AS id, n AS node, n.embedding AS emb
        """))

    if not rows:
        if verbose:
            _print_header()
            print(f"No Identity:{label} nodes found.")
        return None

    q_emb = get_text_embedding(val)
    def _cos_or_0(e): return _cosine(q_emb, e) if e else 0.0

    scored = []
    for r in rows:
        node = dict(r["node"])
        score = float(_cos_or_0(r["emb"]))
        scored.append({"id": r["id"], "node": node, "score": score})

    scored.sort(key=lambda x: x["score"], reverse=True)
    best = scored[0]["node"]
    best["_element_id"] = scored[0]["id"]
    best["_match"] = "cosine_embedding"
    best["_score"] = scored[0]["score"]

    # Print top-N table (matches your Primary/Secondary look)
    if verbose:
        _print_header()
        table_rows = [{
            "machine_name": s["node"].get("machine_name", ""),
            "display_name": s["node"].get("display_name", ""),
            "score": s["score"],
            "reason": "cosine"
        } for s in scored[:9]]
        _print_rows(table_rows)
        print(f"Selected: {best.get('machine_name')}  (reason: cosine_embedding, score={best['_score']:.4f})")

    return best


def resolve_hypothesis_actions_and_events(hypothesis):
    resolved = json.loads(json.dumps(hypothesis))  # deep copy
    rule = resolved.setdefault("rules", [{}])[0]
    act  = rule.setdefault("action", {})

    # --- Normalize legacy secondary/log shapes coming from hypothesis ---
    # legacy: action["log-action"] -> new nested under secondary-action
    if "log-action" in act and isinstance(act["log-action"], str):
        act["secondary-action"] = {"log-action": act["log-action"]}
        del act["log-action"]

    # legacy: action["secondary-action"] is a string -> wrap into object
    if "secondary-action" in act and isinstance(act["secondary-action"], str):
        act["secondary-action"] = {"log-action": act["secondary-action"]}

    # --- Primary action (existing) ---
    try:
        primary_in = (hypothesis.get("rules", [{}])[0].get("action", {}).get("primary-action")
                      or hypothesis.get("rules", [{}])[0].get("action", {}).get("primary"))
        if primary_in is not None:
            cand = resolve_primary_action(primary_in, verbose=True)
            if cand:
                act["primary-action"] = cand.get("machine_name", primary_in)
                # drop legacy key if present
                if "primary" in rule.get("action", {}):
                    del rule["action"]["primary"]
    except Exception as e:
        print(f"[warn] primary-action resolution failed: {e}")

    # --- Secondary / Log action (write ONLY nested form) ---
    try:
        # read from the ORIGINAL hypothesis (accept either place)
        hyp_action = hypothesis.get("rules", [{}])[0].get("action", {}) if hypothesis.get("rules") else {}
        log_in = None
        # nested form?
        sa_h = hyp_action.get("secondary-action")
        if isinstance(sa_h, dict):
            log_in = sa_h.get("log-action")
        # flat legacy keys as fallback
        if log_in is None:
            log_in = hyp_action.get("log-action")
        if log_in is None and isinstance(hyp_action.get("secondary-action"), str):
            log_in = hyp_action.get("secondary-action")

        if log_in:
            cand = resolve_secondary_action(log_in, verbose=True)
            if cand:
                act.setdefault("secondary-action", {})
                act["secondary-action"]["log-action"] = cand["machine_name"]
                # ensure no flat duplicates exist
                if "log-action" in act:
                    del act["log-action"]
    except Exception as e:
        print(f"[warn] secondary/log-action resolution failed: {e}")

    # --- Events: system-event*, system-alarm* (arrays) ---
    try:
        ev_in = hypothesis.get("rules", [{}])[0].get("event", {}) if hypothesis.get("rules") else {}
        want_events = ev_in.get("system-event") or []
        want_alarms = ev_in.get("system-alarm") or []

        # Only print logs for what’s actually present
        ev_resolved = resolve_list_logged(want_events, resolve_system_event,  "SYSTEM-EVENT") if want_events else []
        al_resolved = resolve_list_logged(want_alarms, resolve_system_alarm, "SYSTEM-ALARM") if want_alarms else []

        if ev_resolved or al_resolved:
            rule.setdefault("event", {})
            if ev_resolved:
                rule["event"]["system-event"] = ev_resolved
            if al_resolved:
                rule["event"]["system-alarm"] = al_resolved
    except Exception as e:
        print(f"[warn] event/alarm resolution failed: {e}")

    return resolved


# --------- 4) compose final XML ----------
def LLM_compose_policy(resolved_schema: dict, model=CHAT_MODEL):
    # Examples to guide the model
    example1 = """
  <?xml version="1.0" encoding="UTF-8" ?>
  <i2nsf-cfi-policy
   xmlns="urn:ietf:params:xml:ns:yang:ietf-i2nsf-cons-facing-interface">
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

    example2 = """
 <?xml version="1.0" encoding="UTF-8" ?>
 <i2nsf-cfi-policy
   xmlns="urn:ietf:params:xml:ns:yang:ietf-i2nsf-cons-facing-interface">
   <name>security_policy_for_ddos_attacks</name>
   <rules>
     <name>1000_packets_per_second</name>
     <condition>
       <firewall>
         <destination>webservers</destination>
       </firewall>
       <ddos>
         <rate-limit>
           <packet-rate-threshold>1000</packet-rate-threshold>
         </rate-limit>
       </ddos>
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

    prompt = f"""
You are an I2NSF security policy formatter. Using ONLY the provided schema values, output valid I2NSF XML. If a particularly field
in the schema is null or an empty list, omit it in the output I2NSF XML.

Schema (JSON):
{json.dumps(resolved_schema, ensure_ascii=False, indent=2)}

Here is a few examples of valid I2NSF XML for reference:
Input: {example1}

Input: {example2}

Additional context: 
- {ietf_context}
- Always use the following namespace in the root <i2nsf-cfi-policy> element: "xmlns="urn:ietf:params:xml:ns:yang:ietf-i2nsf-cons-facing-interface". Do not invent or use other namespaces.

Output the XML only.
"""
    resp = client.chat.completions.create(
        model=model,
        messages=[
            {"role":"system","content":"Return only XML. No extra text."},
            {"role":"user","content":prompt}
        ],
        temperature=0
    )
    return _strip_code_fences(resp.choices[0].message.content)


# --------- 5) Orchestrate end-to-end ----------
def run_pipeline(intent: str):
    # Ensure nodes have embeddings (first run or after graph changes)
    bootstrap_all_identities()

    hypothesis = LLM_generate_structural_hypothesis(intent)
    resolved   = resolve_hypothesis_actions_and_events(hypothesis)
    xml        = LLM_compose_policy(resolved)
    return hypothesis, resolved, xml


# --------- EXAMPLE ----------
if __name__ == "__main__":
    # intent = "Block packets coming from Buenos Aires, Argentina but allow packets coming from Lima, Peru."
    # intent = "Block access to social media for all employees from 09:00 to 18:00 on weekdays, but always allow it for the marketing group and log attempts."
    # intent = "Permit packets coming from Lima, Peru."
    # intent =  "When the CPU load on the firewall is above 90%, allow only critical management traffic and rate-limit all other flows."
    # intent = "Mitigate Flood Attacks on a Company Web Server."
    intent = "Restrict access to adult content from all devices."

    hypo, resolved, xml = run_pipeline(intent)

    print("\n--- Hypothesis ---")
    print(json.dumps(hypo, indent=2))
    print("\n--- Resolved ---")
    print(json.dumps(resolved, indent=2))
    print("\n--- XML ---")
    print(xml)