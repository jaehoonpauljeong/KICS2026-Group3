# from openai import OpenAI
# import os

# OPENAI_API_KEY = "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"
# client = OpenAI(api_key=OPENAI_API_KEY)
# model = "gpt-4o-mini"

# def generate_policy(policy_text, model="gpt-4o-mini"):
#     """
#     Converts natural language policy into an XML security policy.
#     Includes an example and IETF draft content for context.
#     """
#     # Examples to guide the model
#     example_input1 = "Block my son's computers from malicious websites."
#     example_output1 = """
# <?xml version="1.0" encoding="UTF-8" ?>
# <i2nsf-cfi-policy
#     xmlns="urn:ietf:params:xml:ns:yang:ietf-i2nsf-cons-facing-interface">
#     <name>block_web_security_policy</name>
#     <rules>
#         <name>block_web</name>
#         <condition>
#             <firewall-condition>
#                 <source>Son's_PC</source>
#             </firewall-condition>
#             <url-condition>
#                 <url-name>malicious_websites</url-name>
#             </url-condition>
#         </condition>
#         <actions>
#             <primary-action>
#                 <action>drop</action>
#             </primary-action>
#         </actions>
#     </rules>
# </i2nsf-cfi-policy>
#     """

#     example_input2 = "Block malicious VoIP/VoCN packets coming to a company."
#     example_output2 = """
# <?xml version="1.0" encoding="UTF-8" ?>
# <i2nsf-cfi-policy
#     xmlns="urn:ietf:params:xml:ns:yang:ietf-i2nsf-cons-facing-interface">
#     <name>
#         security_policy_for_blocking_malicious_voip_packets
#     </name>
#     <rules>
#         <name>Block_malicious_voip_and_vocn_packets</name>
#         <condition>
#             <voice>
#                 <source-id>malicious-id</source-id>
#             </voice>
#             <firewall>
#                 <destination>employees</destination>
#             </firewall>
#         </condition>
#         <action>
#             <primary-action>
#                 <action>drop</action>
#             </primary-action>
#         </action>
#     </rules>
# </i2nsf-cfi-policy>
#     """

# #     example_input3 = "Mitigate flood attacks on a company web server."
# #     example_output3 = """
# # <?xml version="1.0" encoding="UTF-8" ?>
# # <i2nsf-cfi-policy
# #     xmlns="urn:ietf:params:xml:ns:yang:ietf-i2nsf-cons-facing-interface">
# #     <name>security_policy_for_ddos_attacks</name>
# #     <rules>
# #         <name>1000_packets_per_second</name>
# #         <condition>
# #             <firewall>
# #                 <destination>webservers</destination>
# #             </firewall>
# #             <ddos>
# #                 <rate-limit>
# #                     <packet-rate-threshold>1000</packet-rate-threshold>
# #                 </rate-limit>
# #             </ddos>
# #         </condition>
# #         <action>
# #             <primary-action>
# #                 <action>drop</action>
# #             </primary-action>
# #         </action>
# #     </rules>
# # </i2nsf-cfi-policy>
# #     """

#     # Load additional context from I2NSF's official IETF draft
#     ietf_context = """
#     The I2NSF schema follows an Event-Condition-Action (ECA) model. XML policies can have the following headers:
    
#   +--rw i2nsf-cfi-policy* [name]
#   |  +--rw name                   string
#   |  +--rw language?              string
#   |  +--rw priority-usage?        identityref
#   |  +--rw resolution-strategy?   identityref
#   |  +--rw rules* [name]
#      |  +--rw name         string
#      |  +--rw priority?    uint8
#      |  +--rw event
#      |  |  +--rw system-event*   identityref
#      |  |  +--rw system-alarm*   identityref 
#      |  +--rw condition
# 	 |	|  +--rw firewall
# 		 |  |  +--rw source*                     union
# 		 |  |  +--rw destination*                union
# 		 |  |  +--rw transport-layer-protocol?   identityref
# 		 |  |  +--rw range-port-number* [start end]
# 		 |  |  |  +--rw start    inet:port-number
# 		 |  |  |  +--rw end      inet:port-number
# 		 |  |  +--rw icmp
# 		 |  |     +--rw message*   identityref
# 	 |	|  +--rw ddos
# 		 |  |  +--rw rate-limit
# 		 |  |     +--rw packet-rate-threshold?   uint64
# 		 |  |     +--rw byte-rate-threshold?     uint64
# 		 |  |     +--rw flow-rate-threshold?     uint64
# 	 |	|  +--rw anti-virus
# 		 |  |  +--rw profile*   string
# 		 |  |  +--rw exception-files*   string
# 	 |	|  +--rw payload
# 		 |  |  +--rw content*   -> /threat-prevention/payload-content/name
# 	 |	|  +--rw url-category
# 		 |  |  +--rw url-name?   -> /endpoint-groups/url-group/name
# 	 |	|  +--rw voice
# 		 |  |  +--rw source-id*        -> /endpoint-groups/voice-group/name
# 		 |  |  +--rw destination-id*   -> /endpoint-groups/voice-group/name
# 		 |  |  +--rw user-agent*       string
# 	 |  |  +--rw context
# 		 |  |  +--rw time
# 		 |  |  |  +--rw start-date-time?   yang:date-and-time
# 		 |  |  |  +--rw end-date-time?     yang:date-and-time
# 		 |  |  |  +--rw period
# 		 |  |  |  |  +--rw start-time?   time
# 		 |  |  |  |  +--rw end-time?     time
# 		 |  |  |  |  +--rw day*          day
# 		 |  |  |  |  +--rw date*         int8
# 		 |  |  |  |  +--rw month* [start end]
# 		 |  |  |  |     +--rw start    string
# 		 |  |  |  |     +--rw end      string
# 		 |  |  |  +--rw frequency?         enumeration
# 		 |  |  +--rw application
# 		 |  |  |  +--rw protocol*   identityref
# 		 |  |  +--rw device-type
# 		 |  |  |  +--rw device*   identityref
# 		 |  |  +--rw users
# 		 |  |  |  +--rw user* [id]
# 		 |  |  |  |  +--rw id      uint32
# 		 |  |  |  |  +--rw name?   string
# 		 |  |  |  +--rw group* [id]
# 		 |  |  |     +--rw id      uint32
# 		 |  |  |     +--rw name?   string
# 		 |  |  +--rw geographic-location
# 		 |  |     +--rw source
# 		 |  |     |  +--rw country?   -> /endpoint-groups/location-group/country
# 		 |  |     |  +--rw region?    -> /endpoint-groups/location-group/region
# 		 |  |     |  +--rw city?      -> /endpoint-groups/location-group/city
# 		 |  |     +--rw destination
# 		 |  |        +--rw country?   -> /endpoint-groups/location-group/country
# 		 |  |        +--rw region?    -> /endpoint-groups/location-group/region
# 		 |  |        +--rw city?      -> /endpoint-groups/location-group/city
# 	 |  |  +--rw threat-feed
# 		 |  |  +--rw name*   -> /threat-prevention/threat-feed-list/name
#      |  +--rw action
# 	 |  |  +--rw primary-action
# 		 |	|  +--rw action    identityref
# 		 |	|  +--rw limit?    decimal64
# 	 |	|  +--rw secondary-action
#          |	|  +--rw log-action?   identityref
# 	 +--rw endpoint-groups
# 	 |  +--rw user-group* [name]
# 	 |  |  +--rw name                              string
# 	 |     +--rw mac-address*                      yang:mac-address
# 	 |     +--rw (match-type)
# 		 |     +--:(ipv4)
# 		 |     |  +--rw (ipv4-range-or-prefix)?
# 		 |     |     +--:(prefix)
# 		 |     |     |  +--rw ipv4-prefix*          inet:ipv4-prefix
# 		 |     |     +--:(range)
# 		 |     |        +--rw range-ipv4-address* [start end]
# 		 |     |           +--rw start    inet:ipv4-address-no-zone
# 		 |     |           +--rw end      inet:ipv4-address-no-zone
# 		 |     +--:(ipv6)
# 		 |        +--rw (ipv6-range-or-prefix)?
# 		 |           +--:(prefix)
# 		 |           |  +--rw ipv6-prefix*          inet:ipv6-prefix
# 		 |           +--:(range)
# 		 |              +--rw range-ipv6-address* [start end]
# 		 |                 +--rw start    inet:ipv6-address-no-zone
# 		 |                 +--rw end      inet:ipv6-address-no-zone
# 	 |  +--rw device-group* [name]
# 	 |  |  +--rw name                              string
# 		|  +--rw (match-type)
# 		 |  |  +--:(ipv4)
# 		 |  |  |  +--rw (ipv4-range-or-prefix)?
# 		 |  |  |     +--:(prefix)
# 		 |  |  |     |  +--rw ipv4-prefix*          inet:ipv4-prefix
# 		 |  |  |     +--:(range)
# 		 |  |  |        +--rw range-ipv4-address* [start end]
# 		 |  |  |           +--rw start    inet:ipv4-address-no-zone
# 		 |  |  |           +--rw end      inet:ipv4-address-no-zone
# 		 |  |  +--:(ipv6)
# 		 |  |     +--rw (ipv6-range-or-prefix)?
# 		 |  |        +--:(prefix)
# 		 |  |        |  +--rw ipv6-prefix*          inet:ipv6-prefix
# 		 |  |        +--:(range)
# 		 |  |           +--rw range-ipv6-address* [start end]
# 		 |  |              +--rw start    inet:ipv6-address-no-zone
# 		 |  |              +--rw end      inet:ipv6-address-no-zone
# 		|  +--rw application-protocol*             identityref
# 	 |  +--rw location-group* [country region city]
# 	 |  |  +--rw country                           string
# 		|  +--rw region                            string
# 		|  +--rw city                              string
# 		|  +--rw (match-type)
# 		 |     +--:(ipv4)
# 		 |     |  +--rw (ipv4-range-or-prefix)?
# 		 |     |     +--:(prefix)
# 		 |     |     |  +--rw ipv4-prefix*          inet:ipv4-prefix
# 		 |     |     +--:(range)
# 		 |     |        +--rw range-ipv4-address* [start end]
# 		 |     |           +--rw start    inet:ipv4-address-no-zone
# 		 |     |           +--rw end      inet:ipv4-address-no-zone
# 		 |     +--:(ipv6)
# 		 |        +--rw (ipv6-range-or-prefix)?
# 		 |           +--:(prefix)
# 		 |           |  +--rw ipv6-prefix*          inet:ipv6-prefix
# 		 |           +--:(range)
# 		 |              +--rw range-ipv6-address* [start end]
# 		 |                 +--rw start    inet:ipv6-address-no-zone
# 		 |                 +--rw end      inet:ipv6-address-no-zone
# 	 |  +--rw url-group* [name]
# 	 |  |  +--rw name    string
# 	 |	|  +--rw url*    inet:uri
# 	 |  +--rw voice-group* [name]
# 	 |  |  +--rw name      string
# 	 |  |  +--rw sip-id*   inet:uri
# 	 +--rw threat-prevention
#      |  |  +--rw name      string
#      |  |  +--rw ioc*      string
#      |  |  +--rw format    identityref


#     """

#     # Combine all elements into the prompt
#     prompt = f"""
#     You are an expert in XML schema and I2NSF security policies. Convert the following natural language input into an XML security policy compliant with the I2NSF schema. Use the Event-Condition-Action (ECA) format and ensure the XML is valid. Use the provided example and format as context. Try to add the appropiate header to the XML depending of the needs of the user.

#     Here is a few examples for reference:
#     Input: {example_input1}
#     Output: {example_output1}

#     Input: {example_input2}
#     Output: {example_output2}

#     Additional Context:
#     {ietf_context}

#     Now, generate the XML for the following input:
#     Input: {policy_text}

#     Output:
#     """
# 	# Input: {example_input3}
#     # Output: {example_output3}
    
#     response = client.chat.completions.create(
#         model=model,
#         messages=[
#             {"role": "system", "content": "You are an XML schema and I2NSF policy expert."},
#             {"role": "user", "content": prompt}
#         ]
#     )
    
#     return response.choices[0].message.content

# # Example usage
# policy_text = "Mitigate flood attacks on a company web server."
# xml_policy = generate_policy(policy_text, model)

# print("Generated XML Policy:")
# print(xml_policy)


from openai import OpenAI
import csv

OPENAI_API_KEY = "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"
client = OpenAI(api_key=OPENAI_API_KEY)
model = "gpt-4o-mini"

def generate_policy(policy_text, model="gpt-4o-mini"):
    """
    Converts natural language policy into an XML security policy.
    Includes an example and IETF draft content for context.
    """
    # Examples to guide the model
    example_input1 = "Block my son's computers from malicious websites."
    example_output1 = """
<?xml version="1.0" encoding="UTF-8" ?>
<i2nsf-cfi-policy
    xmlns="urn:ietf:params:xml:ns:yang:ietf-i2nsf-cons-facing-interface">
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

#     example_input2 = "Block malicious VoIP/VoCN packets coming to a company."
#     example_output2 = """
# <?xml version="1.0" encoding="UTF-8" ?>
# <i2nsf-cfi-policy
#     xmlns="urn:ietf:params:xml:ns:yang:ietf-i2nsf-cons-facing-interface">
#     <name>
#         security_policy_for_blocking_malicious_voip_packets
#     </name>
#     <rules>
#         <name>Block_malicious_voip_and_vocn_packets</name>
#         <condition>
#             <voice>
#                 <source-id>malicious-id</source-id>
#             </voice>
#             <firewall>
#                 <destination>employees</destination>
#             </firewall>
#         </condition>
#         <action>
#             <primary-action>
#                 <action>drop</action>
#             </primary-action>
#         </action>
#     </rules>
# </i2nsf-cfi-policy>
#     """

#     example_input3 = "Mitigate flood attacks on a company web server."
#     example_output3 = """
# <?xml version="1.0" encoding="UTF-8" ?>
# <i2nsf-cfi-policy
#     xmlns="urn:ietf:params:xml:ns:yang:ietf-i2nsf-cons-facing-interface">
#     <name>security_policy_for_ddos_attacks</name>
#     <rules>
#         <name>1000_packets_per_second</name>
#         <condition>
#             <firewall>
#                 <destination>webservers</destination>
#             </firewall>
#             <ddos>
#                 <rate-limit>
#                     <packet-rate-threshold>1000</packet-rate-threshold>
#                 </rate-limit>
#             </ddos>
#         </condition>
#         <action>
#             <primary-action>
#                 <action>drop</action>
#             </primary-action>
#         </action>
#     </rules>
# </i2nsf-cfi-policy>
#     """

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

    # Here is a few examples for reference:
    # Input: {example_input1}
    # Output: {example_output1}

    # Input: {example_input2}
    # Output: {example_output2}
    
    # Input: {example_input3}
    # Output: {example_output3}

    # Combine all elements into the prompt
    prompt = f"""
    You are an expert in XML schema and I2NSF security policies. Convert the following natural language input into an XML security policy compliant with the I2NSF schema. Use the Event-Condition-Action (ECA) format and ensure the XML is valid. Use the provided example and format as context. Try to add the appropiate header to the XML depending of the needs of the user.

    # Here is a few examples for reference:
    # Input: {example_input1}
    # Output: {example_output1}
	
    Additional Context:
    {ietf_context}

    Now, generate the XML for the following input:
    Input: {policy_text}

    Output:

	Generate only the XML. Do not give additional text.
    """
    
    response = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": "You are an XML schema and I2NSF policy expert."},
            {"role": "user", "content": prompt}
        ]
    )
    
    return response.choices[0].message.content

if __name__ == "__main__":
	# # Example usage
	# # policy_text =  "Permit packets coming from Lima, Peru."
	# # policy_text =  "When the CPU load on the firewall is above 90%, allow only critical management traffic and rate-limit all other flows."
	policy_text =  "Permit access to Youtube, X and Instagram during school hours to all PCs within 128.0.0.0-128.0.0.255 IPv4 ranges."	
	xml_policy = generate_policy(policy_text, model)

	print("Generated XML Policy:")
	print(xml_policy)

	# input_csv = "comparison_testing_intent_dataset.csv"       # CSV with 1 column: "intent"
	# output_txt = "generated_policies_baseline.txt"

	# with open(input_csv, newline="", encoding="utf-8") as csvfile:
	# 	reader = csv.DictReader(csvfile)
		
	# 	with open(output_txt, "w", encoding="utf-8") as outfile:
	# 		for row in reader:
	# 			intent = row["intent"].strip()
	# 			if not intent:
	# 				continue
				
	# 			print(f"Generating policy for intent: {intent}")
	# 			xml_policy = generate_policy(intent, model)
				
	# 			# Write XML policy followed by two newlines
	# 			outfile.write(xml_policy + "\n\n\n\n")

	# print(f"All policies generated and saved to {output_txt}")