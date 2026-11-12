+++
format = "irmind-skill-v1"
name = "aws-credential-compromise"
description = "Review possible AWS credential misuse, privilege changes and follow-on activity in CloudTrail."
version = "0.1.0"
author = "IRMind contributors"
license = "MIT OR Apache-2.0"
target_schema = "irmind-common-event-v1"
tools = ["graph_summary", "text_search", "entity_lookup", "entity_timeline", "neighbors", "path", "raw_records", "case_add_finding"]
sources = ["parser-json"]
categories = ["authentication", "iam", "configuration", "file", "network"]
invocable = true
+++
# AWS credential compromise

## Establish coverage

Check the authorized accounts, regions and interval. Identify CloudTrail sources,
collection gaps and available event categories. Work with local case evidence;
this method declares no remote tool. Missing management or data events constrain
conclusions and must be stated explicitly.

## Investigate in order

1. Start from the reported identity or suspicious event, then inspect the original
   userIdentity, source address, user agent, event name and error fields. Keep
   account namespaces, assumed-role sessions and initiating principals distinct.
2. Review ConsoleLogin and available token or role-assumption activity around
   the event. Absence of an error field is not by itself evidence of success;
   use the source mapping and original response fields.
3. Examine credential and privilege changes such as CreateAccessKey,
   AttachUserPolicy, PutUserPolicy, AddUserToGroup and UpdateAssumeRolePolicy.
   Check actor and target resources independently. A granted permission does not
   prove the permission was exercised.
4. Follow the identity's subsequent activity across authorized regions and
   accounts. Inspect supporting records before attributing enumeration, access,
   collection or exfiltration. Shared IPs and graph edges are investigative leads.
5. Compare the suspicious sequence with plausible automation or administrator
   activity. Explain which observations support the compromise hypothesis and
   which questions remain unanswered by the collected telemetry.

## Report defensible results

Cite source hashes and record references for each claim. Use mapped category,
outcome and role filters only where coverage exists. Label hypotheses and
techniques as proposals for analyst review, and describe uncertainty. This
method neither changes scope nor authorizes containment or external enrichment.
The methodology hash identifies the method used; it is not evidence of an attack.
