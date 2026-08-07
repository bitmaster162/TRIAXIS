# COMMON AUTHORIZATION CORPUS — E002

## Overview
The Common TRIAXIS Authorization Corpus defines 20 engine-neutral test cases covering the mandatory authorization patterns required by TRIAXIS.

Each candidate engine must attempt to translate and execute these test cases without custom glue masking semantic deficiencies.

## 20 Test Cases Summary

| ID | Case Name | Target Principal | Action | Resource | Context / Grant | Expected Decision |
|:---|:---|:---|:---|:---|:---|:---|
| **TC01** | Explicit Allow | User:alice | Action:read | Document:doc_1 | Standard valid context | `ALLOW` |
| **TC02** | Explicit Deny Overrides Allow | User:bob | Action:delete | Document:doc_1 | Explicit forbid policy active | `DENY` |
| **TC03** | No Matching Policy | User:charlie | Action:read | Document:doc_99 | Unmatched target | `DENY` |
| **TC04** | Revoked Delegation Grant | User:dave | Action:export | Report:report_10 | Grant status = REVOKED | `DENY` |
| **TC05** | Expired Delegation Grant | User:eve | Action:read | Document:doc_1 | Grant expires_at < current_time | `DENY` |
| **TC06** | Wrong Resource | User:frank | Action:read | Document:doc_2 | Frank authorized for doc_1 only | `DENY` |
| **TC07** | Wrong Action | User:grace | Action:delete | Document:doc_1 | Grace authorized for read only | `DENY` |
| **TC08** | Compound Principal — Wrong Human | Human:bob + Agent:inst_1 | Action:execute | Task:task_audit | Grant authorizes Human:alice | `DENY` |
| **TC09** | Compound Principal — Wrong Agent | Human:alice + Agent:inst_99 | Action:execute | Task:task_audit | Grant authorizes Agent:inst_1 | `DENY` |
| **TC10** | Compound Principal — Wrong Task | Human:alice + Agent:inst_1 | Action:execute | Task:export_all | Grant authorizes Task:task_audit | `DENY` |
| **TC11** | Context Condition Met | User:helen | Action:read | Document:internal_doc | Context network == internal | `ALLOW` |
| **TC12** | Context Condition Unmet | User:helen | Action:read | Document:internal_doc | Context network == external | `DENY` |
| **TC13** | ReBAC Direct Membership | User:ian | Action:read | Folder:audit_logs | User:ian member of Group:auditors | `ALLOW` |
| **TC14** | ReBAC Nested Membership | User:julia | Action:read | Folder:engineering | julia -> devops -> engineers -> folder | `ALLOW` |
| **TC15** | ReBAC Relationship Removed | User:karl | Action:read | Folder:audit_logs | Membership tuple deleted | `DENY` |
| **TC16** | Stale Policy Version | User:alice | Action:read | Document:doc_1 | Header specifies deprecated v0 | `DENY` |
| **TC17** | Policy Superseded | User:leo | Action:read | Document:legacy_doc | Target policy state = SUPERSEDED | `DENY` |
| **TC18** | Emergency Lockdown | User:alice | Action:read | Document:doc_1 | Emergency lockdown flag = true | `DENY` |
| **TC19** | Malformed Request Payload | null | Action:read | Document:doc_1 | Null principal input | `DENY` |
| **TC20** | Unavailable PDP Service | User:alice | Action:read | Document:doc_1 | PDP timeout / socket error | `DENY` |

## Corpus Definition File
Full JSON specification is stored at [`research/epoch-001/E002/corpus/triaxis_authorization_corpus.json`](file:///c:/PROJECTS/continuity_os/tmp_triaxis_closure_clone/research/epoch-001/E002/corpus/triaxis_authorization_corpus.json).
