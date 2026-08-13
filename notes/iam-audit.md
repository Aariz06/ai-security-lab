\# IAM Audit — Lab Account

\*\*Date:\*\* 2026-08-05 · \*\*Account:\*\* 111122223333 (redacted) · \*\*Auditor:\*\* Aariz Khan



\## Scope

All IAM users, roles, policies and credentials in the lab account.



\## Method

AWS CLI enumeration, IAM credential report, IAM Access Analyzer.

Assessed against AWS IAM best practices and CIS AWS Foundations Benchmark v3.0.



\## Findings



| ID | Finding | Severity | Evidence | CIS Ref | Remediation |

|---|---|---|---|---|---|

| IAM-01 | Customer policy `lab-overly-permissive` grants `Action:\*` on `Resource:\*` | \*\*Critical\*\* | Policy version v1 | 1.16 | Scope to specific actions and ARNs, or delete |

| IAM-02 | User `lab-service-account` has no MFA | \*\*High\*\* | Credential report, col `mfa\_active=false` | 1.10 | Enable MFA, or convert to a role |

| IAM-03 | Access key on `aariz-admin` is 4 days old with no rotation policy | Medium | `list-access-keys` | 1.14 | Rotate every 90 days |

| IAM-04 | No account password policy configured | Medium | `get-account-password-policy` returned NoSuchEntity | 1.8 | Set min length 14, complexity, reuse prevention |



