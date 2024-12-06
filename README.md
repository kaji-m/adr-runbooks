# Security Incident Response Runbooks

This repository contains detailed runbooks for responding to various security incidents detected by Contrast Security. These runbooks provide step-by-step guidance for security teams to effectively triage and respond to different types of security events.

## Available Runbooks

### Injection Attacks
- [Command Injection](runbooks/Command%20Injection%20RunBook.md) - Handling command injection attacks attempting to execute arbitrary system commands
- [JNDI Injection](runbooks/JNDI%20Injection%20RunBook.md) - Responding to JNDI injection attempts targeting Java applications
- [SQL Injection](runbooks/SQL%20Injection%20RunBook.md) - Managing SQL injection attacks against database systems
- [Expression Language Injection](runbooks/Expression%20Language%20Injection%20RunBook.md) - Addressing expression language injection vulnerabilities

### Access Control & Traversal
- [Path Traversal](runbooks/Path%20Traversal%20RunBook.md) - Handling attempts to access files outside intended directories
- [HTTP Method Tampering](runbooks/HTTP%20Method%20Tampering%20RunBook.md) - Managing unauthorized HTTP method manipulation

### Data & Parsing Vulnerabilities  
- [Cross-Site Scripting (XSS)](runbooks/Cross-Site%20Scripting%20(XSS)%20RunBook.md) - Responding to XSS attacks injecting malicious scripts
- [XML External Entity Injection](runbooks/XML%20External%20Entity%20Injection%20RunBook.md) - Handling XXE attacks against XML parsers
- [Untrusted Deserialization](runbooks/Untrusted%20Deserialization%20RunBook.md) - Managing deserialization of untrusted data

## Runbook Structure

Each runbook follows a consistent format:
- Description of the vulnerability/attack
- Example events showing different outcomes (Exploited, Blocked, etc)
- Decision tree for triaging the event type
- Detailed response procedures based on outcome
- False positive handling
- Post-incident activities

## Using the Runbooks

1. Identify the type of security event/alert
2. Navigate to the corresponding runbook
3. Follow the decision tree to classify the event
4. Execute the recommended response procedures
5. Document actions taken and complete post-incident activities
