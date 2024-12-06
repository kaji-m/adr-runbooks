---
layout: default
title: Application Detection and Response Runbooks
---

# Application Detection and Response Runbooks

This repository contains detailed runbooks for responding to various security incidents detected by Contrast Security. These runbooks provide step-by-step guidance for security teams to effectively triage and respond to different types of security events.

## Available Runbooks

### Injection Attacks
- [Command Injection](runbooks/command-injection) - Handling command injection attacks attempting to execute arbitrary system commands
- [JNDI Injection](runbooks/jndi-injection) - Responding to JNDI injection attempts targeting Java applications
- [SQL Injection](runbooks/sql-injection) - Managing SQL injection attacks against database systems
- [Expression Language Injection](runbooks/expression-language-injection) - Addressing expression language injection vulnerabilities

### Access Control & Traversal
- [Path Traversal](runbooks/path-traversal) - Handling attempts to access files outside intended directories
- [HTTP Method Tampering](runbooks/http-method-tampering) - Managing unauthorized HTTP method manipulation

### Data & Parsing Vulnerabilities  
- [Cross-Site Scripting (XSS)](runbooks/cross-site-scripting) - Responding to XSS attacks injecting malicious scripts
- [XML External Entity Injection](runbooks/xml-external-entity-injection) - Handling XXE attacks against XML parsers
- [Untrusted Deserialization](runbooks/untrusted-deserialization) - Managing deserialization of untrusted data

## Using the Runbooks

1. Identify the type of security event/alert
2. Navigate to the corresponding runbook
3. Follow the decision tree to classify the event
4. Execute the recommended response procedures
5. Document actions taken and complete post-incident activities

## Contributing

See our [Contribution Guidelines](CONTRIBUTING.md) for information on how to contribute to these runbooks.