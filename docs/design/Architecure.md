# Sharingan – Architecture Overview

This document describes the **high-level architecture** of the Sharingan project.

The design emphasizes **modularity, transparency, and human control**, ensuring the AI assists rather than replaces the red-team operator.

---

## Architectural Principles

- Human-in-the-loop decision making  
- Modular and extensible components  
- Controlled tool execution  
- Structured data flow  
- Auditability and traceability  

---

## High-Level Architecture

[ Operator ]
     |
[ CLI Interface ]
     |
[ AI Orchestrator ]
     |
[ Task Planner ]
     |
[ Tool Abstraction Layer ]
     |
[ Tool Outputs (JSON) ]
     |
[ Result Normalizer ]
     |
[ Report Generator ]

---

## Component Description

### CLI Interface
- Entry point for the operator  
- Accepts scope, targets, and configuration  
- Displays summarized results  

### AI Orchestrator
- Assists in task selection and sequencing  
- Summarizes and correlates results  
- Does **not** make autonomous attack decisions  

### Task Planner
- Maps objectives to predefined workflows  
- Enforces scope and execution rules  

### Tool Abstraction Layer
- Wraps traditional security tools  
- Prevents raw command execution by AI  
- Ensures consistent output format  

### Result Normalizer
- Converts tool outputs into structured JSON  
- Enables correlation and reporting  

### Report Generator
- Produces human-readable reports  
- Supports Markdown (future: PDF)  

---

## Security & Safety Constraints

- No direct shell access for AI components  
- Operator approval required for all actions  
- Clear separation between analysis and execution  

---

## Architectural References

- MITRE CALDERA (architectural inspiration)  
  https://caldera.mitre.org/  

- NIST SP 800-115  
  https://csrc.nist.gov/publications/detail/sp/800-115/final  

- NIST AI Risk Management Framework  
  https://www.nist.gov/itl/ai-risk-management-framework  
