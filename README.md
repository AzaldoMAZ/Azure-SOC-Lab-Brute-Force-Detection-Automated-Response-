Azure SOC Lab – Brute-Force Detection & Automated Response
Overview

This project demonstrates a small SOC lab built in Azure using Microsoft Sentinel to detect brute-force activity and automate incident response using Automation Rules and Azure Logic Apps.

The goal is to move from raw Windows Security Events → structured incidents → automated response.

Architecture

Data Source

Windows Security Events (Event ID 4625 – Failed Logon)

Collected via Log Analytics Agent

Ingested into Log Analytics Workspace

SIEM Layer

Microsoft Sentinel enabled on the workspace

Custom Analytics Rule (KQL-based detection)

SOAR Layer

Automation Rule (incident-triggered)

Logic Apps Playbook

Notifications via Microsoft Teams + Email

Detection Logic (KQL)

The analytics rule:

Aggregates failed logons

Groups by Account + Source IP

Uses a defined time window

Triggers when failures exceed a threshold

Example logic structure:

SecurityEvent
| where EventID == 4625
| summarize FailedAttempts = count() 
    by Account, IpAddress, bin(TimeGenerated, 5m)
| where FailedAttempts > 10
Entity Mapping

The analytics rule maps:

Account entity

IP entity

This ensures:

Incidents include attacker IP context

Automation/playbooks can extract entities dynamically

Automation Workflow
1. Automation Rule

Trigger: When incident is created
Condition: Match Analytics Rule Name (Brute-Force Detection)
Action: Run Playbook

2. Logic App Playbook

Steps:

Trigger on Sentinel incident creation

Extract IP entities

Post message to Microsoft Teams channel

Send email notification

Outputs

For each brute-force incident:

Teams notification with:

Incident ID

Severity

Affected account

Attacker IP(s)

Timestamp

Email notification with the same context

This ensures immediate triage visibility.

Why This Matters

This lab demonstrates:

Converting noisy authentication failures into structured incidents

Attaching usable entities for automation

Building a deterministic incident response pipeline

Establishing a foundation for enrichment and automated containment

Pipeline:

Telemetry → Detection → Incident → Automation Rule → Playbook → Notification

Future Enhancements

Threat intelligence enrichment

Automatic IP blocking (NSG / Firewall)

ServiceNow / ticketing integration

Geo-IP enrichment

Incident tagging & classification automation
