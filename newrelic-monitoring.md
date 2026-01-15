# New Relic Monitoring for Spring4Shell (CVE-2022-22965) Mitigation

## Overview
This document provides NRQL queries to monitor for Spring4Shell exploitation attempts and verify the effectiveness of the remediation.

## NRQL Queries for Monitoring

### 1. Monitor for Suspicious Request Patterns
Detect potential Spring4Shell exploitation attempts by monitoring for suspicious class.module patterns in request parameters:

```sql
SELECT count(*) 
FROM Transaction 
WHERE request.parameters.class.module IS NOT NULL 
OR request.parameters.class.classLoader IS NOT NULL
FACET appName, request.uri, request.parameters 
SINCE 1 hour ago
```

### 2. Monitor Application Error Rates
Track error rates to detect any issues post-deployment:

```sql
SELECT percentage(count(*), WHERE error IS true) 
FROM Transaction 
WHERE appName = 'InventoryManagementService' 
FACET appName 
SINCE 1 day ago 
COMPARE WITH 1 day ago
```

### 3. Monitor for Suspicious Class Access Patterns
Detect attempts to access or manipulate Java class loaders:

```sql
SELECT count(*) 
FROM Log 
WHERE message LIKE '%class.module%' 
OR message LIKE '%classLoader%' 
OR message LIKE '%ProtectionDomain%'
FACET appName, message 
SINCE 1 hour ago
```

### 4. Track HTTP 400/500 Error Spikes
Monitor for unusual spikes in 4xx/5xx errors that might indicate exploitation attempts:

```sql
SELECT count(*) 
FROM Transaction 
WHERE httpResponseCode >= 400 
AND appName = 'InventoryManagementService'
FACET httpResponseCode, request.uri 
SINCE 1 hour ago 
TIMESERIES
```

### 5. Monitor for Specific Spring4Shell Payloads
Detect known Spring4Shell exploit patterns in request data:

```sql
SELECT count(*) 
FROM Transaction 
WHERE request.uri LIKE '%class.module%' 
OR request.uri LIKE '%class.classLoader%'
OR request.parameters LIKE '%Tomcat%AccessLogValve%'
FACET appName, request.uri, request.method 
SINCE 1 hour ago
```

### 6. Application Performance Baseline
Establish performance baselines before and after the update:

```sql
SELECT average(duration), percentile(duration, 95, 99) 
FROM Transaction 
WHERE appName = 'InventoryManagementService'
FACET name 
SINCE 1 day ago 
COMPARE WITH 1 day ago 
TIMESERIES
```

## Alert Configuration Recommendations

### Critical Alert: Potential Spring4Shell Exploitation
- **Condition**: Query #1 returns results > 0
- **Threshold**: At least 1 attempt in 5 minutes
- **Priority**: Critical
- **Notification**: Immediate (PagerDuty/Slack)

### High Alert: Elevated Error Rate
- **Condition**: Query #2 shows error rate > 5% increase
- **Threshold**: Sustained for 10 minutes
- **Priority**: High
- **Notification**: Team channel

### Warning: Unusual 400/500 Error Pattern
- **Condition**: Query #4 shows spike > 50% above baseline
- **Threshold**: Sustained for 15 minutes
- **Priority**: Warning
- **Notification**: Email/Slack

## Monitoring Schedule

### First 24 Hours Post-Deployment
- Monitor all queries every 5 minutes
- Analyze patterns for false positives
- Adjust thresholds based on baseline traffic

### Ongoing Monitoring
- Monitor Query #1, #3, #5 continuously (real-time alerts)
- Run Query #2, #4, #6 daily for trend analysis
- Review logs weekly for any suspicious patterns

## Testing Verification

After deployment, verify the monitoring is working by:
1. Confirming all NRQL queries return data
2. Checking that no exploitation attempts are detected
3. Validating error rates remain stable or improved
4. Ensuring application performance metrics are within acceptable ranges

## Documentation
- All queries should be saved in New Relic's Query Library
- Alert policies should be documented in the team's runbook
- Escalation procedures should be updated with Spring4Shell-specific response steps
