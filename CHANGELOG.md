# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Security
- **CRITICAL**: Upgraded Spring Boot from 2.5.10 to 2.5.12 to mitigate CVE-2022-22965 (Spring4Shell)
  - This upgrade brings Spring Framework from 5.3.16 to 5.3.18
  - CVE-2022-22965 is a critical Remote Code Execution (RCE) vulnerability affecting Spring Framework versions prior to 5.2.20 and 5.3.18
  - Applications running on JDK 9+ with Apache Tomcat as WAR deployment were at risk
  - The vulnerability has been mitigated by upgrading to the patched version
  - Date: 2026-01-21
