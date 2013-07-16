This a general information security policy meant to meet the EXACT requirements of the PCI-DSS. No more, no less, but still flexible for your organization.



# Information Security Policy for PCI #

The Information Security Policy helps to protect the confidentiality, integrity, and availability of information and information systems.

##Table of Contents##


- [Roles and Responsibilities](#roles-and-responsibilities)
    - [Security team](#security-team)
    - [Operations team](#operations-team)
    - [Engineering team](#engineering-team)
    - [Human Resources team](#human-resources-team)
    - [Personnel](#personnel)
- [Data management policy](#data-management-policy)
    - [Data Labeling And Marking](#data-labeling-and-marking)
    - [Data Access](#data-access)
    - [Data Storage](#data-storage)
    - [Data Sanitization And Disposal](#data-sanitization-and-disposal)
    - [Data Privacy](#data-privacy)
- [Access management policy](#access-management-policy)
    - [Account Management](#account-management)
    - [Access Enforcement](#access-enforcement)
    - [Separation Of Duties](#separation-of-duties)
    - [Least Privilege](#least-privilege)
    - [Unsuccessful Login Attempts](#unsuccessful-login-attempts)
    - [Remote Access](#remote-access)
- [Identification and Authentication management policy](#identification-and-authentication-management-policy)
    - [User Identification And Authentication](#user-identification-and-authentication)
    - [Identifier Management](#identifier-management)
    - [Authenticator Management](#authenticator-management)
    - [Cryptographic Key Establishment And Management](#cryptographic-key-establishment-and-management)
- [Audit management policy](#audit-management-policy)
    - [Auditable Events](#auditable-events)
    - [Content Of Audit Records](#content-of-audit-records)
    - [Audit Monitoring, Analysis, And Reporting](#audit-monitoring-analysis-and-reporting)
    - [Audit Reduction, Report Generation, And Protection](#audit-reduction-report-generation-and-protection)
    - [Audit Record Retention And Storage](#audit-record-retention-and-storage)
    - [Time Stamps](#time-stamps)
    - [Information System Monitoring Tools And Techniques](#information-system-monitoring-tools-and-techniques)
- [Risk management policy](#risk-management-policy)
    - [Risk Assessment](#risk-assessment)
    - [Security Alerts And Advisories](#security-alerts-and-advisories)
    - [Vulnerability Scanning](#vulnerability-scanning)
    - [Penetration Testing](#penetration-testing)
- [Incident management policy](#incident-management-policy)
    - [Incident Response Training And Testing](#incident-response-training-and-testing)
    - [Incident Handling](#incident-handling)
    - [Incident Monitoring And Reporting](#incident-monitoring-and-reporting)
    - [Incident Response Assistance](#incident-response-assistance)
- [Application management policy](#application-management-policy)
    - [Life Cycle Support](#life-cycle-support)
    - [Security Engineering Principles](#security-engineering-principles)
    - [Developer Security Testing](#developer-security-testing)
    - [Developer Change Control](#developer-change-control)
- [Change management policy](#change-management-policy)
    - [Configuration Change Control](#configuration-change-control)
    - [Monitoring Configuration Changes](#monitoring-configuration-changes)
    - [Access Restrictions For Change](#access-restrictions-for-change)
    - [Flaw Remediation](#flaw-remediation)
- [Configuration management policy](#configuration-management-policy)
    - [Baseline Configuration](#baseline-configuration)
    - [Configuration Settings](#configuration-settings)
    - [Least Functionality](#least-functionality)
    - [Information System Recovery And Reconstitution](#information-system-recovery-and-reconstitution)
- [Network management policy](#network-management-policy)
    - [Boundary Protection](#boundary-protection)
    - [Information Flow Enforcement](#information-flow-enforcement)
    - [Wireless Access Restrictions](#wireless-access-restrictions)
    - [Information System Documentation](#information-system-documentation)
    - [External Information System Services](#external-information-system-services)
    - [Transmission Integrity And Confidentiality](#transmission-integrity-and-confidentiality)
    - [Session Termination](#session-termination)
- [Personnel management policy](#personnel-management-policy)
    - [Security Awareness](#security-awareness)
    - [Security Training](#security-training)
    - [Personnel Screening](#personnel-screening)
    - [Personnel Termination](#personnel-termination)
    - [Personnel Transfer](#personnel-transfer)
    - [Personnel Sanctions](#personnel-sanctions)
    - [Access Agreements](#access-agreements)
- [Acceptable Use Policy](#acceptable-use-policy)
    - [Rules Of Behavior](#rules-of-behavior)
- [Definitions](#definitions)


##Roles and Responsibilities##
Roles and responsibilities lists a top level breakdown of the duties and permissions assigned to each role in the organization.

###Security team###
   *  Establish, document, and distribute security policies and procedures
   *  Create and distribute security incident response and escalation procedures.
   *  Monitor and analyze security alerts and information, and distribute to appropriate personnel
   *  Provide appropriate security training
   *  Act as the Primary Point of Contact for incidents

###Operations team###
   *  Applying policies and procedures when and where appropriate.
   *  Distribute secret shards
   *  Follow Daily Operational Procedures

###Engineering team###
   *  Follow security engineering principles
   *  Responsible that all application security controls are added to the application design.
   *  Coordinates security specialist and developers
   *  Ensures that the products meet (security) specifications

###Human Resources team###
   *  Ensure the Information Security Policy is distributed to all employees, contractors, vendors and         partners.
   *  Work with Security to formulate sanctions and other disciplinary actions involving violations of security policies.
   *  Work with Security to distribute security information awareness and education materials to employees.
   *  Coordinate employee hiring with Operations.

###Personnel###
   *  Assist the organization in meetings its business goals by understanding that their actions have real              consequences. Personnel must act accordingly, especially when it pertains to information security policy.
   *  Avoid distributing restricted or sensitive information
   *  Maintain an understanding of current information security policies.


## Data management policy ##
The Data management policy ensures that the integrity of the data is
maintained, risk associated with data retention is reduced, and loss
of data is prevented.

### Data Labeling And Marking ###
**Personnel** label information indicating the distribution
limitations, handling caveats, and applicable security
markings. Information labeling is accomplished in accordance with: (i)
access control requirements; and (ii) special dissemination, handling,
or distribution requirements. **Personnel** mark information using
standard naming conventions to identify data sensitivity, special
dissemination, and handling distribution instructions. Labeling and
marking are not required for information determined to be Public,
Private, or Restricted.

These naming conventions are :

*  Public: information (e.g. blog posts) that would not cause any effects to the organization;
*  Private: information (e.g. policies and procedures, meeting notes, and quarterly goals) that would cause undesirable effects, if publicly available;
*  Restricted: information (e.g. financial statements, employment records, and secret shards) that would cause damage or be prejudicial, if publicly available;
*  Sensitive: information (e.g. cardholders data) that would cause serious damage, if publicly available.


### Data Access ###
**Operations** restricts access to **sensitive** information system data to
authorized personnel. **Operations** authorizes, monitors, and controls
all methods of data access to the information system. **Operations**
employs automated mechanisms to (i) facilitate the monitoring and
control of data access methods; (ii) restrict access to data storage
areas; and (iii) audit access attempts and access granted.

### Data Storage ###
**Operations** controls and securely stores **sensitive** information system
data within controlled areas for no more then **3 months** (unless
required for business reasons). **Sensitive** information at rest is
routinely encrypted. **Operations** develops, documents, and maintains a
current inventory of **sensitive** information system data and updates the
inventory **every 1 year**.

### Data Sanitization And Disposal ###
Sanitization is the process used to remove information from
information systems such that there is reasonable assurance, in
proportion to the confidentiality of the information, that the
information cannot be retrieved or reconstructed. Sanitization and
disposal techniques (e.g. clearing, purging, and destroying data
information) prevent the disclosure of organizational information to
unauthorized individuals. **Operations** employs automated mechanisms to
sanitize **sensitive** information system data older than **3
months**. **Operations** tracks, documents, and verifies data sanitization
and disposal actions. *Data management procedure* specifies methods for
performing tasks on secure disposal of data.

### Data Privacy ###
The information system obscures feedback of **sensitive** information
system data (e.g. PANs) to protect the information from possible
exploitation/use by unauthorized individuals. *Tokenization Process*
describes how **sensitive** information system data is protected.

## Access management policy ##
The Access management policy ensures that only authorized users are
granted the right to use a service and that privileges are separated
into functional roles.

### Account Management ###
**Operations** manages information system accounts, including
establishing, activating, modifying, reviewing, disabling, and
removing accounts. **Operations** reviews **sensitive** information system
accounts **every 1 year**. Account management includes the identification
of account types (e.g. individual, group, and system), establishment
of conditions for group membership, and assignment of associated
authorizations. **Operations** identifies authorized users of the
information system and specifies access rights/privileges. **Operations**
grants access to the information system based on: (i) a valid
need-to-know that is determined by assigned official duties and
satisfying all personnel security criteria; and (ii) intended system
usage. **Operations** requires proper identification for requests to
establish information system accounts and approves such
requests. **Operations** prohibits and restricts the use of shared
information system accounts (e.g., guest, anonymous accounts) and
removes, disables, or otherwise secures unnecessary accounts on
**sensitive** information systems **every 3 months**. **Operations** is notified
when information system users are terminated or transferred and
associated accounts are removed, disabled, or otherwise
secured. **Operations** is notified when users information system usage or
need-to-know changes. **Operations** employs automated mechanisms
(e.g. configuration management tools) to support the management of
information system accounts, including audit account creation,
modification, disabling, termination actions, and notifying
appropriate individuals.

### Access Enforcement ###
**Operations** employs access control policies (e.g., identity-based
policies, rule-based policies) and associated access enforcement
mechanisms (e.g., password authentication, access control lists) to
automatically control access between users (or processes acting on
behalf of users) and objects (e.g., devices, files, records,
processes, programs, domains) in the information system. In addition,
access enforcement mechanisms are employed at the application level,
when necessary, to provide increased information
security. Consideration is given to the implementation of a
controlled, audited, and manual override of automated mechanisms in
the event of emergencies or other serious events. Access to privileged
functions and security-relevant information is restricted to
explicitly authorized personnel (e.g. **Operations**, **Security**).

### Separation Of Duties ###
**Operations** establishes appropriate divisions of responsibility and
separates duties as needed to eliminate conflicts of interests in the
responsibilities and duties of personnel. Separation of duties is
enforced through assigned access authorizations by the information
system. There is access control software on the information system
that prevents users from having all of the necessary authority or
information access to perform fraudulent activity without
collusion. Examples of separation of duties include: (i) mission
functions and distinct information system support functions are
divided among **Operations**, **Engineering**, and **Security**; and (ii)
different teams perform information system support functions (e.g.,
systems programming and systems management).

### Least Privilege ###
The most restrictive set of rights/privileges or accesses need by
users (or processes acting on behalf of users) are enforced for the
performance of specified tasks.

### Unsuccessful Login Attempts ###
A limit of **6** consecutive invalid access attempts by a user is enforced
by the **sensitive** information system. Unless released by an
administrator, the information system automatically locks the account
for **30 minutes** and delays the next login prompt when the maximum
number of unsuccessful attempts is exceeded.

### Remote Access ###
**Operations** authorizes, monitors, and controls all methods of remote
access to the information system. Remote access controls are
applicable to information systems other than public web servers or
systems specifically designed for public access. **Operations** restricts
access achieved and protects against unauthorized connections
(e.g. using virtual private network technology). **Operations** employs
automated mechanisms to facilitate the monitoring and control of
remote access methods. Cryptography is used to protect the
confidentiality and integrity of remote access sessions. All remote
accesses are controlled through a limited number of managed access
control points. For vendor access, **Operations** (i) permits remote
access for privileged functions only for compelling operational needs;
(ii) documents the rational for such access; and (iii) immediately
deactivates access after operational needs have been met.


## Identification and Authentication management policy ##
The Identification and Authentication management policy ensures that
privileged access to assets and services is controlled using industry
standard security mechanisms.

### User Identification And Authentication ###
Users (e.g. **Personnel**) or processes acting on behalf of users are
uniquely identified and authenticated by the information system for
all accesses explicitly documented by **Human Resources** and
**Security**. Authentication of user identities is accomplished through
the use of passwords, cryptographic keys, tokens, or some combination
thereof for multifactor authentication. **Sensitive** information systems
implement multifactor authentication for remote and local accesses at
the application level or information system level (e.g. system
logins).

### Identifier Management ###
**Operations** manages user identifiers by: (i) uniquely identifying each
user; (ii) verifying the identity of each user; (iii) receiving
authorization to issue a user identifier from **Human Resources** or
**Security**; (iv) issuing the user identifier to the intended party; (v)
disabling or removing the user identifier after **3 months** of
inactivity; and (vi) archiving user identifiers.

### Authenticator Management ###
**Operations** manages information system authenticators (e.g. passwords,
cryptographic keys, tokens) by: (i) defining unique initial
authenticator content; (ii) implementing administrative procedures for
initial authenticator distribution, for lost/compromised, or damaged
authenticators, and for revoking authenticators; (iii) changing
authenticators upon information system installation; and (iv)
changing/refreshing authenticators periodically. For password-based
authentication, the information system: (i) protects passwords from
unauthorized disclosure and modification when stored and transmitted;
(ii) prohibits passwords from being displayed when entered; (iii)
enforces password uniqueness containing both **numeric and alphabetic**
characters; (iv) enforces password minimum length of **7 characters**; (v)
enforces password maximum lifetime restrictions of **3 months**; and (vi)
prohibits password reuse for **4 generations**. For public-key
authentication, the information system: (i) establishes user control
of the corresponding private key; and (ii) maps the authenticated
identity to the user account.

### Cryptographic Key Establishment And Management ###
**Operations** establishes and manages **sensitive** cryptographic keys using
automated mechanisms with supporting procedures. **Operations** implements
strong cryptography and effective cryptographic key management in
support of encryption and provides protections to maintain the
availability of the **sensitive** information in the event of the loss of
cryptographic keys. **Operations** changes **sensitive** cryptographic keys
(i) **every 1 year**; (ii) when cryptographic keys are lost, compromised;
and (iii) when individuals are transferred/terminated. Public key
certificates are obtained from an approved service provider or issued
by the organization. *Key management procedure* specifies methods for
performing tasks on managing cryptographic keys. *PCI-DSS* provides
guidance on strong cryptography.



## Audit management policy ##
The Audit Management Policy ensures that activities within the
business are traced and accounted.

### Auditable Events ###
Audit records are generated by the information system for at least the
following events: invalid/valid access attempts, actions taken with
root/administrative privileges, changes to time settings. **Security**
specifies which information system components carry out auditing
activities, which events require auditing on a continuous basis, and
which events require auditing in response to specific
situations. Additionally, the security audit function is coordinated
with the network health and status monitoring function to enhance the
mutual support between the two functions by the selection of
information to be recorded by each function. Audit records are
compiled from multiple components throughout the system into a
system-wide (logical or physical), time-correlated audit
trail. *PCI-DSS 10.2* provides guidance on auditable events.

### Content Of Audit Records ###
The information system produces audit records that contain sufficient
information to establish what events occurred, the sources of the
events, and the outcomes of the events. The information system
provides the capability to include additional, more detailed
information in the audit records for audit events identified by type,
location, or subject. The information system provides the capability
to centrally manage the content of audit records generated by
individual components throughout the system. *PCI-DSS 10.3* provides
guidance on content of audit records.

### Audit Monitoring, Analysis, And Reporting ###
**Security** (i) reviews and analyzes information system audit records
**every 1 day** (e.g. intrusion detection logs, system activity logs) for
indications of inappropriate/unusual activity; (ii) investigates
suspicious activity or suspected violations; (iii) takes necessary
actions (e.g. reports findings to **Operations**). **Operations** also (i)
reviews the activities of users (e.g. user activity logs) with respect
to the enforcement and usage of information system access controls;
(ii) investigates any unusual information system related activities;
and (iii) periodically reviews changes to access authorizations. It is
not intended that every single audit record be reviewed, but rather
with automated mechanisms (e.g. log harvesting, parsing, alerting
tools) and when specific circumstances warrant review of other audit
records. **Operations** employs automated mechanisms to integrate audit
monitoring, analysis, and reporting into an overall process for
investigation and response to suspicious activities. Automated
mechanisms are employed to alert **Operations** and **Security** of
inappropriate/unusual activities with security implications and
facilitate the review of user activities. *Daily operational procedure*
specifies methods for performing tasks on audit monitoring and
analysis.

### Audit Reduction, Report Generation, And Protection ###
Audit reduction and report generation tools are provided by the
information system to support after-the-fact investigations of
security incidents without altering original audit records. Audit
information (e.g. audit records, audit settings, and audit reports)
and audit tools are protected from unauthorized access, modification,
and deletion by the information system. Access to audit information is
restricted to **Operations**, **Engineering**, and **Security**. Audit records are
automatically processed for events of interest based upon selectable
event criteria.

### Audit Record Retention And Storage ###
**Operations** retains audit records for **1 year** and makes **3 months** of
audit records immediately available to provide support for
after-the-fact investigations of security incidents and to meet
regulatory and organizational information retention requirements
(e.g. PCI-DSS). *Audit management procedure* provides methods on
retaining and restoring audit records.

### Time Stamps ###
Time stamps for use in audit record generation are provided by the
information system. Time stamps (including date and time) of audit
records are generated using internal system clocks. **Operations** employs
automated mechanisms (e.g. ntp) to synchronize **sensitive** information
system time with internal time servers. Internal time servers receive
time updates only from industry-accepted time sources.

### Information System Monitoring Tools And Techniques ###
**Operations** employs tools and techniques (e.g. intrusion detection
systems, integrity verification applications, audit record monitoring
software) to monitor events on the information system, detect attacks,
and provide identification of unauthorized use of the
system. Monitoring tools are strategically deployed within the
information system (e.g. at selected perimeter locations, ad hoc
locations) to collect essential information and track specific
transactions. Additionally, these tools are used to track the impact
of security changes to the information system. Intrusion detection
tools (i) are connected and configured into a system-wide intrusion
detection system for near real-time analysis of events; (ii) are
integrated into access control/flow control mechanisms for rapid
response to attacks and by enabling reconfiguration of these
mechanisms in support of attack isolation and elimination; (iii)
monitor inbound and outbound communications for unusual or
unauthorized activities or conditions. File integrity monitoring
tools: (i) detect and protect against unauthorized changes to software
and information, and (ii) automatically monitor the integrity of the
information system and the applications it hosts. **Operations**
reassesses the integrity of software and information by performing
integrity scans of the system **every 1 week** and looks for evidence of
information tampering, errors, and omissions. **Operations** employs
automated tools that provide notification to appropriate individuals
upon discovering discrepancies during integrity verification.



## Risk management policy ##
The Risk Management Policy ensures that activities and environments
are assessed for business impact and possible disruption.

### Risk Assessment ###
**Security** conducts assessments of the risk and magnitude of harm that
could result from the unauthorized access, use, disclosure,
disruption, modification, or destruction of **sensitive** information and
**sensitive** information systems that support the operations and assets of the
organization (including information and information systems
managed/operated by external parties). **Security** updates the risk
assessment **every 1 year** and after significant changes to the
information system. Risk assessments take into account
vulnerabilities, threat sources, and security controls planned or in
place to determine the resulting level of residual risk posed to
organizational operations, organizational assets, or individuals based
on the operation of the information system. Risk assessments also take
into account risk posed to organizational operations, organizational
assets, or individuals from external parties (e.g., service providers,
contractors operating information systems on behalf of the
organization, individuals accessing organizational information
systems, outsourcing entities). *PCI DSS Risk Assessment Guidelines* provides guidance on
conducting risk assessments.

### Security Alerts And Advisories ###
**Security** receives information system security alerts/advisories
(e.g. vendor security notifications, CVE) on a regular basis, issues
alerts/advisories to appropriate personnel, and takes appropriate
actions in response. **Security** documents the types of actions to be
taken in response to security alerts/advisories and assigns a risk
ranking according to CVSS. **Security** also maintains contact with
special interest groups (e.g., information security forums) that: (i)
facilitate sharing of security-related information (e.g., threats,
vulnerabilities, and latest security technologies); (ii) provide
access to advice from security professionals; and (iii) improve
knowledge of security best practices. Automated mechanisms are
employed to make security alert and advisory information available
throughout the organization as needed.

### Vulnerability Scanning ###
**Security** scans for vulnerabilities in the **sensitive** information system
**every 3 months** and after any significant change in the network
occurs. Vulnerability scanning is internally conducted using
appropriate scanning tools and techniques and externally conducted via
an Approved Scanning Vendor (ASV). **Security** performs rescans until
passing results are obtained and all high risk vulnerabilities
(e.g. according to CVSS) are resolved. Selected personnel are trained
in the use and maintenance of internal vulnerability scanning tools
and techniques. Vulnerability scanning procedures demonstrating the
breadth and depth of scan coverage, including vulnerabilities checked
and information system components scanned is employed. Vulnerability
analysis for custom software and applications require more specialized
approaches (e.g. source code reviews and static analysis of source
code). *Incident management policy* and *Change management policy* are
initiated for remediation efforts.

### Penetration Testing ###
**Security** performs penetration (e.g. network-layer, application-layer)
testing **every 1 year** or when significant new changes potentially affecting the system are identified. Tests include components for network functions,
operating systems, and high risk vulnerabilities identified in *PCI-DSS
6.5*. Penetration testing is internally and externally conducted using
appropriate testing tools and techniques and by trained selected
personnel. **Security** performs retests until all noted exploitable
vulnerabilities are corrected. *Penetration testing procedure* specifies
methods for performing tasks on penetration testing.




## Incident management policy ##
The Incident Management Policy ensures that adverse impact on business
operations are minimized, and normal service operations are restored
as quickly as possible.

### Incident Response Training And Testing ###
**Security** trains personnel in their incident response roles and
responsibilities with respect to the **sensitive** information system and
provides refresher training **every 1 year**. Security tests and exercises
the incident response capability for the **sensitive** information system
**every 1 year** using simulated events to determine the incident response
effectiveness and documents the results.

### Incident Handling ###
**Security** implements an incident handling capability for security
incidents that includes preparation, detection and analysis,
containment, eradication, and recovery. Incident-related information
is obtained from a variety of sources (e.g. audit monitoring, network
monitoring, user/administrator reports). **Security** incorporates the
lessons learned from ongoing incident handling activities into the
incident response procedures and implements the procedures
accordingly. **Operations** employs automated mechanisms to support the
incident handling process.

### Incident Monitoring And Reporting ###
**Security** tracks and documents **sensitive** information system security
incidents on an ongoing basis. **Operations** employs automated mechanisms
(e.g. monitoring tools) to assist in the tracking of security
incidents and in the collection and analysis of incident
information. **Security** promptly reports incident information to
appropriate authorities. In addition to incident information,
weaknesses and vulnerabilities in the **sensitive** information system are
reported to appropriate organizational officials in a timely manner to
prevent security incidents. Organizational officials report security
compromises to appropriate payment brands and legal bodies within an
appropriate timeframe. **Operations** employs automated mechanisms to
assist in the tracking of security incidents, reporting of security
incidents, and in the collection and analysis of incident
information. *Incident management procedure* specifies methods for
performing tasks on incident monitoring and reporting.

### Incident Response Assistance ###
**Security** provides an incident response support resource available
**on-call 24/7** that offers advice and assistance to personnel of the
**sensitive** information system for the handling and reporting of
security incidents.



## Application management policy ##
The Application management policy ensures that software is resilient,
features are delivered securely with minimized risk, and required
functionality is available with minimal risk.

### Life Cycle Support ###
**Engineering** designs and implements the **sensitive** information system
using an agile software development life cycle methodology that
includes information security considerations. In the following phase,
**Engineering** employs information security considerations in the
following phases: (i) Requirements: Misuse cases are identified and
assessed against security risks (e.g. Owasp Top 10); (ii)
Implementation: Test cases are developed and code is reviewed by a
peer knowledgeable in *Security Engineering Principles*; (iii) Testing:
Outcomes are verified for success using continuous integration
mechanisms; (iv) Release: Appropriate personnel are notified and
*Change management policy* is followed; (v) Maintenance: Problems are
identified and *Incident management policy* is followed.

### Security Engineering Principles ###
**Engineering** designs and implements the information system using
security engineering principles and applies them to system upgrades
and modifications. **Engineering** adheres to best practice secure coding
guidelines (e.g. Owasp Top 10, Cert Secure Coding, CWE/Sans Top
25). **Sensitive** information system data (e.g. live PANs) is not used
for development/testing, and test data (e.g. custom application
accounts, identifiers, authenticators) is removed before code release
into the information system. *Application management procedure*
specifies methods for ensuring applications are not vulnerable to
common coding vulnerabilities.

### Developer Security Testing ###
**Engineering** creates a security test and evaluation plan, implements
the plan, and documents the results for the **sensitive** information
system. Developmental security test results are used to the greatest
extent feasible after verification of the results and recognizing that
these results are impacted whenever there have been security relevant
modifications to the **sensitive** information system subsequent to
developer testing.

### Developer Change Control ###
**Engineering** controls changes to the system during development, tracks
security flaws, requires authorization of changes, and provides
documentation of the implementation for the **sensitive** information
system.



## Change management policy ##
The Change management policy ensures that changes into controlled
environments are maintained throughout transition activities and
handled reliably on the basis of formal approvals.
### Configuration Change Control ###
**Operations** authorizes, documents, and controls changes to the
**sensitive** information system. Configuration change control involves
the systematic proposal, justification, implementation,
test/evaluation, review, and disposition of changes to the **sensitive**
information system, including upgrades and
modifications. Configuration change control includes changes to the
configuration settings for **sensitive** information technology products
(e.g., operating systems and firewalls). **Operations** includes emergency
changes in the configuration change control process, including changes
resulting from the remediation of flaws. **Operations** employs automated
mechanisms to: (i) document proposed and completed changes to the
information system; (ii) notify appropriate approval authorities;
(iii) inhibit change until necessary approvals are received; and (iv)
track security flaws and impact of change. **Operations** includes
documentation of (i) impact of changes; (ii) change approval by
authorized personnel; (iii) functionality testing of changes; and (iv)
back out procedures. The approvals to implement a change to the
information system include (i) successful results from the security
analysis of the change; and (ii) change reviews by authorized
personnel (e.g. Operations, Engineering). *Change management procedure*
specifies methods for performing tasks on configuration change
control.

### Monitoring Configuration Changes ###
**Operations** and **Engineering** monitor changes to the **sensitive**
information system conducting security impact analyses to determine
the effects of the changes. Prior to change implementation, and as
part of the change approval process, **Operations** analyzes changes to
the information system for potential security impacts. After the
**sensitive** information system is changed (including upgrades and
modifications), **Operations** checks the security features to verify that
the features are still functioning properly. **Operations** audits
activities associated with the configuration changes to the **sensitive**
information system. Monitoring configuration changes and conducting
security impact analyses are important elements with regard to the
ongoing assessment of security controls in the information system.

### Access Restrictions For Change ###
**Operations**: (i) approves individual access privileges and enforces
physical and logical access restrictions associated with changes to
the information system; and (ii) generates, retains, and reviews
records reflecting all such changes. Only **Operations** obtain access to
**sensitive** information system components for the purposes of initiating
changes, including upgrades, and modifications. **Operations** employs
automated mechanisms to enforce access restrictions and support
auditing of the enforcement actions.

### Flaw Remediation ###
**Operations** identifies, reports, and corrects information system
flaws. **Operations** identifies information systems containing software
affected by recently announced software flaws (and potential
vulnerabilities resulting from those flaws). **Operations** (or the vendor
in the case of software developed and maintained by a
vendor/contractor) (i) installs, **within 1 month**, newly released
security relevant patches, service packs, and hot fixes; and (ii)
tests patches, service packs, and hot fixes for effectiveness and
potential side effects on the organization’s **sensitive** information
systems before installation. Flaws discovered during security
assessments, continuous monitoring, incident response activities, or
information system error handling are also addressed
expeditiously. **Operations** centrally manages the flaw remediation
process and installs updates automatically. **Operations** employs
automated mechanisms to periodically and upon demand determine the
state of information system components with regard to flaw
remediation.



## Configuration management policy ##
The Configuration Management Policy ensures that assets and services
are baselined, maintained, and consistent.

### Baseline Configuration ###
**Operations** develops, documents, and maintains a current baseline
configuration of the **sensitive** information system. Baseline
configurations provide information about a component’s makeup
(e.g. the standard software stack for a database including updated
patch information) and the component’s logical placement within the
information system architecture. Baseline configurations also provide
a well-defined and documented specification to which the information
system is built and deviations, if required, are documented in support
of mission needs/objectives. **Operations** updates baseline
configurations as an integral part of information system component
installations, especially when new vulnerabilities are
identified. **Operations** employs automated mechanisms
(e.g. Configuration Management Tools) to maintain an up-to-date,
complete, accurate, and readily available baseline configuration of
the information system. *System configuration standard* provides
guidance on baseline configurations and system hardening standards.

### Configuration Settings ###
Configuration settings are the configurable parameters of the
information technology products that compose the information
system. **Operations**: (i) establishes mandatory configuration settings
for information technology products employed within the information
system; (ii) configures the security settings of information
technology products to the most restrictive mode consistent with
operational requirements (e.g. according to *Least Functionality*);
(iii) documents the configuration settings; (iv) enforces the
configuration settings in all components of the information system;
and (v) monitors and controls changes in accordance with Change
Management Policy. **Operations** employs automated mechanisms
(e.g. configuration management tools) to centrally manage, apply, and
verify configuration settings. *System configuration standard* provides
guidance on configuration settings and system hardening standards.

### Least Functionality ###
**Operations** configures the **sensitive** information system to provide only
essential capabilities and specifically prohibits/restricts the use of
all ports, protocols, and/or services without documented business
justifications. **Operations** limits component functionality to a single
function per server (e.g. application server or database server, not
both), where feasible. **Operations** reviews the **sensitive** information
system **every 6 months** to document business justifications for enabled
capabilities and to eliminate unnecessary functions (e.g. scripts,
drivers, ports, protocols, services, firewall rules).

### Information System Recovery And Reconstitution ###
**Operations** employs mechanisms with supporting procedures to allow the
information system to be recovered and reconstituted to a known state
after a disruption or failure. Information system recovery and
reconstitution to a known secure state means that all system
parameters are set to secure values, security-critical patches are
reinstalled, security-related configuration settings are
reestablished, system documentation and operating procedures are
available, application and system software is reinstalled and
configured with secure settings, information from the most recent,
known secure backups is loaded, and the system is fully tested.


## Network management policy ##
The Network Management Policy ensures that assets and services are
segmented into functional roles within monitored and controlled
environments.

### Boundary Protection ###
Information system communications are monitored and controlled at
external boundaries and at key internal boundaries within the
information system. Any connections to the Internet, or other external
networks or information systems, occur through appropriate boundary
protection devices (e.g., proxies, gateways, firewalls, encrypted
tunnels) arranged in an effective architecture (e.g. DMZs where
**sensitive** application gateways reside on a protected
subnetwork). **Operations** (i) allocates publicly accessible information
system components to separate subnetworks; (ii) prevents public access
into the organization’s **sensitive** internal networks except as
appropriately mediated; (iii) limits the number of access points to
and from the **sensitive** information system. **Operations** partitions
information systems into separate environments (e.g. development,
test, production) and restricts/prohibits network access to authorized
personnel. Boundary protections at any designated alternate processing
sites provide the same levels of protection as that of the primary
site. Information systems deny network traffic by default and allow
network traffic by exception (i.e. deny all, permit by exception).

### Information Flow Enforcement ###
The information system enforces assigned authorizations for
controlling the flow of information within the system and between
interconnected systems. Information flow control regulates where
information is allowed to travel within an information system and
between information systems (e.g. blocking outside traffic that claims
to be from within the organization, and not passing direct connections
between the Internet and internal networks). As opposed to who is
allowed to access the information, information flow control regulates
information travel without explicit regard to subsequent accesses to
that information. As a basis for flow control decisions (e.g. to
control the release of certain types of information), information flow
control is enforced using (i) explicit labels on source and
destination objects; (ii) protected processing domains (e.g. domain
type-enforcement); and/or (iii) dynamic security policy mechanisms.

### Wireless Access Restrictions ###
**Operations** (i) authorizes, monitors, and controls **sensitive** wireless
access to the information system; and (ii) uses strong authentication
and strong encryption to protect **sensitive** wireless access to the
information system. *PCI-DSS* provides guidance on strong encryption.

### Information System Documentation ###
**Operations** obtains, protects as required, and makes available to
authorized personnel, adequate documentation for the information
system. Documentation (e.g. network diagrams) describing the
functional properties, design, and implementation details of the
security controls employed within the **sensitive** information system are
updated **every 1 month** with sufficient detail to permit analysis and
testing of the controls.

### External Information System Services ###
**Operations**: (i) requires that providers (e.g. backup, payment
processors, hosting) of external information system services provide
written acknowledgement that adequate security controls are employed
in accordance with policies, standards, guidance, and established
service-level agreements, (ii) monitors and reviews security control
compliance of providers **every 1 year**; and (iii) maintains an
up-to-date list of all service providers. *External Information Systems
Services procedure* specifies methods for performing tasks on engaging
service providers.

### Transmission Integrity And Confidentiality ###
The information system protects the integrity and confidentiality of
transmitted information. **Operations** employs strong cryptographic
mechanisms (e.g. SSL, SSH, IPSEC) to prevent unauthorized
disclosure/recognize changes to information during
transmission. *PCI-DSS* provides guidance on strong cryptography.

### Session Termination ###
All sessions (e.g. remote, local) are automatically terminated after
**15 minutes** of inactivity by the information system.



## Personnel management policy ##
The Personnel Management Policy ensures that due diligence has been
conducted on all personnel with access to assets.

### Security Awareness ###
**Security** provides basic security awareness training to personnel
before authorizing access to the system, when required by system
changes, upon hire, and **every 1 year** thereafter. **Security** determines
the appropriate content of security awareness training based on the
specific requirements of the organization and the information systems
to which personnel have authorized access.

### Security Training ###
**Security** identifies personnel (e.g. Operations, Engineering) that have
significant information system security roles and responsibilities
during the system development life cycle and provides appropriate
information system security training (e.g. secure coding techniques
according to industry best practices) **every 1 year**. *NIST SP 800-50*
provides guidance on security training.

### Personnel Screening ###
**Human Resources** screens individuals requiring access to organizational
information and information systems before authorizing
access. Screenings (e.g. background checks) are consistent with the
criteria established for the risk designation of the assigned
position.

### Personnel Termination ###
**Operations**, upon termination of individual employment, **immediately**
terminates information system access, retrieves all organizational
information system-related property (e.g. identifiers, authenticators,
and laptops) and provides appropriate personnel with access to
official records created by the terminated employee that are stored on
organizational information systems.

### Personnel Transfer ###
**Operations** reviews information systems access authorizations when
personnel are reassigned or transferred to other positions within the
organization and initiates appropriate actions. Appropriate actions
that may be required include: (i) deactivating old and issuing new
keys, (ii) closing old accounts and establishing new accounts; (iii)
changing system access authorizations; and (iv) providing for access
to official records created or controlled by the employee at the old
work location and in the old accounts.

### Personnel Sanctions ###
**Human Resources** employs a formal sanctions process for personnel
failing to comply with established information security policies and
procedures.

### Access Agreements ###
**Human Resources** completes appropriate signed access agreements
(e.g. acceptable use agreements, rules of behavior, information
security policy) for personnel requiring access to organizational
information and information systems. **Human Resources** receives signed
acknowledgement from users **every 1 year** indicating that they have
read, understood, and agree to abide by the agreements before
authorizing access to the information system and its resident
information. **Security** reviews and updates the access agreements **every
1 year**. Electronic signatures are acceptable for use in acknowledging
access agreements. **Security** establishes a set of rules (e.g. Rules Of
Behavior) for all Personnel.


## Acceptable Use Policy ##
The acceptable use policy (AUP) is a set of rules to restrict the ways
in which the information system may be used.
### Rules Of Behavior ###
* **Personnel** MUST NOT copy, move, or store **sensitive** information data onto non-sensitive information system media (e.g. local hard drives, flash drives).

* **Personnel** with access to **sensitive** information systems MUST (i) enable personal firewall software; (ii) enable personal antivirus software with automatic updates; and (iii) install operating system updates and security patches to existing software whenever new releases are available.

* **Personnel** MUST take reasonable measures to safeguard secrets (e.g. identifiers, authenticators, secret shards) including maintaining possession of their individual secrets, not loaning or sharing secrets with others, and reporting lost or compromised secrets shards immediately.

* **Personnel** SHOULD only distribute **public** information after receiving approval from **Communications**.

* **Personnel** MUST NOT distribute **private** information outside of the organization.

* **Personnel** MUST only distribute **restricted** information on a valid need-to-know basis.

* **Personnel** should not distribute **sensitive** information.

* **Personnel** MUST NOT send **sensitive** information by end-user messaging technologies (e.g. email, instant messaging, chat).

* **Personnel** MUST complete Security Awareness Training **upon hire** and **every 1 year**, thereafter.

* **Personnel** MUST read, understand, and sign the Information Security Policy **upon hire** and **every 1 year**, thereafter.

##Definitions##

Access: level and extent of a service’s functionality or data that a user is entitled to use

Identity: information about a user that distinguishes them as an individual and verifies their status within the organization

Controlled Area: any area or space for which the organization has confidence that the physical and procedural protections provided are sufficient to meet the requirements established for protecting the information and/or information system.

Data: a recorded information produced or received in the initiation, conduct or completion of an institutional or individual activity and that comprises content, context and structure sufficient to provide evidence of the activity.

PAN: Primary Account Number

MUST: This word, or the terms "REQUIRED" or "SHALL", mean that the definition is an absolute requirement of the specification.

MUST NOT: This phrase, or the phrase "SHALL NOT", mean that the definition is an absolute prohibition of the specification.

SHOULD: This word, or the adjective "RECOMMENDED", mean that there may exist valid reasons in particular circumstances to ignore a particular item, but the full implications must be understood and carefully weighed before choosing a different course.

SHOULD NOT: This phrase, or the phrase "NOT RECOMMENDED" mean that there may exist valid reasons in particular circumstances when the particular behaviour is acceptable or even useful, but the full implications should be understood and the case carefully weighed before implementing any behaviour described with this label.
