# OSIRIS

### Operating System Incident Reconstruction and Intelligence System
**_Turning Events into Evidence_**

OSIRIS is a Linux-based system monitoring and cybersecurity investigation platform designed to collect, store, reconstruct, and analyze operating system activities. The project brings together concepts from **Operating Systems, Database Management Systems, and Cybersecurity** into a single investigative platform.

---

## Summary

OSIRIS monitors selected Linux activities related to processes, users, filesystem changes, and system resources. The collected activities are converted into structured, timestamped events and stored in a relational database using **PostgreSQL**.

The system maintains historical activity data so that users can examine events that occurred within a particular time period, reconstruct sequences of activities of interest, and analyze potentially suspicious behavior.

OSIRIS also includes an explainable security-analysis module that applies predefined rules to identify suspicious activities and generate alerts for further investigation.

---

## Core Capabilities

- Linux process and system activity monitoring
- Filesystem change monitoring
- System resource monitoring
- Structured event collection and normalization
- Historical event storage using PostgreSQL
- Historical activity reconstruction
- Explainable security analysis
- File integrity monitoring
- Alert generation and incident management
- Web-based monitoring and investigation dashboard

---

## Technology Stack

**Backend:** Python, FastAPI  
**Database:** PostgreSQL  
**Environment:** Linux  
**Frontend:** HTML, CSS, JavaScript

---

## System Workflow

```text
Linux System
     ↓
Activity Collection
     ↓
Event Normalization
     ↓
PostgreSQL Database
     ↓
Historical Reconstruction
     ↓
Security Analysis
     ↓
Alerts
     ↓
Incident Investigation