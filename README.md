# HexaShield 🔒

**Six-Layered Security Platform | IDS/IPS Solution**  
**Developer: Hassan Hamisi | Security Architect**

## Overview

HexaShield is a professional six-layered Intrusion Detection and Prevention System (IDS/IPS) designed for enterprise security operations. Unlike traditional security tools, HexaShield implements a multi-layered defense strategy that provides comprehensive network protection.

## ✨ Six Security Layers

### **Layer 1: Perimeter Defense**
- Network boundary protection
- IP blacklisting/whitelisting
- External-to-internal traffic monitoring

### **Layer 2: Signature Detection**
- Pattern-based attack detection
- Pre-defined threat signatures
- Real-time content inspection

### **Layer 3: Behavioral Analysis**
- Anomaly detection
- Connection rate monitoring
- Port scan detection
- DDoS pattern recognition

### **Layer 4: Threat Intelligence**
- Known malicious IP database
- Suspicious IP range detection
- Threat actor identification

### **Layer 5: Protocol Analysis**
- Protocol compliance validation
- Packet structure analysis
- Malformed packet detection

### **Layer 6: Automated Response**
- Intelligent response actions
- IP blocking and throttling
- Alert escalation and logging

## 🚀 Features

- **Zero Dependencies**: Pure Python, no external libraries required
- **Multi-Layered Defense**: Six independent security layers
- **Real-time Monitoring**: Live traffic analysis (simulation mode)
- **Comprehensive Logging**: JSON-formatted logs for SIEM integration
- **Professional Interface**: Color-coded alerts and statistics
- **Cross-Platform**: Works on Windows, Linux, and macOS
- **Educational Mode**: Safe simulation without network access

## 📋 Installation

### **No Installation Required!**
HexaShield requires only Python 3.6+ with no external dependencies:

```bash
# Clone the repository
git clone <repository-url>
cd hexashield

# Run immediately - no pip install needed!
python hexashield.py

#Run on windows interface
hexashield_env\Scripts\activate

#Deactivate
deactivate