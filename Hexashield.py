#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║                 HEXASHIELD REAL-TIME ENTERPRISE SOC         ║
╠══════════════════════════════════════════════════════════════╣
║  Developer: Hassan Hamisi                                    ║
║  GitHub: khabib23-h                                          ║
║  Email: hassanhamisim1@gmail.com                             ║
║  Version: 5.0.0 | Professional Enterprise Edition           ║
║  Release Date: February 2024                                 ║
╚══════════════════════════════════════════════════════════════╝
"""

import os
import sys
import time
import threading
import socket
import json
import re
import hashlib
import subprocess
import sqlite3
import statistics
from datetime import datetime, timedelta
from collections import defaultdict, deque, Counter, OrderedDict
from typing import Dict, List, Optional, Set, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum, IntEnum
import platform
import getpass
import urllib.parse
from pathlib import Path
import ipaddress
import ctypes
import struct
import io
import tempfile
import uuid
import html
import xml.etree.ElementTree as ET
import configparser
import inspect
import importlib
import warnings
import contextlib
import itertools
import math
import decimal
import numbers
import collections.abc
import pprint
import textwrap
import builtins
import types
import traceback
import linecache
import tokenize
import token
import keyword
import ast
import dis
import opcode
import marshal
import shelve
import hmac
import secrets
import bisect
import heapq
import array
import weakref
import copy
import pdb
import profile
import cProfile
import timeit
import doctest
import unittest
import difflib
import fnmatch
import glob
import shutil
import stat
import errno
import select
import selectors
import signal
import mmap
import ssl
import gettext
import locale
import logging
import logging.handlers
import getopt
import argparse
import cmd
import shlex
import runpy
import sysconfig
import site
import abc
import atexit

# Import Windows-specific modules with try-except
try:
    import winreg
    import win32api
    import win32con
    import win32file
    import win32evtlog
    import win32evtlogutil
    import win32security
    import win32service
    import wmi
except ImportError:
    print("[!] Windows-specific modules not available - some features will be limited")

# ============================================================================
# DEPENDENCY CHECK AND IMPORTS
# ============================================================================

print("\n" + "="*80)
print("HEXASHIELD SOC v5.0 - INITIALIZING".center(80))
print("="*80)

REQUIRED_PACKAGES = {
    'psutil': 'System monitoring',
    'colorama': 'Terminal colors',
}

# Make other packages optional
OPTIONAL_PACKAGES = {
    'prettytable': 'Formatted tables',
    'wmi': 'Windows Management',
    'win32api': 'Windows API',
    'scapy': 'Packet analysis',
    'pandas': 'Data analysis',
    'numpy': 'Numerical operations',
    'matplotlib': 'Visualization',
    'requests': 'HTTP requests',
}

print("\n[+] Checking dependencies...")

# Try to import required packages
import_errors = []
for package, description in REQUIRED_PACKAGES.items():
    try:
        if package == 'psutil':
            import psutil
        elif package == 'colorama':
            from colorama import init, Fore, Back, Style
            init(autoreset=True)
        print(f"  ✓ {package:15} - {description}")
    except ImportError as e:
        print(f"  ✗ {package:15} - MISSING: {e}")
        import_errors.append(package)

if import_errors:
    print(f"\n[!] Missing required packages: {', '.join(import_errors)}")
    print("[!] Install with: pip install " + " ".join(import_errors))
    sys.exit(1)

print("\n[+] All required dependencies satisfied")

# Import optional packages
for package, description in OPTIONAL_PACKAGES.items():
    try:
        if package == 'prettytable':
            from prettytable import PrettyTable, ALL
            print(f"  ✓ {package:15} - {description} (optional)")
        elif package == 'wmi':
            import wmi
            print(f"  ✓ {package:15} - {description} (optional)")
        elif package == 'win32api':
            import win32api
            import win32con
            import win32file
            import win32evtlog
            print(f"  ✓ {package:15} - {description} (optional)")
        elif package == 'scapy':
            import scapy.all
            print(f"  ✓ {package:15} - {description} (optional)")
        elif package == 'pandas':
            import pandas as pd
            print(f"  ✓ {package:15} - {description} (optional)")
        elif package == 'numpy':
            import numpy as np
            print(f"  ✓ {package:15} - {description} (optional)")
        elif package == 'matplotlib':
            import matplotlib.pyplot as plt
            print(f"  ✓ {package:15} - {description} (optional)")
        elif package == 'requests':
            import requests
            print(f"  ✓ {package:15} - {description} (optional)")
    except ImportError:
        print(f"  - {package:15} - Not installed (optional)")

print("\n" + "="*80)
print("SYSTEM INITIALIZATION COMPLETE".center(80))
print("="*80 + "\n")

# ============================================================================
# CONFIGURATION
# ============================================================================

class Config:
    """Configuration settings"""
    VERSION = "5.0.0"
    AUTHOR = "Hassan Hamisi"
    EMAIL = "hassanhamisim1@gmail.com"
    GITHUB = "khabib23-h"
    
    # Database
    DB_PATH = "hexashield_soc.db"
    LOG_PATH = "hexashield_logs"
    REPORTS_PATH = "hexashield_reports"
    
    # Monitoring intervals (seconds)
    NETWORK_SCAN_INTERVAL = 2
    PROCESS_SCAN_INTERVAL = 3
    FILE_SCAN_INTERVAL = 5
    WEBSITE_SCAN_INTERVAL = 3
    SYSTEM_SCAN_INTERVAL = 5
    DASHBOARD_UPDATE_INTERVAL = 2
    
    # Alert thresholds
    HIGH_CPU_THRESHOLD = 85
    HIGH_MEMORY_THRESHOLD = 85
    HIGH_DISK_THRESHOLD = 90
    SUSPICIOUS_CONNECTIONS_THRESHOLD = 10
    
    # Website tracking
    MAX_WEBSITE_HISTORY = 10000
    MAX_DNS_HISTORY = 5000
    MAX_CONNECTION_HISTORY = 5000
    
    # Colors
    COLORS = {
        'HEADER': '\033[96m\033[1m',
        'SUCCESS': '\033[92m\033[1m',
        'WARNING': '\033[93m\033[1m',
        'ERROR': '\033[91m\033[1m',
        'INFO': '\033[94m',
        'CYAN': '\033[96m',
        'MAGENTA': '\033[95m',
        'BLUE': '\033[94m',
        'GREEN': '\033[92m',
        'YELLOW': '\033[93m',
        'RED': '\033[91m',
        'BOLD': '\033[1m',
        'UNDERLINE': '\033[4m',
        'RESET': '\033[0m',
        'DIM': '\033[2m'
    }

# Create necessary directories
os.makedirs(Config.LOG_PATH, exist_ok=True)
os.makedirs(Config.REPORTS_PATH, exist_ok=True)

# ============================================================================
# PROFESSIONAL LOGGING SYSTEM
# ============================================================================

class ProfessionalLogger:
    """Professional logging system"""
    
    def __init__(self):
        self.log_file = os.path.join(Config.LOG_PATH, f"soc_{datetime.now().strftime('%Y%m%d')}.log")
        self.alert_file = os.path.join(Config.LOG_PATH, f"alerts_{datetime.now().strftime('%Y%m%d')}.log")
        self.audit_file = os.path.join(Config.LOG_PATH, f"audit_{datetime.now().strftime('%Y%m%d')}.log")
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(self.log_file),
                logging.StreamHandler()
            ]
        )
        
        self.logger = logging.getLogger('HexaShieldSOC')
        self._print_banner()
    
    def _print_banner(self):
        """Print professional banner"""
        banner = f"""
{Config.COLORS['CYAN']}{Config.COLORS['BOLD']}
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║                    H E X A S H I E L D   S O C   v{Config.VERSION}                     ║
║                                                                              ║
║                 Professional Security Operations Center                      ║
║                 Real-Time Enterprise Monitoring System                       ║
║                                                                              ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  Developer: {Config.AUTHOR:<30} GitHub: {Config.GITHUB:<20} ║
║  Email: {Config.EMAIL:<35} Date: {datetime.now().strftime('%Y-%m-%d'):<15} ║
╚══════════════════════════════════════════════════════════════════════════════╝
{Config.COLORS['RESET']}
"""
        print(banner)
        self.logger.info("HexaShield SOC initialized")
    
    def log(self, level, message, component="System"):
        """Log message with component"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        
        if level == "INFO":
            color = Config.COLORS['INFO']
            log_func = self.logger.info
        elif level == "WARNING":
            color = Config.COLORS['WARNING']
            log_func = self.logger.warning
        elif level == "ERROR":
            color = Config.COLORS['ERROR']
            log_func = self.logger.error
        elif level == "CRITICAL":
            color = Config.COLORS['RED'] + Config.COLORS['BOLD']
            log_func = self.logger.critical
        elif level == "SUCCESS":
            color = Config.COLORS['SUCCESS']
            log_func = self.logger.info
        else:
            color = Config.COLORS['INFO']
            log_func = self.logger.info
        
        formatted = f"[{timestamp}] [{component}] [{level}] {message}"
        print(f"{color}{formatted}{Config.COLORS['RESET']}")
        log_func(f"[{component}] {message}")
        
        # Also write to alert file if critical/warning
        if level in ["CRITICAL", "ERROR", "WARNING"]:
            with open(self.alert_file, 'a') as f:
                f.write(formatted + "\n")
    
    def alert(self, severity, message, details=None):
        """Generate security alert"""
        alert_id = str(uuid.uuid4())[:8]
        timestamp = datetime.now()
        
        # Convert details to JSON-serializable format
        serializable_details = {}
        if details:
            for key, value in details.items():
                if isinstance(value, datetime):
                    serializable_details[key] = value.isoformat()
                elif hasattr(value, '__dict__'):
                    # Try to convert objects to dict
                    try:
                        serializable_details[key] = vars(value)
                    except:
                        serializable_details[key] = str(value)
                else:
                    serializable_details[key] = value
        
        alert_data = {
            'id': alert_id,
            'timestamp': timestamp.isoformat(),  # Already a string
            'severity': severity,
            'message': message,
            'details': serializable_details or {},
            'status': 'NEW'
        }
        
        # Log alert
        self.log("WARNING" if severity == "MEDIUM" else "ERROR", 
                f"ALERT {alert_id}: {message}", "AlertSystem")
        
        # Save to alerts database
        self._save_alert(alert_data)
        
        # Return alert data
        return alert_data
    
    def _save_alert(self, alert_data):
        """Save alert to database"""
        try:
            conn = sqlite3.connect(Config.DB_PATH)
            cursor = conn.cursor()
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS alerts (
                    id TEXT PRIMARY KEY,
                    timestamp TEXT,
                    severity TEXT,
                    message TEXT,
                    details TEXT,
                    status TEXT,
                    resolved_time TEXT
                )
            ''')
            
            cursor.execute('''
                INSERT INTO alerts (id, timestamp, severity, message, details, status)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                alert_data['id'],
                alert_data['timestamp'],
                alert_data['severity'],
                alert_data['message'],
                json.dumps(alert_data['details'], default=str),  # Use default=str for any non-serializable objects
                alert_data['status']
            ))
            
            conn.commit()
            conn.close()
        except Exception as e:
            self.log("ERROR", f"Failed to save alert: {e}", "Logger")
    
    def audit(self, action, user="System", details=None):
        """Audit logging"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        audit_entry = f"{timestamp} | {user} | {action} | {details or ''}"
        
        with open(self.audit_file, 'a') as f:
            f.write(audit_entry + "\n")

# Initialize logger
logger = ProfessionalLogger()

# ============================================================================
# REAL-TIME NETWORK MONITOR
# ============================================================================

class RealTimeNetworkMonitor:
    """Professional real-time network monitoring"""
    
    def __init__(self):
        self.running = False
        self.thread = None
        self.connections = deque(maxlen=Config.MAX_CONNECTION_HISTORY)
        self.connection_stats = defaultdict(lambda: {
            'count': 0,
            'first_seen': None,
            'last_seen': None,
            'ports': set(),
            'threat_score': 0
        })
        self.bandwidth_stats = {
            'total_sent': 0,
            'total_received': 0,
            'peak_sent': 0,
            'peak_received': 0,
            'start_time': datetime.now()
        }
        
        # Threat intelligence
        self.suspicious_ports = {
            4444: ('Metasploit/Meterpreter', 10),
            31337: ('Back Orifice', 10),
            6667: ('IRC Botnet', 8),
            1337: ('Leet Backdoor', 7),
            2323: ('Telnet Alternative', 6),
            8080: ('Proxy/C2 Server', 5),
            3389: ('RDP Bruteforce', 7),
            22: ('SSH Bruteforce', 6),
            23: ('Telnet', 5),
            21: ('FTP', 4),
            25: ('SMTP Abuse', 4),
            1433: ('MSSQL Attack', 7),
            3306: ('MySQL Attack', 7),
            5432: ('PostgreSQL Attack', 7),
            27017: ('MongoDB Attack', 7)
        }
        
        # Known malicious IPs/CIDR
        self.malicious_networks = [
            '185.220.101.0/24',  # APT28
            '91.121.203.0/24',   # APT29
            '103.10.124.0/24',   # Lazarus
            '45.155.205.0/24',   # FIN7
            '192.168.0.0/16',    # Internal (for testing)
            '10.0.0.0/8',        # Internal
            '172.16.0.0/12'      # Internal
        ]
        
        logger.log("INFO", "Network monitor initialized", "NetworkMonitor")
    
    def start(self):
        """Start real-time monitoring"""
        if self.running:
            return
        
        self.running = True
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.thread.start()
        
        logger.log("SUCCESS", "Real-time network monitoring started", "NetworkMonitor")
    
    def _monitor_loop(self):
        """Main monitoring loop"""
        last_connections = []
        last_io = psutil.net_io_counters()
        
        while self.running:
            try:
                # Get current timestamp
                current_time = datetime.now()
                
                # 1. Monitor network connections
                current_connections = self._get_active_connections(current_time)
                
                # 2. Detect new connections
                new_connections = self._detect_new_connections(last_connections, current_connections)
                
                # 3. Analyze new connections
                for conn in new_connections:
                    self._analyze_connection(conn)
                
                # 4. Update bandwidth stats
                self._update_bandwidth_stats()
                
                # 5. Detect port scans
                self._detect_port_scans(current_connections)
                
                # 6. Detect data exfiltration
                self._detect_data_exfiltration()
                
                # Update last connections
                last_connections = current_connections
                
                # Sleep for configured interval
                time.sleep(Config.NETWORK_SCAN_INTERVAL)
                
            except Exception as e:
                logger.log("ERROR", f"Network monitoring error: {e}", "NetworkMonitor")
                time.sleep(5)
    
    def _get_active_connections(self, timestamp):
        """Get all active network connections"""
        connections = []
        
        try:
            for conn in psutil.net_connections(kind='inet'):
                try:
                    # Get process info first
                    process_info = self._get_process_info(conn.pid) if conn.pid else 'Unknown'
                    
                    conn_info = {
                        'timestamp': timestamp,
                        'local_addr': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                        'remote_addr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                        'status': conn.status,
                        'pid': conn.pid,
                        'process': process_info,
                        'family': 'IPv4' if conn.family == socket.AF_INET else 'IPv6' if conn.family == socket.AF_INET6 else 'Unknown',
                        'type': 'TCP' if conn.type == socket.SOCK_STREAM else 'UDP' if conn.type == socket.SOCK_DGRAM else 'Unknown'
                    }
                    
                    if conn.raddr:
                        conn_info['remote_ip'] = conn.raddr.ip
                        conn_info['remote_port'] = conn.raddr.port
                    
                    connections.append(conn_info)
                    
                    # Add to history
                    self.connections.append(conn_info)
                    
                    # Update statistics
                    if conn.raddr:
                        ip = conn.raddr.ip
                        stats = self.connection_stats[ip]
                        stats['count'] += 1
                        stats['last_seen'] = timestamp
                        if stats['first_seen'] is None:
                            stats['first_seen'] = timestamp
                        if conn.raddr.port:
                            stats['ports'].add(conn.raddr.port)
                    
                except Exception as e:
                    continue
        
        except Exception as e:
            logger.log("ERROR", f"Error getting connections: {e}", "NetworkMonitor")
        
        return connections
    
    def _get_process_info(self, pid):
        """Get detailed process information"""
        try:
            proc = psutil.Process(pid)
            return {
                'name': proc.name(),
                'exe': proc.exe(),
                'cmdline': proc.cmdline(),
                'username': proc.username(),
                'create_time': datetime.fromtimestamp(proc.create_time()).strftime("%Y-%m-%d %H:%M:%S")
            }
        except:
            return {"name": f"PID:{pid}", "exe": "Unknown", "cmdline": [], "username": "Unknown", "create_time": None}
    
    def _detect_new_connections(self, old_conns, new_conns):
        """Detect new connections since last scan"""
        if not old_conns:
            return new_conns
        
        # Create sets of connection identifiers
        old_set = set()
        for conn in old_conns:
            if conn['remote_addr']:
                old_set.add(conn['remote_addr'])
        
        new_set = set()
        for conn in new_conns:
            if conn['remote_addr']:
                new_set.add(conn['remote_addr'])
        
        # Find new connections
        new_remote_addrs = new_set - old_set
        
        # Return new connections
        new_connections = []
        for conn in new_conns:
            if conn['remote_addr'] in new_remote_addrs:
                new_connections.append(conn)
        
        return new_connections
    
    def _analyze_connection(self, conn):
        """Analyze connection for threats"""
        threat_score = 0
        threats = []
        
        # Check suspicious ports
        if 'remote_port' in conn:
            port = conn['remote_port']
            if port in self.suspicious_ports:
                threat_name, score = self.suspicious_ports[port]
                threat_score += score
                threats.append(f"Suspicious port {port} ({threat_name})")
        
        # Check for internal to external connections
        if 'remote_ip' in conn:
            remote_ip = conn['remote_ip']
            
            # Check if remote IP is in malicious networks
            for network in self.malicious_networks:
                try:
                    if ipaddress.ip_address(remote_ip) in ipaddress.ip_network(network):
                        threat_score += 8
                        threats.append(f"Connection to known malicious network: {network}")
                        break
                except:
                    continue
            
            # Check for private IP connecting to public IP (possible data exfiltration)
            try:
                if ipaddress.ip_address(remote_ip).is_private:
                    # Internal connection
                    pass
                else:
                    # External connection
                    threat_score += 2
            except:
                pass
        
        # Check process reputation - FIXED: Check if process is dict before calling .get()
        if 'process' in conn:
            if isinstance(conn['process'], dict):
                proc_name = conn['process'].get('name', '').lower()
                suspicious_processes = ['powershell', 'cmd', 'wscript', 'cscript', 'rundll32', 'mshta']
                if any(sp in proc_name for sp in suspicious_processes):
                    threat_score += 3
                    threats.append(f"Suspicious process: {proc_name}")
        
        # Generate alert if threat score is high
        if threat_score >= 5:
            alert_msg = f"Suspicious network connection detected"
            
            # Create safe connection details for alert
            safe_conn = {}
            for key, value in conn.items():
                if isinstance(value, datetime):
                    safe_conn[key] = value.isoformat()
                elif key == 'process' and not isinstance(value, dict):
                    safe_conn[key] = str(value)
                else:
                    safe_conn[key] = value
            
            alert_details = {
                'connection': safe_conn,
                'threat_score': threat_score,
                'threats': threats,
                'timestamp': conn['timestamp'].isoformat() if isinstance(conn['timestamp'], datetime) else str(conn['timestamp'])
            }
            
            severity = "HIGH" if threat_score >= 10 else "MEDIUM"
            logger.alert(severity, alert_msg, alert_details)
            
            # Log to console
            remote_addr = conn.get('remote_addr', 'Unknown')
            process_name = "Unknown"
            if 'process' in conn:
                if isinstance(conn['process'], dict):
                    process_name = conn['process'].get('name', 'Unknown')
                else:
                    process_name = str(conn['process'])
            
            logger.log("WARNING", 
                      f"Suspicious connection: {remote_addr} via {process_name} "
                      f"(Score: {threat_score})", 
                      "NetworkMonitor")
    
    def _update_bandwidth_stats(self):
        """Update bandwidth statistics"""
        try:
            current_io = psutil.net_io_counters()
            
            # Calculate delta (simplified)
            self.bandwidth_stats['total_sent'] = current_io.bytes_sent
            self.bandwidth_stats['total_received'] = current_io.bytes_recv
            
            # Update peaks
            if current_io.bytes_sent > self.bandwidth_stats['peak_sent']:
                self.bandwidth_stats['peak_sent'] = current_io.bytes_sent
            
            if current_io.bytes_recv > self.bandwidth_stats['peak_received']:
                self.bandwidth_stats['peak_received'] = current_io.bytes_recv
                
        except Exception as e:
            logger.log("ERROR", f"Error updating bandwidth stats: {e}", "NetworkMonitor")
    
    def _detect_port_scans(self, connections):
        """Detect potential port scanning"""
        # Group connections by remote IP
        ip_connections = defaultdict(list)
        for conn in connections:
            if 'remote_ip' in conn:
                ip_connections[conn['remote_ip']].append(conn)
        
        # Check each IP
        for ip, conns in ip_connections.items():
            if len(conns) >= Config.SUSPICIOUS_CONNECTIONS_THRESHOLD:
                # Count unique ports
                unique_ports = len(set(c.get('remote_port') for c in conns if 'remote_port' in c))
                
                if unique_ports >= 5:  # Scanning multiple ports
                    alert_msg = f"Possible port scan from {ip}"
                    
                    # Create safe connections list for alert
                    safe_conns = []
                    for c in conns[:10]:
                        safe_c = {}
                        for key, value in c.items():
                            if isinstance(value, datetime):
                                safe_c[key] = value.isoformat()
                            else:
                                safe_c[key] = value
                        safe_conns.append(safe_c)
                    
                    alert_details = {
                        'source_ip': ip,
                        'connection_count': len(conns),
                        'unique_ports': unique_ports,
                        'connections': safe_conns  # First 10 connections
                    }
                    
                    logger.alert("HIGH", alert_msg, alert_details)
                    logger.log("WARNING", f"Port scan detected from {ip} ({len(conns)} connections, {unique_ports} ports)", "NetworkMonitor")
    
    def _detect_data_exfiltration(self):
        """Detect potential data exfiltration"""
        # Check for large outbound transfers
        try:
            net_io = psutil.net_io_counters(pernic=True)
            
            for iface, stats in net_io.items():
                # Calculate transfer rate (simplified)
                sent_mb = stats.bytes_sent / (1024 * 1024)
                
                if sent_mb > 100:  # More than 100MB sent
                    alert_msg = f"Large data transfer detected on {iface}"
                    alert_details = {
                        'interface': iface,
                        'bytes_sent': stats.bytes_sent,
                        'bytes_sent_mb': sent_mb,
                        'packets_sent': stats.packets_sent
                    }
                    
                    logger.alert("MEDIUM", alert_msg, alert_details)
                    logger.log("WARNING", f"Large transfer on {iface}: {sent_mb:.2f}MB sent", "NetworkMonitor")
                    
        except Exception as e:
            logger.log("ERROR", f"Error detecting data exfiltration: {e}", "NetworkMonitor")
    
    def get_stats(self):
        """Get current statistics"""
        return {
            'total_connections': len(self.connections),
            'unique_ips': len(self.connection_stats),
            'bandwidth_stats': self.bandwidth_stats,
            'suspicious_ports_detected': sum(1 for ip in self.connection_stats.values() if ip['threat_score'] > 0),
            'monitoring_duration': str(datetime.now() - self.bandwidth_stats['start_time'])
        }
    
    def get_recent_connections(self, limit=20):
        """Get recent connections"""
        recent = list(self.connections)[-limit:]
        
        # Convert datetime objects to strings for safe serialization
        safe_recent = []
        for conn in recent:
            safe_conn = {}
            for key, value in conn.items():
                if isinstance(value, datetime):
                    safe_conn[key] = value.isoformat()
                else:
                    safe_conn[key] = value
            safe_recent.append(safe_conn)
        
        return safe_recent
    
    def get_top_talkers(self, limit=10):
        """Get top communicating IPs"""
        sorted_ips = sorted(
            self.connection_stats.items(),
            key=lambda x: x[1]['count'],
            reverse=True
        )[:limit]
        
        result = []
        for ip, stats in sorted_ips:
            result.append({
                'ip': ip,
                'connection_count': stats['count'],
                'first_seen': stats['first_seen'].isoformat() if stats['first_seen'] else None,
                'last_seen': stats['last_seen'].isoformat() if stats['last_seen'] else None,
                'ports_accessed': list(stats['ports'])[:10],
                'threat_score': stats['threat_score']
            })
        
        return result
    
    def stop(self):
        """Stop monitoring"""
        self.running = False
        if self.thread:
            self.thread.join(timeout=2)
        logger.log("INFO", "Network monitoring stopped", "NetworkMonitor")

# ============================================================================
# SIMPLIFIED DASHBOARD
# ============================================================================

class HexaShieldDashboard:
    """Simplified dashboard for monitoring"""
    
    def __init__(self, network_monitor=None):
        self.network_monitor = network_monitor
        self.running = False
        self.thread = None
        self.stats = {
            'cpu_percent': 0,
            'memory_percent': 0,
            'disk_percent': 0,
            'network_connections': 0,
            'alerts': 0,
            'suspicious_connections': 0,
            'last_update': None
        }
        
        logger.log("INFO", "Dashboard initialized", "Dashboard")
    
    def start(self):
        """Start dashboard updates"""
        if self.running:
            return
        
        self.running = True
        self.thread = threading.Thread(target=self._update_loop, daemon=True)
        self.thread.start()
        
        logger.log("SUCCESS", "Dashboard started", "Dashboard")
    
    def _update_loop(self):
        """Update dashboard data"""
        while self.running:
            try:
                self._update_stats()
                self.display_dashboard()
                time.sleep(2)
            except Exception as e:
                logger.log("ERROR", f"Dashboard update error: {e}", "Dashboard")
                time.sleep(5)
    
    def _update_stats(self):
        """Update dashboard statistics"""
        try:
            # CPU usage
            self.stats['cpu_percent'] = psutil.cpu_percent(interval=0.1)
            
            # Memory usage
            memory = psutil.virtual_memory()
            self.stats['memory_percent'] = memory.percent
            
            # Disk usage (average of all partitions)
            disk_usages = []
            for partition in psutil.disk_partitions():
                try:
                    usage = psutil.disk_usage(partition.mountpoint)
                    disk_usages.append(usage.percent)
                except:
                    continue
            
            if disk_usages:
                self.stats['disk_percent'] = sum(disk_usages) / len(disk_usages)
            
            # Network connections
            connections = len(psutil.net_connections(kind='inet'))
            self.stats['network_connections'] = connections
            
            # Suspicious connections from network monitor
            if self.network_monitor:
                try:
                    stats = self.network_monitor.get_stats()
                    self.stats['suspicious_connections'] = stats['suspicious_ports_detected']
                except:
                    self.stats['suspicious_connections'] = 0
            
            # Alert count
            try:
                conn = sqlite3.connect(Config.DB_PATH)
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM alerts WHERE status = 'NEW'")
                count = cursor.fetchone()[0]
                conn.close()
                self.stats['alerts'] = count
            except:
                self.stats['alerts'] = 0
            
            self.stats['last_update'] = datetime.now().strftime("%H:%M:%S")
            
        except Exception as e:
            logger.log("ERROR", f"Error updating stats: {e}", "Dashboard")
    
    def display_dashboard(self):
        """Display the dashboard"""
        try:
            os.system('cls' if os.name == 'nt' else 'clear')
            
            # Dashboard header
            header = f"""
{Config.COLORS['CYAN']}{Config.COLORS['BOLD']}
╔══════════════════════════════════════════════════════════════════════════════╗
║                    HEXASHIELD SOC - REAL-TIME MONITOR                        ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  Version: {Config.VERSION:<10} Last Update: {self.stats['last_update']:<19}                    ║
╚══════════════════════════════════════════════════════════════════════════════╝
{Config.COLORS['RESET']}
"""
            print(header)
            
            # System status
            print(f"{Config.COLORS['BOLD']}SYSTEM STATUS:{Config.COLORS['RESET']}")
            
            cpu_color = Config.COLORS['RED'] if self.stats['cpu_percent'] > 80 else Config.COLORS['YELLOW'] if self.stats['cpu_percent'] > 60 else Config.COLORS['GREEN']
            mem_color = Config.COLORS['RED'] if self.stats['memory_percent'] > 80 else Config.COLORS['YELLOW'] if self.stats['memory_percent'] > 60 else Config.COLORS['GREEN']
            disk_color = Config.COLORS['RED'] if self.stats['disk_percent'] > 80 else Config.COLORS['YELLOW'] if self.stats['disk_percent'] > 60 else Config.COLORS['GREEN']
            
            print(f"  CPU Usage:    {cpu_color}{self.stats['cpu_percent']:6.1f}%{Config.COLORS['RESET']}")
            print(f"  Memory Usage: {mem_color}{self.stats['memory_percent']:6.1f}%{Config.COLORS['RESET']}")
            print(f"  Disk Usage:   {disk_color}{self.stats['disk_percent']:6.1f}%{Config.COLORS['RESET']}")
            
            print()
            
            # Network status
            print(f"{Config.COLORS['BOLD']}NETWORK STATUS:{Config.COLORS['RESET']}")
            print(f"  Active Connections: {self.stats['network_connections']:6d}")
            suspicious_color = Config.COLORS['RED'] if self.stats['suspicious_connections'] > 0 else Config.COLORS['GREEN']
            print(f"  Suspicious Connections: {suspicious_color}{self.stats['suspicious_connections']:6d}{Config.COLORS['RESET']}")
            
            print()
            
            # Security status
            print(f"{Config.COLORS['BOLD']}SECURITY STATUS:{Config.COLORS['RESET']}")
            alert_color = Config.COLORS['RED'] if self.stats['alerts'] > 0 else Config.COLORS['GREEN']
            print(f"  Active Alerts: {alert_color}{self.stats['alerts']:6d}{Config.COLORS['RESET']}")
            
            print()
            
            # Process information
            print(f"{Config.COLORS['BOLD']}TOP PROCESSES:{Config.COLORS['RESET']}")
            try:
                processes = []
                for proc in psutil.process_iter(['pid', 'name', 'cpu_percent']):
                    try:
                        info = proc.info
                        if info['cpu_percent'] is not None and info['cpu_percent'] > 0:
                            processes.append((info['name'], info['cpu_percent']))
                    except:
                        continue
                
                processes.sort(key=lambda x: x[1], reverse=True)
                for name, cpu in processes[:5]:
                    print(f"  {name[:25]:25} {cpu:5.1f}%")
            except:
                print("  Unable to get process information")
            
            print()
            
            # Recent alerts
            if self.stats['alerts'] > 0:
                print(f"{Config.COLORS['BOLD']}RECENT ALERTS:{Config.COLORS['RESET']}")
                try:
                    conn = sqlite3.connect(Config.DB_PATH)
                    cursor = conn.cursor()
                    cursor.execute("""
                        SELECT severity, message, timestamp 
                        FROM alerts 
                        WHERE status = 'NEW' 
                        ORDER BY timestamp DESC 
                        LIMIT 3
                    """)
                    alerts = cursor.fetchall()
                    conn.close()
                    
                    for severity, message, timestamp in alerts:
                        severity_color = Config.COLORS['RED'] if severity in ['HIGH', 'CRITICAL'] else Config.COLORS['YELLOW'] if severity == 'MEDIUM' else Config.COLORS['BLUE']
                        time_str = datetime.fromisoformat(timestamp).strftime("%H:%M:%S")
                        print(f"  {severity_color}[{severity}] {time_str}: {message[:40]}...{Config.COLORS['RESET']}")
                except:
                    print("  Unable to load alerts")
                print()
            
            # Footer
            print(f"{Config.COLORS['CYAN']}{'='*80}{Config.COLORS['RESET']}")
            print(f"{Config.COLORS['DIM']}Press Ctrl+C to exit | HexaShield SOC v{Config.VERSION}{Config.COLORS['RESET']}")
            
        except Exception as e:
            print(f"{Config.COLORS['ERROR']}Error displaying dashboard: {e}{Config.COLORS['RESET']}")
    
    def stop(self):
        """Stop dashboard"""
        self.running = False
        if self.thread:
            self.thread.join(timeout=2)
        logger.log("INFO", "Dashboard stopped", "Dashboard")

# ============================================================================
# MAIN APPLICATION
# ============================================================================

class HexaShieldSOC:
    """Main HexaShield SOC Application"""
    
    def __init__(self):
        self.running = False
        self.components = {}
        
        logger.log("INFO", "HexaShield SOC application initializing...", "Main")
    
    def initialize(self):
        """Initialize all components"""
        try:
            # Initialize database
            self._initialize_database()
            
            # Initialize network monitor
            network_monitor = RealTimeNetworkMonitor()
            self.components['network'] = network_monitor
            
            # Initialize dashboard with network monitor reference
            dashboard = HexaShieldDashboard(network_monitor)
            self.components['dashboard'] = dashboard
            
            logger.log("SUCCESS", "All components initialized", "Main")
            
        except Exception as e:
            logger.log("ERROR", f"Failed to initialize components: {e}", "Main")
            raise
    
    def _initialize_database(self):
        """Initialize database schema"""
        try:
            conn = sqlite3.connect(Config.DB_PATH)
            cursor = conn.cursor()
            
            # Create alerts table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS alerts (
                    id TEXT PRIMARY KEY,
                    timestamp TEXT,
                    severity TEXT,
                    message TEXT,
                    details TEXT,
                    status TEXT,
                    resolved_time TEXT
                )
            ''')
            
            conn.commit()
            conn.close()
            
            logger.log("INFO", "Database initialized", "Main")
            
        except Exception as e:
            logger.log("ERROR", f"Failed to initialize database: {e}", "Main")
            raise
    
    def start(self):
        """Start all monitoring components"""
        try:
            self.running = True
            
            # Start network monitoring
            self.components['network'].start()
            time.sleep(1)
            
            # Start dashboard
            self.components['dashboard'].start()
            
            logger.log("SUCCESS", "HexaShield SOC started successfully", "Main")
            
            # Keep main thread alive
            while self.running:
                time.sleep(1)
            
        except KeyboardInterrupt:
            self.stop()
        except Exception as e:
            logger.log("ERROR", f"Failed to start monitoring: {e}", "Main")
            self.stop()
    
    def stop(self):
        """Stop all monitoring components"""
        self.running = False
        
        logger.log("INFO", "Stopping HexaShield SOC...", "Main")
        
        # Stop components in reverse order
        if 'dashboard' in self.components:
            self.components['dashboard'].stop()
        
        if 'network' in self.components:
            self.components['network'].stop()
        
        logger.log("SUCCESS", "HexaShield SOC stopped successfully", "Main")
        
        # Final message
        print(f"\n{Config.COLORS['GREEN']}{Config.COLORS['BOLD']}")
        print("╔══════════════════════════════════════════════════════════════╗")
        print("║          HEXASHIELD SOC - MONITORING COMPLETE               ║")
        print("║          Thank you for using HexaShield Security            ║")
        print("╚══════════════════════════════════════════════════════════════╝")
        print(f"{Config.COLORS['RESET']}")
        
        sys.exit(0)

# ============================================================================
# ENTRY POINT
# ============================================================================

def main():
    """Main entry point"""
    try:
        # Check if running as administrator (Windows)
        if os.name == 'nt':
            try:
                is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
                if not is_admin:
                    print(f"{Config.COLORS['YELLOW']}[!] Warning: Not running as administrator")
                    print("[!] Some features may be limited")
                    time.sleep(2)
            except:
                pass
        
        # Create and run SOC
        soc = HexaShieldSOC()
        soc.initialize()
        soc.start()
        
    except KeyboardInterrupt:
        print(f"\n{Config.COLORS['YELLOW']}[!] Interrupted by user{Config.COLORS['RESET']}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Config.COLORS['RED']}[!] Fatal error: {e}{Config.COLORS['RESET']}")
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()