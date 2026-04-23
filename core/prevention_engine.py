"""
Prevention Engine - Automated threat blocking and mitigation
"""

import subprocess
import os
import json
from datetime import datetime, timedelta
from collections import defaultdict

class PreventionEngine:
    """Automated threat prevention and blocking"""
    
    def __init__(self):
        self.blocked_ips = set()
        self.blocked_ports = set()
        self.block_history = []
        self.temp_blocks = defaultdict(datetime.now)
        
        # Prevention policies
        self.policies = {
            'auto_block': True,
            'block_duration': 3600,  # 1 hour in seconds
            'permanent_block_threshold': 5,  # Block permanently after 5 incidents
            'enable_iptables': True,
            'enable_rate_limiting': True
        }
        
        self.load_policies()
        
    def load_policies(self):
        """Load prevention policies from config"""
        config_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            'config',
            'prevention_policies.json'
        )
        
        if os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    self.policies.update(json.load(f))
            except:
                pass
                
    def save_policies(self):
        """Save prevention policies to config"""
        config_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            'config',
            'prevention_policies.json'
        )
        
        try:
            os.makedirs(os.path.dirname(config_path), exist_ok=True)
            with open(config_path, 'w') as f:
                json.dump(self.policies, f, indent=4)
        except:
            pass
            
    def block_threat(self, threat_info, force=False):
        """Block detected threat"""
        if not self.policies.get('auto_block', True):
            return False

        source_ip = threat_info.get('source', '')
        severity  = threat_info.get('severity', 'Low')

        if not source_ip or source_ip in ('Unknown', 'N/A', ''):
            return False

        # Skip private/local IPs unless forced (can be overridden in settings)
        if self.is_local_ip(source_ip) and not self.policies.get('block_local_ips', False) and not force:
            return False

        # Critical and High → block immediately
        if severity in ('Critical', 'High'):
            return self.apply_block(source_ip, threat_info)

        # Medium → block after 3 incidents
        if severity == 'Medium':
            incident_count = sum(1 for b in self.block_history if b.get('ip') == source_ip)
            if incident_count >= 3:
                return self.apply_block(source_ip, threat_info)

        return False
        
    def apply_block(self, ip_address, threat_info):
        """Apply blocking rules - returns True if block was applied"""
        try:
            # Already in memory block list
            if ip_address in self.blocked_ips:
                return True

            self.blocked_ips.add(ip_address)

            # Record in history (use 'ip' key consistently)
            self.block_history.append({
                'ip':          ip_address,
                'source':      ip_address,
                'threat_type': threat_info.get('type', 'Unknown'),
                'severity':    threat_info.get('severity', 'Unknown'),
                'timestamp':   datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            })

            # iptables rule (requires root)
            iptables_ok = False
            if self.policies.get('enable_iptables', True):
                iptables_ok = self.add_iptables_rule(ip_address)

            # Temporary block expiry
            incident_count = sum(1 for b in self.block_history if b.get('ip') == ip_address)
            if incident_count < self.policies.get('permanent_block_threshold', 5):
                duration = self.policies.get('block_duration', 3600)
                self.temp_blocks[ip_address] = datetime.now() + timedelta(seconds=duration)

            print(f"[BLOCK] {ip_address} | iptables={'✓' if iptables_ok else '✗ (need root)'}")
            return True

        except Exception as e:
            print(f"[BLOCK ERROR] {ip_address}: {e}")
            return False
            
    def add_iptables_rule(self, ip_address):
        """Add iptables blocking rule"""
        try:
            # Check if running with sufficient privileges
            if os.geteuid() != 0:
                # Not running as root, can't modify iptables
                return False
                
            # Add DROP rule
            cmd = f"iptables -A INPUT -s {ip_address} -j DROP"
            subprocess.run(cmd.split(), capture_output=True)
            
            return True
            
        except Exception as e:
            return False
            
    def remove_iptables_rule(self, ip_address):
        """Remove iptables blocking rule"""
        try:
            if os.geteuid() != 0:
                return False
                
            # Remove DROP rule
            cmd = f"iptables -D INPUT -s {ip_address} -j DROP"
            subprocess.run(cmd.split(), capture_output=True)
            
            return True
            
        except Exception as e:
            return False
            
    def unblock_ip(self, ip_address):
        """Unblock an IP address"""
        if ip_address in self.blocked_ips:
            self.blocked_ips.remove(ip_address)
            
        if ip_address in self.temp_blocks:
            del self.temp_blocks[ip_address]
            
        # Remove iptables rule
        self.remove_iptables_rule(ip_address)
        
        return True
        
    def check_temp_blocks(self):
        """Check and remove expired temporary blocks"""
        current_time = datetime.now()
        expired = []
        
        for ip, expiry_time in self.temp_blocks.items():
            if current_time >= expiry_time:
                expired.append(ip)
                
        for ip in expired:
            self.unblock_ip(ip)
            
    def is_local_ip(self, ip_address):
        """Check if IP is local/private"""
        try:
            parts = ip_address.split('.')
            if len(parts) != 4:
                return False
                
            # Check for private IP ranges
            first_octet = int(parts[0])
            second_octet = int(parts[1])
            
            # 10.0.0.0/8
            if first_octet == 10:
                return True
                
            # 172.16.0.0/12
            if first_octet == 172 and 16 <= second_octet <= 31:
                return True
                
            # 192.168.0.0/16
            if first_octet == 192 and second_octet == 168:
                return True
                
            # Loopback
            if first_octet == 127:
                return True
                
            return False
            
        except:
            return False
            
    def get_blocked_ips(self):
        """Get list of currently blocked IPs"""
        return list(self.blocked_ips)
        
    def get_block_history(self):
        """Get blocking history"""
        return self.block_history
        
    def clear_all_blocks(self):
        """Clear all blocks"""
        for ip in list(self.blocked_ips):
            self.unblock_ip(ip)
            
        self.block_history.clear()
        
    def apply_rate_limiting(self, ip_address, rate_limit):
        """Apply rate limiting to an IP"""
        try:
            if os.geteuid() != 0:
                return False
                
            # Use iptables hashlimit module for rate limiting
            cmd = (f"iptables -A INPUT -s {ip_address} -m hashlimit "
                   f"--hashlimit-above {rate_limit}/sec --hashlimit-mode srcip "
                   f"--hashlimit-name ratelimit -j DROP")
            
            subprocess.run(cmd.split(), capture_output=True)
            return True
            
        except Exception as e:
            return False
