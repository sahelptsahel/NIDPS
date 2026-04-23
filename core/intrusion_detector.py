"""
Intrusion Detection Engine - GNN-based and Hybrid Detection
"""

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from datetime import datetime
import pickle
import os
from collections import defaultdict, deque

class GNNDetector(nn.Module):
    """Graph Neural Network for intrusion detection"""
    
    def __init__(self, input_dim=20, hidden_dim=64, output_dim=2):
        super(GNNDetector, self).__init__()
        
        self.fc1 = nn.Linear(input_dim, hidden_dim)
        self.fc2 = nn.Linear(hidden_dim, hidden_dim)
        self.fc3 = nn.Linear(hidden_dim, output_dim)
        
        self.dropout = nn.Dropout(0.3)
        
    def forward(self, x):
        """Forward pass"""
        x = F.relu(self.fc1(x))
        x = self.dropout(x)
        x = F.relu(self.fc2(x))
        x = self.dropout(x)
        x = self.fc3(x)
        return F.softmax(x, dim=1)

class IntrusionDetector:
    """Main intrusion detection engine"""
    
    def __init__(self):
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        
        # Initialize GNN model
        self.gnn_model = GNNDetector().to(self.device)
        self.load_model()
        
        # Statistical trackers
        self.connection_tracker = defaultdict(lambda: {
            'count': 0,
            'first_seen': None,
            'last_seen': None,
            'ports': set(),
            'flags': []
        })
        
        self.traffic_history = defaultdict(lambda: deque(maxlen=100))
        
        # Threat signatures
        self.threat_signatures = self.load_threat_signatures()
        
        # Detection thresholds
        self.thresholds = {
            'port_scan': {'unique_ports': 20, 'time_window': 60},
            'ddos': {'packet_rate': 1000, 'time_window': 10},
            'brute_force': {'attempts': 5, 'time_window': 300},
            'syn_flood': {'syn_count': 100, 'time_window': 5}
        }
        
    def load_model(self):
        """Load pre-trained GNN model (supports both raw state_dict and metadata dict)"""
        model_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            'models',
            'gnn_model.pth'
        )

        if os.path.exists(model_path):
            try:
                data = torch.load(model_path, map_location=self.device)

                # New format: dict with 'state_dict' + metadata
                if isinstance(data, dict) and 'state_dict' in data:
                    input_dim  = data.get('input_dim',  20)
                    hidden_dim = data.get('hidden_dim', 64)
                    # Rebuild model with saved dimensions if different
                    if (input_dim != 20 or hidden_dim != 64):
                        self.gnn_model = GNNDetector(
                            input_dim=input_dim,
                            hidden_dim=hidden_dim
                        ).to(self.device)
                    self.gnn_model.load_state_dict(data['state_dict'])
                else:
                    # Legacy format: raw state_dict
                    self.gnn_model.load_state_dict(data)

                self.gnn_model.eval()
            except Exception:
                # Model file corrupt or incompatible; continue with random weights
                pass
                
    def load_threat_signatures(self):
        """Load known threat signatures"""
        return {
            'malware_ports': [4444, 5555, 6666, 6667, 31337, 12345],
            'suspicious_ports': [23, 135, 139, 445, 1433, 3306, 3389],
            'known_malicious_ips': set(),  # Can be loaded from file
            'ddos_patterns': ['SYN flood', 'UDP flood', 'ICMP flood']
        }
        
    def analyze_packet(self, packet, packet_info):
        """Analyze packet for threats using hybrid approach"""
        threats = []
        
        # 1. Signature-based detection
        sig_threat = self.signature_detection(packet_info)
        if sig_threat:
            threats.append(sig_threat)
            
        # 2. Anomaly-based detection
        anom_threat = self.anomaly_detection(packet_info)
        if anom_threat:
            threats.append(anom_threat)
            
        # 3. Behavioral analysis
        behav_threat = self.behavioral_analysis(packet_info)
        if behav_threat:
            threats.append(behav_threat)
            
        # 4. GNN-based detection
        gnn_threat = self.gnn_detection(packet_info)
        if gnn_threat:
            threats.append(gnn_threat)
            
        # Combine threat assessments
        if threats:
            return self.aggregate_threats(threats, packet_info)
            
        return None
        
    def signature_detection(self, packet_info):
        """Signature-based threat detection"""
        threat = None
        
        # Check for malware ports
        if 'dport' in packet_info:
            dport = packet_info['dport']
            
            if dport in self.threat_signatures['malware_ports']:
                return {
                    'type': 'Malware Communication',
                    'severity': 'Critical',
                    'confidence': 0.95,
                    'reason': f'Communication on malware port {dport}'
                }
                
            if dport in self.threat_signatures['suspicious_ports']:
                return {
                    'type': 'Suspicious Port Access',
                    'severity': 'High',
                    'confidence': 0.75,
                    'reason': f'Access to suspicious port {dport}'
                }
                
        # Check for known malicious IPs
        src_ip = packet_info.get('src', '')
        if src_ip in self.threat_signatures['known_malicious_ips']:
            return {
                'type': 'Known Malicious Source',
                'severity': 'Critical',
                'confidence': 0.98,
                'reason': f'Traffic from known malicious IP {src_ip}'
            }
            
        return threat
        
    def anomaly_detection(self, packet_info):
        """Anomaly-based detection using statistical methods"""
        src_ip = packet_info.get('src', '')
        
        if not src_ip or src_ip == 'N/A':
            return None
            
        # Track connection
        tracker = self.connection_tracker[src_ip]
        tracker['count'] += 1
        tracker['last_seen'] = datetime.now()
        
        if tracker['first_seen'] is None:
            tracker['first_seen'] = datetime.now()
            
        # Port scan detection
        if 'dport' in packet_info:
            tracker['ports'].add(packet_info['dport'])
            
            time_delta = (tracker['last_seen'] - tracker['first_seen']).total_seconds()
            
            if (len(tracker['ports']) >= self.thresholds['port_scan']['unique_ports'] and
                time_delta <= self.thresholds['port_scan']['time_window']):
                return {
                    'type': 'Port Scan',
                    'severity': 'High',
                    'confidence': 0.85,
                    'reason': f'Scanned {len(tracker["ports"])} ports in {time_delta:.1f}s'
                }
                
        # SYN flood detection
        if 'flags' in packet_info:
            tracker['flags'].append(packet_info['flags'])
            
            # Keep only recent flags
            if len(tracker['flags']) > 200:
                tracker['flags'] = tracker['flags'][-200:]
                
            syn_count = sum(1 for f in tracker['flags'][-100:] if 'S' in str(f) and 'A' not in str(f))
            
            if syn_count >= self.thresholds['syn_flood']['syn_count']:
                return {
                    'type': 'SYN Flood Attack',
                    'severity': 'Critical',
                    'confidence': 0.90,
                    'reason': f'Detected {syn_count} SYN packets without ACK'
                }
                
        # DDoS detection - high packet rate
        self.traffic_history[src_ip].append(datetime.now())
        
        # Check packet rate
        if len(self.traffic_history[src_ip]) >= 10:
            recent_packets = list(self.traffic_history[src_ip])[-10:]
            time_span = (recent_packets[-1] - recent_packets[0]).total_seconds()
            
            if time_span > 0:
                packet_rate = len(recent_packets) / time_span
                
                if packet_rate >= self.thresholds['ddos']['packet_rate']:
                    return {
                        'type': 'DDoS Attack',
                        'severity': 'Critical',
                        'confidence': 0.92,
                        'reason': f'High packet rate: {packet_rate:.1f} packets/sec'
                    }
                    
        return None
        
    def behavioral_analysis(self, packet_info):
        """Behavioral pattern analysis"""
        protocol = packet_info.get('protocol', '')
        
        # Detect unusual protocol usage patterns
        if 'TCP' in protocol:
            # Check for unusual flag combinations
            if 'flags' in packet_info:
                flags = str(packet_info['flags'])
                
                # XMAS scan detection (FIN, PSH, URG)
                if 'F' in flags and 'P' in flags and 'U' in flags:
                    return {
                        'type': 'XMAS Scan',
                        'severity': 'High',
                        'confidence': 0.88,
                        'reason': 'Detected XMAS scan pattern'
                    }
                    
                # NULL scan detection
                if flags == '':
                    return {
                        'type': 'NULL Scan',
                        'severity': 'High',
                        'confidence': 0.87,
                        'reason': 'Detected NULL scan pattern'
                    }
                    
        # Detect fragmented packet attacks
        length = packet_info.get('length', 0)
        if length < 20 or length > 65535:
            return {
                'type': 'Malformed Packet',
                'severity': 'Medium',
                'confidence': 0.70,
                'reason': f'Unusual packet length: {length}'
            }
            
        return None
        
    def gnn_detection(self, packet_info):
        """GNN-based detection"""
        try:
            # Extract features for GNN
            features = self.extract_features(packet_info)
            
            if features is None:
                return None
                
            # Convert to tensor
            x = torch.FloatTensor(features).unsqueeze(0).to(self.device)
            
            # Make prediction
            with torch.no_grad():
                output = self.gnn_model(x)
                threat_prob = output[0][1].item()  # Probability of threat
                
            # Threshold for classification
            if threat_prob > 0.7:
                return {
                    'type': 'GNN Detected Anomaly',
                    'severity': 'High' if threat_prob > 0.85 else 'Medium',
                    'confidence': threat_prob,
                    'reason': f'GNN model detected anomaly (confidence: {threat_prob:.2%})'
                }
                
        except Exception as e:
            # GNN detection failed, skip silently
            pass
            
        return None
        
    def extract_features(self, packet_info):
        """Extract features for GNN model"""
        try:
            features = []
            
            # Protocol encoding
            protocol = packet_info.get('protocol', 'Unknown')
            if 'TCP' in protocol:
                features.extend([1, 0, 0])
            elif 'UDP' in protocol:
                features.extend([0, 1, 0])
            elif 'ICMP' in protocol:
                features.extend([0, 0, 1])
            else:
                features.extend([0, 0, 0])
                
            # Port information (normalized)
            features.append(packet_info.get('dport', 0) / 65535.0 if 'dport' in packet_info else 0)
            features.append(packet_info.get('sport', 0) / 65535.0 if 'sport' in packet_info else 0)
            
            # Packet length (normalized)
            features.append(packet_info.get('length', 0) / 65535.0)
            
            # IP address features (simplified)
            src_ip = packet_info.get('src', '0.0.0.0')
            if src_ip != 'N/A':
                try:
                    parts = src_ip.split('.')
                    features.extend([int(p) / 255.0 for p in parts])
                except:
                    features.extend([0, 0, 0, 0])
            else:
                features.extend([0, 0, 0, 0])
                
            # Connection statistics
            tracker = self.connection_tracker.get(src_ip, {})
            features.append(min(tracker.get('count', 0) / 1000.0, 1.0))
            features.append(min(len(tracker.get('ports', set())) / 100.0, 1.0))
            
            # Time-based features
            features.append(datetime.now().hour / 24.0)
            features.append(datetime.now().minute / 60.0)
            
            # Pad or truncate to 20 features
            while len(features) < 20:
                features.append(0)
            features = features[:20]
            
            return features
            
        except Exception as e:
            return None
            
    def aggregate_threats(self, threats, packet_info):
        """Aggregate multiple threat detections"""
        # Find highest severity
        severity_order = {'Critical': 3, 'High': 2, 'Medium': 1, 'Low': 0}
        
        highest_threat = max(threats, key=lambda t: (
            severity_order.get(t['severity'], 0),
            t.get('confidence', 0)
        ))
        
        # Combine threat types
        threat_types = ', '.join(set(t['type'] for t in threats))
        
        # Average confidence
        avg_confidence = sum(t.get('confidence', 0.5) for t in threats) / len(threats)
        
        return {
            'is_threat': True,
            'type': threat_types,
            'severity': highest_threat['severity'],
            'confidence': avg_confidence,
            'source': packet_info.get('src', 'Unknown'),
            'destination': packet_info.get('dst', 'Unknown'),
            'protocol': packet_info.get('protocol', 'Unknown'),
            'description': highest_threat['reason'],
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'detections': len(threats),
            'raw_packet': packet_info.get('raw_packet')
        }
        
    def cleanup_old_connections(self):
        """Cleanup old connection tracking data"""
        current_time = datetime.now()
        timeout = 300  # 5 minutes
        
        to_delete = []
        for ip, tracker in self.connection_tracker.items():
            if tracker['last_seen']:
                age = (current_time - tracker['last_seen']).total_seconds()
                if age > timeout:
                    to_delete.append(ip)
                    
        for ip in to_delete:
            del self.connection_tracker[ip]
            if ip in self.traffic_history:
                del self.traffic_history[ip]
