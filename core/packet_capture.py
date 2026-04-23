"""
Packet Capture Thread - Real-time network packet capture
"""

from PyQt5.QtCore import QThread, pyqtSignal
from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP
from datetime import datetime
import traceback

class PacketCaptureThread(QThread):
    """Thread for capturing network packets"""
    
    packet_received = pyqtSignal(dict)
    threat_detected = pyqtSignal(dict)
    error_occurred = pyqtSignal(str)
    
    def __init__(self, interface, detector, prevention_engine, alert_manager):
        super().__init__()
        self.interface = interface
        self.detector = detector
        self.prevention_engine = prevention_engine
        self.alert_manager = alert_manager
        self.running = False
        self.packet_count = 0
        
    def run(self):
        """Start packet capture"""
        self.running = True
        
        try:
            sniff(
                iface=self.interface,
                prn=self.process_packet,
                stop_filter=lambda x: not self.running,
                store=False
            )
        except PermissionError:
            self.error_occurred.emit(
                "Permission denied. Please run the application with sudo/administrator privileges."
            )
        except Exception as e:
            self.error_occurred.emit(f"Packet capture error: {str(e)}\n{traceback.format_exc()}")
            
    def process_packet(self, packet):
        """Process captured packet"""
        try:
            self.packet_count += 1
            
            # Extract packet information
            packet_info = self.extract_packet_info(packet)
            
            if packet_info:
                # Emit packet received signal
                self.packet_received.emit(packet_info)
                
                # Analyze packet for threats
                if self.detector:
                    threat_info = self.detector.analyze_packet(packet, packet_info)
                    
                    if threat_info and threat_info.get('is_threat', False):
                        # Apply prevention measures
                        blocked = False
                        if self.prevention_engine:
                            blocked = self.prevention_engine.block_threat(threat_info)
                            threat_info['blocked'] = blocked
                            
                        # Send alerts
                        if self.alert_manager:
                            self.alert_manager.send_alert(threat_info)
                            
                        # Emit threat detected signal
                        self.threat_detected.emit(threat_info)
                        
        except Exception as e:
            # Silently log packet processing errors to avoid spam
            pass
            
    def extract_packet_info(self, packet):
        """Extract relevant information from packet"""
        try:
            info = {
                'time': datetime.now().strftime("%H:%M:%S.%f")[:-3],
                'src': 'N/A',
                'dst': 'N/A',
                'protocol': 'Unknown',
                'length': len(packet),
                'threat_level': 'Safe',
                'action': 'Allowed',
                'raw_packet': packet
            }
            
            # Extract IP layer information
            if IP in packet:
                info['src'] = packet[IP].src
                info['dst'] = packet[IP].dst
                
                # Determine protocol
                if TCP in packet:
                    info['protocol'] = f"TCP:{packet[TCP].dport}"
                    info['sport'] = packet[TCP].sport
                    info['dport'] = packet[TCP].dport
                    info['flags'] = packet[TCP].flags
                elif UDP in packet:
                    info['protocol'] = f"UDP:{packet[UDP].dport}"
                    info['sport'] = packet[UDP].sport
                    info['dport'] = packet[UDP].dport
                elif ICMP in packet:
                    info['protocol'] = "ICMP"
                else:
                    info['protocol'] = f"IP ({packet[IP].proto})"
                    
            elif ARP in packet:
                info['protocol'] = "ARP"
                info['src'] = packet[ARP].psrc
                info['dst'] = packet[ARP].pdst
                
            return info
            
        except Exception as e:
            return None
            
    def stop(self):
        """Stop packet capture"""
        self.running = False
