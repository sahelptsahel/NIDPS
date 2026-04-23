"""
Database Manager - SQLite database for packet and threat storage
"""

import sqlite3
import os
import json
from datetime import datetime

class DatabaseManager:
    """Manage SQLite database for NIDPS"""
    
    def __init__(self):
        self.db_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            'database',
            'nidps.db'
        )
        
        # Create database directory
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        
        self.conn = None
        self.init_database()
        
    def init_database(self):
        """Initialize database and create tables"""
        try:
            self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self.conn.row_factory = sqlite3.Row
            cursor = self.conn.cursor()
            
            # Packets table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS packets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    src_ip TEXT,
                    dst_ip TEXT,
                    protocol TEXT,
                    length INTEGER,
                    threat_level TEXT DEFAULT 'Safe',
                    confidence REAL DEFAULT 0.0,
                    action TEXT DEFAULT 'Allowed',
                    raw_data TEXT
                )
            ''')
            
            # Threats table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS threats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    severity TEXT,
                    type TEXT,
                    source_ip TEXT,
                    destination_ip TEXT,
                    description TEXT,
                    confidence REAL,
                    blocked BOOLEAN DEFAULT 0,
                    details TEXT
                )
            ''')
            
            # Alerts table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    alert_type TEXT,
                    severity TEXT,
                    message TEXT,
                    sent_email BOOLEAN DEFAULT 0,
                    sent_sms BOOLEAN DEFAULT 0,
                    details TEXT
                )
            ''')
            
            # Statistics table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS statistics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    packets_total INTEGER,
                    threats_detected INTEGER,
                    threats_blocked INTEGER,
                    bandwidth_mb REAL,
                    false_positives INTEGER DEFAULT 0,
                    detection_accuracy REAL DEFAULT 0.0
                )
            ''')
            
            # Blocked IPs table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS blocked_ips (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT UNIQUE,
                    first_blocked DATETIME DEFAULT CURRENT_TIMESTAMP,
                    last_blocked DATETIME DEFAULT CURRENT_TIMESTAMP,
                    block_count INTEGER DEFAULT 1,
                    threat_type TEXT,
                    is_permanent BOOLEAN DEFAULT 0,
                    expires_at DATETIME
                )
            ''')
            
            # OTP Tokens table - for forgot password email verification
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS otp_tokens (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    username    TEXT    NOT NULL,
                    otp_code    TEXT    NOT NULL,
                    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
                    expires_at  DATETIME NOT NULL,
                    used        INTEGER  DEFAULT 0
                )
            ''')

            # Admin config table - stores admin account settings (email, etc.)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS admin_config (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    config_key  TEXT    UNIQUE NOT NULL,
                    config_val  TEXT,
                    updated_at  DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            # Create indices for better performance
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_packets_timestamp ON packets(timestamp)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_packets_src ON packets(src_ip)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_threats_timestamp ON threats(timestamp)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_threats_severity ON threats(severity)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_blocked_ips_ip ON blocked_ips(ip_address)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_otp_username ON otp_tokens(username)')
            
            self.conn.commit()
            
        except Exception as e:
            print(f"Database init error: {e}")
            
    def _sanitize(self, data: dict) -> str:
        """Remove non-JSON-serializable values (Scapy packets, bytes, etc.) and return JSON string."""
        clean = {}
        for k, v in data.items():
            if isinstance(v, (str, int, float, bool, type(None))):
                clean[k] = v
            elif isinstance(v, (list, tuple)):
                clean[k] = [x for x in v if isinstance(x, (str, int, float, bool, type(None)))]
            # Skip Scapy packet objects, bytes, and anything else non-serializable
        try:
            return json.dumps(clean)
        except Exception:
            return '{}'

    def store_packet(self, packet_info):
        """Store packet in database"""
        try:
            cursor = self.conn.cursor()
            
            cursor.execute('''
                INSERT INTO packets (src_ip, dst_ip, protocol, length, threat_level, confidence, action, raw_data)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                packet_info.get('src', 'Unknown'),
                packet_info.get('dst', 'Unknown'),
                packet_info.get('protocol', 'Unknown'),
                packet_info.get('length', 0),
                packet_info.get('threat_level', 'Safe'),
                packet_info.get('confidence', 0.0),
                packet_info.get('action', 'Allowed'),
                self._sanitize(packet_info)
            ))
            
            self.conn.commit()
            
            # Cleanup old packets (keep last 10000)
            cursor.execute('SELECT COUNT(*) FROM packets')
            count = cursor.fetchone()[0]
            if count > 10000:
                cursor.execute('''
                    DELETE FROM packets WHERE id IN (
                        SELECT id FROM packets ORDER BY timestamp ASC LIMIT 1000
                    )
                ''')
                self.conn.commit()
                
        except Exception as e:
            print(f"Store packet error: {e}")
            
    def store_threat(self, threat_info):
        """Store threat in database"""
        try:
            cursor = self.conn.cursor()
            
            cursor.execute('''
                INSERT INTO threats (severity, type, source_ip, destination_ip, description, confidence, blocked, details)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                threat_info.get('severity', 'Medium'),
                threat_info.get('type', 'Unknown'),
                threat_info.get('source', 'Unknown'),
                threat_info.get('destination', 'Unknown'),
                threat_info.get('description', ''),
                threat_info.get('confidence', 0.0),
                1 if threat_info.get('blocked', False) else 0,
                self._sanitize(threat_info)
            ))
            
            self.conn.commit()
            
        except Exception as e:
            print(f"Store threat error: {e}")
            
    def store_alert(self, alert_type, severity, message, sent_email=False, sent_sms=False):
        """Store alert in database"""
        try:
            cursor = self.conn.cursor()
            
            cursor.execute('''
                INSERT INTO alerts (alert_type, severity, message, sent_email, sent_sms)
                VALUES (?, ?, ?, ?, ?)
            ''', (alert_type, severity, message, sent_email, sent_sms))
            
            self.conn.commit()
            
        except Exception as e:
            print(f"Store alert error: {e}")
            
    def store_statistics(self, stats):
        """Store current statistics"""
        try:
            cursor = self.conn.cursor()
            
            cursor.execute('''
                INSERT INTO statistics (packets_total, threats_detected, threats_blocked, bandwidth_mb)
                VALUES (?, ?, ?, ?)
            ''', (
                stats.get('packets', 0),
                stats.get('threats', 0),
                stats.get('blocked', 0),
                stats.get('bandwidth', 0.0)
            ))
            
            self.conn.commit()
            
        except Exception as e:
            print(f"Store statistics error: {e}")
            
    def add_blocked_ip(self, ip_address, threat_type, is_permanent=False, duration_seconds=3600):
        """Add IP to blocked list"""
        try:
            cursor = self.conn.cursor()
            
            expires_at = None
            if not is_permanent:
                from datetime import timedelta
                expires_at = datetime.now() + timedelta(seconds=duration_seconds)
                
            cursor.execute('''
                INSERT OR REPLACE INTO blocked_ips (ip_address, threat_type, is_permanent, expires_at, block_count)
                VALUES (?, ?, ?, ?, 
                    COALESCE((SELECT block_count + 1 FROM blocked_ips WHERE ip_address = ?), 1))
            ''', (ip_address, threat_type, is_permanent, expires_at, ip_address))
            
            self.conn.commit()
            
        except Exception as e:
            print(f"Add blocked IP error: {e}")
            
    def get_record_count(self):
        """Get total record count"""
        try:
            cursor = self.conn.cursor()
            
            cursor.execute('SELECT COUNT(*) FROM packets')
            packet_count = cursor.fetchone()[0]
            
            cursor.execute('SELECT COUNT(*) FROM threats')
            threat_count = cursor.fetchone()[0]
            
            return packet_count + threat_count
            
        except:
            return 0
            
    def get_database_size(self):
        """Get database size in KB"""
        try:
            size = os.path.getsize(self.db_path) / 1024
            return size
        except:
            return 0.0
            
    def get_packets(self, limit=100, offset=0):
        """Get packets from database"""
        try:
            cursor = self.conn.cursor()
            
            cursor.execute('''
                SELECT * FROM packets 
                ORDER BY timestamp DESC 
                LIMIT ? OFFSET ?
            ''', (limit, offset))
            
            return cursor.fetchall()
            
        except:
            return []
            
    def get_threats(self, limit=100, offset=0, severity=None):
        """Get threats from database"""
        try:
            cursor = self.conn.cursor()
            
            if severity:
                cursor.execute('''
                    SELECT * FROM threats 
                    WHERE severity = ?
                    ORDER BY timestamp DESC 
                    LIMIT ? OFFSET ?
                ''', (severity, limit, offset))
            else:
                cursor.execute('''
                    SELECT * FROM threats 
                    ORDER BY timestamp DESC 
                    LIMIT ? OFFSET ?
                ''', (limit, offset))
            
            return cursor.fetchall()
            
        except:
            return []
            
    def get_statistics_history(self, hours=24):
        """Get statistics for last N hours"""
        try:
            cursor = self.conn.cursor()
            
            cursor.execute('''
                SELECT * FROM statistics 
                WHERE timestamp >= datetime('now', '-' || ? || ' hours')
                ORDER BY timestamp DESC
            ''', (hours,))
            
            return cursor.fetchall()
            
        except:
            return []
            
    def get_blocked_ips(self):
        """Get currently blocked IPs"""
        try:
            cursor = self.conn.cursor()
            
            cursor.execute('''
                SELECT * FROM blocked_ips 
                WHERE is_permanent = 1 OR expires_at > datetime('now')
                ORDER BY last_blocked DESC
            ''')
            
            return cursor.fetchall()
            
        except:
            return []
            
    def get_threat_statistics(self):
        """Get threat statistics"""
        try:
            cursor = self.conn.cursor()
            
            # Total threats
            cursor.execute('SELECT COUNT(*) FROM threats')
            total = cursor.fetchone()[0]
            
            # By severity
            cursor.execute('''
                SELECT severity, COUNT(*) as count 
                FROM threats 
                GROUP BY severity
            ''')
            by_severity = dict(cursor.fetchall())
            
            # By type
            cursor.execute('''
                SELECT type, COUNT(*) as count 
                FROM threats 
                GROUP BY type 
                ORDER BY count DESC 
                LIMIT 10
            ''')
            by_type = cursor.fetchall()
            
            # Top sources
            cursor.execute('''
                SELECT source_ip, COUNT(*) as count 
                FROM threats 
                GROUP BY source_ip 
                ORDER BY count DESC 
                LIMIT 10
            ''')
            top_sources = cursor.fetchall()
            
            return {
                'total': total,
                'by_severity': by_severity,
                'by_type': by_type,
                'top_sources': top_sources
            }
            
        except Exception as e:
            print(f"Get statistics error: {e}")
            return {}
            
    def cleanup_expired_blocks(self):
        """Remove expired IP blocks"""
        try:
            cursor = self.conn.cursor()
            
            cursor.execute('''
                DELETE FROM blocked_ips 
                WHERE is_permanent = 0 AND expires_at < datetime('now')
            ''')
            
            self.conn.commit()
            
        except Exception as e:
            print(f"Cleanup error: {e}")
            
    def vacuum_database(self):
        """Optimize database"""
        try:
            cursor = self.conn.cursor()
            cursor.execute('VACUUM')
            self.conn.commit()
        except Exception as e:
            print(f"Vacuum error: {e}")
            
    def export_to_csv(self, table_name, filename):
        """Export table to CSV"""
        try:
            import csv
            
            cursor = self.conn.cursor()
            cursor.execute(f'SELECT * FROM {table_name}')
            
            rows = cursor.fetchall()
            if not rows:
                return False
                
            with open(filename, 'w', newline='') as f:
                writer = csv.writer(f)
                
                # Write header
                writer.writerow([description[0] for description in cursor.description])
                
                # Write data
                writer.writerows(rows)
                
            return True
            
        except Exception as e:
            print(f"Export error: {e}")
            return False
            
    def close(self):
        """Close database connection"""
        if self.conn:
            try:
                self.conn.close()
            except:
                pass
