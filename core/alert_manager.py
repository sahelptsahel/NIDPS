"""
Alert Manager - Email and SMS notification system
"""

import smtplib
import json
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
import requests

class AlertManager:
    """Manage security alerts and notifications"""
    
    def __init__(self, config_manager):
        self.config_manager = config_manager
        self.config = self.load_config()
        self.alert_history = []
        
    def load_config(self):
        """Load alert configuration"""
        config_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            'config',
            'alert_config.json'
        )
        
        default_config = {
            'email': {
                'enabled': False,
                'smtp_server': 'smtp.gmail.com',
                'smtp_port': 587,
                'sender_email': '',
                'sender_password': '',
                'recipient_emails': [],
                'use_tls': True
            },
            'sms': {
                'enabled': False,
                'provider': 'twilio',  # or 'nexmo'
                'account_sid': '',
                'auth_token': '',
                'from_number': '',
                'to_numbers': []
            },
            'alert_levels': {
                'Critical': True,
                'High': True,
                'Medium': False,
                'Low': False
            },
            'rate_limit': {
                'enabled': True,
                'max_alerts_per_minute': 10
            }
        }
        
        if os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    loaded_config = json.load(f)
                    default_config.update(loaded_config)
            except:
                pass
                
        return default_config
        
    def save_config(self):
        """Save alert configuration"""
        config_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            'config',
            'alert_config.json'
        )
        
        try:
            os.makedirs(os.path.dirname(config_path), exist_ok=True)
            with open(config_path, 'w') as f:
                json.dump(self.config, f, indent=4)
        except Exception as e:
            pass
            
    def send_alert(self, threat_info):
        """Send alert for detected threat"""
        severity = threat_info.get('severity', 'Medium')
        
        # Check if we should alert for this severity level
        if not self.config['alert_levels'].get(severity, False):
            return
            
        # Check rate limiting
        if not self.check_rate_limit():
            return
            
        # Record alert
        self.alert_history.append({
            'timestamp': datetime.now(),
            'threat_info': threat_info
        })
        
        # Send email alert
        if self.config['email']['enabled']:
            self.send_email_alert(threat_info)
            
        # Send SMS alert
        if self.config['sms']['enabled']:
            self.send_sms_alert(threat_info)
            
    def send_email_alert(self, threat_info):
        """Send email alert"""
        try:
            email_config = self.config['email']
            
            # Create message
            msg = MIMEMultipart('alternative')
            msg['Subject'] = f"[NIDPS] {threat_info['severity']} Security Alert"
            msg['From'] = email_config['sender_email']
            msg['To'] = ', '.join(email_config['recipient_emails'])
            
            # Create HTML content
            html_content = self.create_email_html(threat_info)
            
            # Create text content
            text_content = self.create_email_text(threat_info)
            
            part1 = MIMEText(text_content, 'plain')
            part2 = MIMEText(html_content, 'html')
            
            msg.attach(part1)
            msg.attach(part2)
            
            # Send email
            with smtplib.SMTP(email_config['smtp_server'], email_config['smtp_port']) as server:
                if email_config['use_tls']:
                    server.starttls()
                    
                server.login(email_config['sender_email'], email_config['sender_password'])
                server.send_message(msg)
                
            return True
            
        except Exception as e:
            return False
            
    def create_email_text(self, threat_info):
        """Create plain text email content"""
        text = f"""
NETWORK INTRUSION DETECTION ALERT

Severity: {threat_info.get('severity', 'Unknown')}
Threat Type: {threat_info.get('type', 'Unknown')}
Source: {threat_info.get('source', 'Unknown')}
Destination: {threat_info.get('destination', 'Unknown')}
Protocol: {threat_info.get('protocol', 'Unknown')}
Timestamp: {threat_info.get('timestamp', 'Unknown')}

Description:
{threat_info.get('description', 'No description available')}

Action Taken:
{'Threat blocked and source IP added to blacklist' if threat_info.get('blocked', False) else 'Threat detected but not blocked'}

---
This is an automated alert from your Network Intrusion Detection & Prevention System
"""
        return text
        
    def create_email_html(self, threat_info):
        """Create HTML email content"""
        severity_colors = {
            'Critical': '#F44336',
            'High': '#FF9800',
            'Medium': '#FFC107',
            'Low': '#4CAF50'
        }
        
        color = severity_colors.get(threat_info.get('severity', 'Medium'), '#FFC107')
        
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }}
        .container {{ max-width: 600px; margin: 0 auto; background-color: white; border-radius: 10px; overflow: hidden; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .header {{ background-color: {color}; color: white; padding: 20px; text-align: center; }}
        .content {{ padding: 20px; }}
        .info-row {{ margin: 15px 0; padding: 10px; background-color: #f9f9f9; border-left: 4px solid {color}; }}
        .label {{ font-weight: bold; color: #333; }}
        .value {{ color: #666; margin-top: 5px; }}
        .footer {{ background-color: #333; color: white; padding: 15px; text-align: center; font-size: 12px; }}
        .action-box {{ background-color: #e8f5e9; border: 2px solid #4CAF50; padding: 15px; margin: 15px 0; border-radius: 5px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ SECURITY ALERT</h1>
            <h2>{threat_info.get('severity', 'Unknown')} Threat Detected</h2>
        </div>
        
        <div class="content">
            <div class="info-row">
                <div class="label">Threat Type:</div>
                <div class="value">{threat_info.get('type', 'Unknown')}</div>
            </div>
            
            <div class="info-row">
                <div class="label">Source IP:</div>
                <div class="value">{threat_info.get('source', 'Unknown')}</div>
            </div>
            
            <div class="info-row">
                <div class="label">Destination IP:</div>
                <div class="value">{threat_info.get('destination', 'Unknown')}</div>
            </div>
            
            <div class="info-row">
                <div class="label">Protocol:</div>
                <div class="value">{threat_info.get('protocol', 'Unknown')}</div>
            </div>
            
            <div class="info-row">
                <div class="label">Detection Time:</div>
                <div class="value">{threat_info.get('timestamp', 'Unknown')}</div>
            </div>
            
            <div class="info-row">
                <div class="label">Description:</div>
                <div class="value">{threat_info.get('description', 'No description available')}</div>
            </div>
            
            <div class="action-box">
                <strong>Action Taken:</strong><br>
                {'✅ Threat blocked successfully. Source IP has been added to the blacklist.' if threat_info.get('blocked', False) else '⚠️ Threat detected but not blocked automatically.'}
            </div>
        </div>
        
        <div class="footer">
            <p>This is an automated alert from your Network Intrusion Detection & Prevention System</p>
            <p>NIDPS v1.0 © 2024</p>
        </div>
    </div>
</body>
</html>
"""
        return html
        
    def send_sms_alert(self, threat_info):
        """Send SMS alert"""
        try:
            sms_config = self.config['sms']
            
            # Create SMS message
            message = (f"NIDPS ALERT: {threat_info['severity']} threat detected - "
                      f"{threat_info['type']} from {threat_info['source']}")
            
            # Truncate message if too long
            if len(message) > 160:
                message = message[:157] + "..."
                
            # Send via Twilio
            if sms_config['provider'] == 'twilio':
                return self.send_twilio_sms(message, sms_config)
            # Add other providers as needed
            
        except Exception as e:
            return False
            
    def send_twilio_sms(self, message, sms_config):
        """Send SMS via Twilio"""
        try:
            from twilio.rest import Client
            
            client = Client(sms_config['account_sid'], sms_config['auth_token'])
            
            for to_number in sms_config['to_numbers']:
                client.messages.create(
                    body=message,
                    from_=sms_config['from_number'],
                    to=to_number
                )
                
            return True
            
        except Exception as e:
            # Twilio not available or error occurred
            return False
            
    def check_rate_limit(self):
        """Check if alert rate limit is exceeded"""
        if not self.config['rate_limit']['enabled']:
            return True
            
        # Clean old alerts (older than 1 minute)
        current_time = datetime.now()
        self.alert_history = [
            a for a in self.alert_history
            if (current_time - a['timestamp']).total_seconds() < 60
        ]
        
        # Check limit
        max_alerts = self.config['rate_limit']['max_alerts_per_minute']
        return len(self.alert_history) < max_alerts
        
    def update_config(self, new_config):
        """Update alert configuration"""
        self.config.update(new_config)
        self.save_config()
        
    def send_test_email(self):
        """Send test email — called from UI"""
        email_config = self.config.get('email', {})
        if not email_config.get('enabled', False):
            raise RuntimeError(
                "Email alerts are disabled.\n\n"
                "Go to Tools → Settings → Alerts tab and:\n"
                "1. Tick 'Enable Email Alerts'\n"
                "2. Enter your SMTP server, port, sender and recipient emails\n"
                "3. Click Save"
            )
        if not email_config.get('sender_email') or not email_config.get('recipient_emails'):
            raise RuntimeError(
                "Email not configured.\n\n"
                "Go to Tools → Settings → Alerts tab and fill in:\n"
                "• Sender email + password\n"
                "• Recipient email(s)\n"
                "• SMTP server (e.g. smtp.gmail.com) and port (587)"
            )
        result = self.test_email()
        if not result:
            raise RuntimeError(
                "Email send failed.\n\n"
                "Common fixes:\n"
                "• For Gmail: enable 2FA and use an App Password\n"
                "• Check SMTP server and port settings\n"
                "• Verify credentials are correct"
            )
        return True

    def send_test_sms(self):
        """Send test SMS — called from UI"""
        sms_config = self.config.get('sms', {})
        if not sms_config.get('enabled', False):
            raise RuntimeError(
                "SMS alerts are disabled.\n\n"
                "Go to Tools → Settings → Alerts tab and:\n"
                "1. Tick 'Enable SMS Alerts'\n"
                "2. Enter Twilio Account SID, Auth Token, From/To numbers\n"
                "3. Click Save"
            )
        if not sms_config.get('account_sid') or not sms_config.get('auth_token'):
            raise RuntimeError(
                "SMS not configured.\n\n"
                "Go to Tools → Settings → Alerts tab and fill in:\n"
                "• Twilio Account SID and Auth Token\n"
                "• From number (your Twilio number)\n"
                "• To number(s) to receive alerts"
            )
        result = self.test_sms()
        if not result:
            raise RuntimeError(
                "SMS send failed.\n\n"
                "Common fixes:\n"
                "• Verify Twilio credentials\n"
                "• Ensure 'twilio' package is installed: pip install twilio\n"
                "• Check that from/to numbers include country code (+1...)"
            )
        return True

    def test_email(self):
        """Send test email"""
        test_threat = {
            'severity': 'Low',
            'type': 'Test Alert',
            'source': '192.168.1.100',
            'destination': '192.168.1.1',
            'protocol': 'TCP',
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'description': 'This is a test alert to verify email configuration.',
            'blocked': False
        }
        
        return self.send_email_alert(test_threat)
        
    def test_sms(self):
        """Send test SMS"""
        test_threat = {
            'severity': 'Low',
            'type': 'Test Alert',
            'source': '192.168.1.100'
        }
        
        return self.send_sms_alert(test_threat)
