"""
Configuration Manager - Handles all application configurations
"""

import json
import os
from datetime import datetime

class ConfigManager:
    """Manages application configuration"""
    
    def __init__(self):
        self.config_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            'config'
        )
        
        os.makedirs(self.config_dir, exist_ok=True)
        
        self.config_file = os.path.join(self.config_dir, 'app_config.json')
        self.config = self.load_config()
        
    def load_config(self):
        """Load configuration from file"""
        default_config = {
            'version': '1.0.0',
            'last_updated': datetime.now().isoformat(),
            'network': {
                'default_interface': 'eth0',
                'promiscuous_mode': True,
                'buffer_size': 65536
            },
            'detection': {
                'enable_gnn': True,
                'enable_signature': True,
                'enable_anomaly': True,
                'enable_behavioral': True,
                'confidence_threshold': 0.7
            },
            'prevention': {
                'auto_block': True,
                'block_duration': 3600,
                'permanent_block_threshold': 5,
                'enable_iptables': True
            },
            'alerts': {
                'email_enabled': False,
                'sms_enabled': False,
                'alert_on_critical': True,
                'alert_on_high': True,
                'alert_on_medium': False,
                'alert_on_low': False
            },
            'ui': {
                'theme': 'dark',
                'show_system_tray': True,
                'minimize_to_tray': True,
                'packet_display_limit': 100
            },
            'logging': {
                'log_level': 'INFO',
                'log_to_file': True,
                'max_log_size_mb': 100,
                'log_rotation': True
            },
            'distributed': {
                'enabled': False,
                'node_type': 'standalone',  # standalone, master, slave
                'master_address': '',
                'sync_interval': 60
            }
        }
        
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    loaded_config = json.load(f)
                    default_config.update(loaded_config)
            except:
                pass
                
        return default_config
        
    def save_config(self):
        """Save configuration to file"""
        try:
            self.config['last_updated'] = datetime.now().isoformat()
            
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=4)
                
            return True
        except Exception as e:
            return False
            
    def get(self, key, default=None):
        """Get configuration value"""
        keys = key.split('.')
        value = self.config
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
                
        return value
        
    def set(self, key, value):
        """Set configuration value"""
        keys = key.split('.')
        config = self.config
        
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
            
        config[keys[-1]] = value
        self.save_config()
        
    def save_settings(self, settings):
        """Save settings from settings dialog"""
        # Update email settings
        if 'email' in settings:
            email_conf = settings['email']
            self.config.setdefault('email', {})
            self.config['email'].update(email_conf)
            
        # Update SMS settings
        if 'sms' in settings:
            sms_conf = settings['sms']
            self.config.setdefault('sms', {})
            self.config['sms'].update(sms_conf)
            
        # Update detection settings
        if 'detection' in settings:
            det_conf = settings['detection']
            
            if 'alert_levels' in det_conf:
                self.config['alerts'].update({
                    'alert_on_critical': det_conf['alert_levels'].get('Critical', True),
                    'alert_on_high': det_conf['alert_levels'].get('High', True),
                    'alert_on_medium': det_conf['alert_levels'].get('Medium', False),
                    'alert_on_low': det_conf['alert_levels'].get('Low', False)
                })
                
            if 'thresholds' in det_conf:
                self.config['detection']['thresholds'] = det_conf['thresholds']
                
        # Update prevention settings
        if 'prevention' in settings:
            prev_conf = settings['prevention']
            self.config['prevention'].update(prev_conf)
            
        # Update general settings
        if 'general' in settings:
            gen_conf = settings['general']
            
            if 'log_level' in gen_conf:
                self.config['logging']['log_level'] = gen_conf['log_level']
                
            if 'packet_buffer' in gen_conf:
                self.config['ui']['packet_display_limit'] = gen_conf['packet_buffer']
                
        self.save_config()
        
    def export_config(self, filepath):
        """Export configuration to file"""
        try:
            with open(filepath, 'w') as f:
                json.dump(self.config, f, indent=4)
            return True
        except:
            return False
            
    def import_config(self, filepath):
        """Import configuration from file"""
        try:
            with open(filepath, 'r') as f:
                imported_config = json.load(f)
                self.config.update(imported_config)
                
            self.save_config()
            return True
        except:
            return False
            
    def reset_to_defaults(self):
        """Reset configuration to defaults"""
        if os.path.exists(self.config_file):
            os.remove(self.config_file)
            
        self.config = self.load_config()
        self.save_config()
