"""Report Generation Module"""
from datetime import datetime
import os

class ReportGenerator:
    def __init__(self, db_manager, stats):
        self.db_manager = db_manager
        self.stats = stats
        
    def generate(self, report_type, format_type):
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"report_{timestamp}.{format_type.lower()}"
            filepath = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', filename)
            
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            
            if format_type == "CSV":
                return self.generate_csv(filepath)
            elif format_type == "HTML":
                return self.generate_html(filepath)
            elif format_type == "PDF":
                return self.generate_pdf(filepath)
            else:
                return self.generate_json(filepath)
                
        except Exception as e:
            print(f"Report generation error: {e}")
            return None
            
    def generate_csv(self, filepath):
        self.db_manager.export_to_csv('threats', filepath)
        return filepath
        
    def generate_html(self, filepath):
        html = f"""
        <html>
        <head><title>NIDPS Security Report</title></head>
        <body>
        <h1>Network Security Report</h1>
        <p>Generated: {datetime.now()}</p>
        <h2>Statistics</h2>
        <p>Packets: {self.stats.get('packets', 0)}</p>
        <p>Threats: {self.stats.get('threats', 0)}</p>
        <p>Blocked: {self.stats.get('blocked', 0)}</p>
        </body>
        </html>
        """
        with open(filepath, 'w') as f:
            f.write(html)
        return filepath
        
    def generate_pdf(self, filepath):
        # Simplified PDF generation
        with open(filepath.replace('.pdf', '.txt'), 'w') as f:
            f.write(f"NIDPS Security Report\n")
            f.write(f"Generated: {datetime.now()}\n\n")
            f.write(f"Packets: {self.stats.get('packets', 0)}\n")
            f.write(f"Threats: {self.stats.get('threats', 0)}\n")
            f.write(f"Blocked: {self.stats.get('blocked', 0)}\n")
        return filepath.replace('.pdf', '.txt')
        
    def generate_json(self, filepath):
        import json
        data = {
            'timestamp': datetime.now().isoformat(),
            'statistics': self.stats,
            'threats': []
        }
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
        return filepath
