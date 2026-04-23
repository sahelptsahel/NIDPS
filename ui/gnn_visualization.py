"""
GNN Visualization Widget - Real-time Graph Neural Network Visualization
"""

from PyQt5.QtWidgets import QWidget
from PyQt5.QtCore import Qt, QTimer, QPointF
from PyQt5.QtGui import QPainter, QColor, QPen, QBrush, QRadialGradient, QFont
import math
import random

class Node:
    """Graph node for GNN visualization"""
    
    def __init__(self, x, y, node_type="input", value=0):
        self.x = x
        self.y = y
        self.type = node_type  # input, hidden, output
        self.value = value  # Activation value 0-1
        self.is_threat = False
        self.connections = []
        
class Connection:
    """Connection between nodes"""
    
    def __init__(self, from_node, to_node, weight=0.5):
        self.from_node = from_node
        self.to_node = to_node
        self.weight = weight  # 0-1
        self.active = False

class GNNVisualizationWidget(QWidget):
    """Real-time GNN network visualization"""
    
    def __init__(self):
        super().__init__()
        self.setMinimumSize(300, 300)
        
        # GNN structure: 20 input, 64 hidden, 2 output
        self.nodes = []
        self.connections = []
        
        self.init_network()
        
        # Animation timer
        self.anim_timer = QTimer()
        self.anim_timer.timeout.connect(self.animate)
        self.anim_timer.start(50)  # 20 FPS
        
        self.pulse_phase = 0
        
    def init_network(self):
        """Initialize GNN structure"""
        width = 300
        height = 300
        
        # Create layers
        # Input layer (20 nodes) - show subset
        input_count = 8
        input_spacing = height / (input_count + 1)
        input_nodes = []
        for i in range(input_count):
            node = Node(50, input_spacing * (i + 1), "input")
            input_nodes.append(node)
            self.nodes.append(node)
            
        # Hidden layer (64 nodes) - show subset
        hidden_count = 12
        hidden_spacing = height / (hidden_count + 1)
        hidden_nodes = []
        for i in range(hidden_count):
            node = Node(150, hidden_spacing * (i + 1), "hidden")
            hidden_nodes.append(node)
            self.nodes.append(node)
            
        # Output layer (2 nodes)
        output_nodes = []
        for i in range(2):
            node = Node(250, height / 3 * (i + 1), "output")
            output_nodes.append(node)
            self.nodes.append(node)
            
        # Create connections (subset for visualization)
        # Input to hidden
        for inp in input_nodes:
            # Connect to 3-4 random hidden nodes
            targets = random.sample(hidden_nodes, min(4, len(hidden_nodes)))
            for hid in targets:
                conn = Connection(inp, hid, random.random())
                self.connections.append(conn)
                inp.connections.append(conn)
                
        # Hidden to output
        for hid in hidden_nodes:
            # Connect to both outputs
            for out in output_nodes:
                conn = Connection(hid, out, random.random())
                self.connections.append(conn)
                hid.connections.append(conn)
                
    def add_node(self, packet_info):
        """Add packet data - simulates forward pass"""
        # Activate random input nodes
        input_nodes = [n for n in self.nodes if n.type == "input"]
        for node in random.sample(input_nodes, min(3, len(input_nodes))):
            node.value = random.random()
            
            # Propagate through connections
            for conn in node.connections:
                conn.active = True
                if conn.to_node.type == "hidden":
                    conn.to_node.value = node.value * conn.weight
                    
        # Activate outputs based on threat
        output_nodes = [n for n in self.nodes if n.type == "output"]
        threat_level = packet_info.get('threat_level', 'Safe')
        
        if threat_level == 'Safe':
            output_nodes[0].value = 0.9  # Normal
            output_nodes[1].value = 0.1  # Threat
        else:
            output_nodes[0].value = 0.2  # Normal
            output_nodes[1].value = 0.8  # Threat
            output_nodes[1].is_threat = True
            
    def mark_threat(self, threat_info):
        """Mark threat on network"""
        output_nodes = [n for n in self.nodes if n.type == "output"]
        if len(output_nodes) > 1:
            output_nodes[1].is_threat = True
            output_nodes[1].value = 1.0
            
    def animate(self):
        """Animate network"""
        self.pulse_phase = (self.pulse_phase + 0.1) % (2 * math.pi)
        
        # Decay active connections
        for conn in self.connections:
            if conn.active:
                conn.active = False
                
        # Decay node values
        for node in self.nodes:
            if node.value > 0:
                node.value *= 0.95
            if node.is_threat and node.value < 0.3:
                node.is_threat = False
                
        self.update()
        
    def paintEvent(self, event):
        """Paint GNN network"""
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        
        # Scale to widget size
        scale_x = self.width() / 300
        scale_y = self.height() / 300
        
        # Draw background grid
        painter.setPen(QPen(QColor(30, 30, 50), 1))
        for i in range(0, self.width(), 50):
            painter.drawLine(i, 0, i, self.height())
        for i in range(0, self.height(), 50):
            painter.drawLine(0, i, self.width(), i)
            
        # Draw connections
        for conn in self.connections:
            from_x = conn.from_node.x * scale_x
            from_y = conn.from_node.y * scale_y
            to_x = conn.to_node.x * scale_x
            to_y = conn.to_node.y * scale_y
            
            # Color based on activation
            if conn.active:
                color = QColor(0, 217, 255, 200)
                width = 2
            else:
                alpha = int(100 * conn.weight)
                color = QColor(100, 100, 150, alpha)
                width = 1
                
            painter.setPen(QPen(color, width))
            painter.drawLine(int(from_x), int(from_y), int(to_x), int(to_y))
            
        # Draw nodes
        for node in self.nodes:
            x = node.x * scale_x
            y = node.y * scale_y
            
            # Node size based on type
            if node.type == "input":
                radius = 6
                base_color = QColor(33, 150, 243)
            elif node.type == "hidden":
                radius = 5
                base_color = QColor(156, 39, 176)
            else:  # output
                radius = 8
                base_color = QColor(76, 175, 80) if not node.is_threat else QColor(244, 67, 54)
                
            # Activation intensity
            intensity = int(255 * node.value) if node.value > 0 else 50
            color = QColor(base_color.red(), base_color.green(), base_color.blue(), intensity)
            
            # Pulse effect
            if node.value > 0.5:
                pulse = math.sin(self.pulse_phase) * 3
                radius += pulse
                
            # Glow for high activation
            if node.value > 0.7:
                gradient = QRadialGradient(x, y, radius + 5)
                glow_color = QColor(color)
                glow_color.setAlpha(50)
                gradient.setColorAt(0, color)
                gradient.setColorAt(1, glow_color)
                painter.setBrush(QBrush(gradient))
            else:
                painter.setBrush(QBrush(color))
                
            painter.setPen(QPen(color.lighter(150), 1))
            painter.drawEllipse(QPointF(x, y), radius, radius)
            
        # Draw labels
        painter.setPen(QPen(QColor(200, 200, 200)))
        painter.setFont(QFont('Arial', 8))
        
        painter.drawText(10, 20, "Input Layer")
        painter.drawText(int(self.width() / 2) - 30, 20, "Hidden (GNN)")
        painter.drawText(self.width() - 80, 20, "Output")
        
        # Draw legend
        y_offset = self.height() - 60
        painter.setFont(QFont('Arial', 7))
        
        painter.setBrush(QBrush(QColor(76, 175, 80)))
        painter.drawEllipse(QPointF(20, y_offset), 4, 4)
        painter.drawText(30, y_offset + 4, "Normal")
        
        painter.setBrush(QBrush(QColor(244, 67, 54)))
        painter.drawEllipse(QPointF(20, y_offset + 20), 4, 4)
        painter.drawText(30, y_offset + 24, "Threat")
        
        painter.setBrush(QBrush(QColor(0, 217, 255)))
        painter.drawRect(100, y_offset - 2, 20, 2)
        painter.drawText(125, y_offset + 4, "Active")
        
    def resizeEvent(self, event):
        """Handle resize"""
        super().resizeEvent(event)
        # Reinitialize network with new dimensions
        # For simplicity, we keep the same logical positions and scale in paintEvent
