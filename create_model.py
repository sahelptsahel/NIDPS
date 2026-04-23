#!/usr/bin/env python3
"""
Generate initial pre-trained GNN model
This creates a baseline model that will be improved through training
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
import os

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

def create_initial_model():
    """Create and save initial model"""
    
    # Create model
    model = GNNDetector()
    
    # Initialize with reasonable weights
    for module in model.modules():
        if isinstance(module, nn.Linear):
            nn.init.xavier_uniform_(module.weight)
            if module.bias is not None:
                nn.init.zeros_(module.bias)
    
    # Create models directory
    models_dir = os.path.join(os.path.dirname(__file__), 'models')
    os.makedirs(models_dir, exist_ok=True)
    
    # Save model
    model_path = os.path.join(models_dir, 'gnn_model.pth')
    torch.save(model.state_dict(), model_path)
    
    print(f"✅ Initial GNN model created and saved to: {model_path}")
    print(f"📊 Model parameters: {sum(p.numel() for p in model.parameters())} total parameters")
    
    return model_path

if __name__ == '__main__':
    create_initial_model()
