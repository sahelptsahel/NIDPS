"""
Model Training Dialog - Fully Working ML Training Interface
Supports: CSV datasets, PCAP files, Live captured data, Synthetic data
Compatible datasets: CICIDS2017, NSL-KDD, UNSW-NB15, custom CSV
"""

import os
import sys
import json
import traceback
import numpy as np
from datetime import datetime
from collections import Counter

import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import Dataset, DataLoader
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.utils.class_weight import compute_class_weight

from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QGroupBox, QLabel, QPushButton,
    QProgressBar, QTextEdit, QFileDialog, QComboBox, QSpinBox, QFormLayout,
    QMessageBox, QTabWidget, QWidget, QTableWidget, QTableWidgetItem,
    QHeaderView, QSplitter, QLineEdit
)
from PyQt5.QtCore import QThread, pyqtSignal, Qt
from PyQt5.QtGui import QFont, QColor, QPainter, QPen

# Qt Charts for live training curves
try:
    from PyQt5.QtChart import QChart, QChartView, QLineSeries, QValueAxis
    HAS_CHARTS = True
except ImportError:
    HAS_CHARTS = False


# ─────────────────────────────────────────────────────────────────────────────
# GNN Model  (must match core/intrusion_detector.py)
# ─────────────────────────────────────────────────────────────────────────────

class GNNDetector(nn.Module):
    def __init__(self, input_dim=20, hidden_dim=64, output_dim=2):
        super().__init__()
        self.fc1 = nn.Linear(input_dim, hidden_dim)
        self.bn1 = nn.BatchNorm1d(hidden_dim)
        self.fc2 = nn.Linear(hidden_dim, hidden_dim)
        self.bn2 = nn.BatchNorm1d(hidden_dim)
        self.fc3 = nn.Linear(hidden_dim, hidden_dim // 2)
        self.fc4 = nn.Linear(hidden_dim // 2, output_dim)
        self.dropout = nn.Dropout(0.3)

    def forward(self, x):
        x = torch.relu(self.bn1(self.fc1(x)))
        x = self.dropout(x)
        x = torch.relu(self.bn2(self.fc2(x)))
        x = self.dropout(x)
        x = torch.relu(self.fc3(x))
        return torch.softmax(self.fc4(x), dim=1)


# ─────────────────────────────────────────────────────────────────────────────
# Dataset wrapper
# ─────────────────────────────────────────────────────────────────────────────

class NetworkDataset(Dataset):
    def __init__(self, X, y):
        self.X = torch.FloatTensor(X)
        self.y = torch.LongTensor(y)

    def __len__(self):
        return len(self.X)

    def __getitem__(self, idx):
        return self.X[idx], self.y[idx]


# ─────────────────────────────────────────────────────────────────────────────
# Data processing utilities
# ─────────────────────────────────────────────────────────────────────────────

class DataProcessor:
    LABEL_COLUMNS = [
        ' Label', 'Label', 'label', 'class', 'Class', 'attack',
        'category', 'Category', 'attack_cat', 'type', 'Type',
        'target', 'Target', 'y', 'outcome', 'Outcome', 'Result'
    ]
    NORMAL_LABELS = [
        'BENIGN', 'Normal', 'normal', 'benign', 'Benign',
        '0', 'NORMAL', 'legitimate', 'Legitimate', 'safe', 'Safe'
    ]

    @staticmethod
    def detect_label_column(df):
        for col in DataProcessor.LABEL_COLUMNS:
            if col in df.columns:
                return col
        for col in reversed(df.columns.tolist()):
            if df[col].nunique() <= 20:
                return col
        return None

    @staticmethod
    def load_csv(filepath, label_col=None, max_rows=200000):
        try:
            import pandas as pd
            df = pd.read_csv(filepath, nrows=max_rows, low_memory=False)
            df.columns = df.columns.str.strip()

            if label_col is None:
                label_col = DataProcessor.detect_label_column(df)
            if label_col is None:
                cols_preview = list(df.columns[:15])
                raise ValueError(
                    f"Could not auto-detect label column.\n"
                    f"Available columns (first 15): {cols_preview}\n"
                    f"Please type the label column name in the field above."
                )

            raw_labels = df[label_col].astype(str).str.strip()
            y = (~raw_labels.isin(DataProcessor.NORMAL_LABELS)).astype(int).values

            X_df = df.drop(columns=[label_col]).select_dtypes(include=[float, int])
            if X_df.shape[1] == 0:
                raise ValueError("No numeric feature columns found.")

            import numpy as np
            X_df = X_df.replace([float('inf'), float('-inf')], float('nan')).fillna(0)
            X = X_df.values.astype(np.float32)

            attack_counts = dict(Counter(raw_labels[y == 1]).most_common(10))
            stats = {
                'total_samples': len(X),
                'total_features': X.shape[1],
                'normal_count': int((y == 0).sum()),
                'attack_count': int((y == 1).sum()),
                'label_col': label_col,
                'feature_names': list(X_df.columns),
                'attack_types': attack_counts,
            }
            return X, y, stats
        except Exception as e:
            raise RuntimeError(str(e))

    @staticmethod
    def load_pcap(filepath):
        try:
            from scapy.all import rdpcap, IP, TCP, UDP, ICMP
        except ImportError:
            raise RuntimeError("Scapy not installed. Run: pip install scapy")

        packets = rdpcap(filepath)
        feats, labels = [], []
        for pkt in packets:
            f = DataProcessor._pkt_features(pkt)
            if f:
                feats.append(f)
                labels.append(0)

        if not feats:
            raise ValueError("No valid IP packets found in PCAP.")

        import numpy as np
        X = np.array(feats, dtype=np.float32)
        y = np.array(labels, dtype=np.int64)
        stats = {
            'total_samples': len(X), 'total_features': 20,
            'normal_count': len(X), 'attack_count': 0,
            'label_col': 'N/A (PCAP has no labels)',
            'feature_names': [f'pkt_f{i}' for i in range(20)],
        }
        return X, y, stats

    @staticmethod
    def _pkt_features(pkt):
        try:
            from scapy.all import IP, TCP, UDP, ICMP
            import numpy as np
            if IP not in pkt:
                return None
            f = []
            if TCP in pkt:
                f.extend([1, 0, 0])
                f.append(pkt[TCP].dport / 65535.0)
                f.append(pkt[TCP].sport / 65535.0)
                flags = int(pkt[TCP].flags)
                f += [(flags >> i) & 1 for i in range(5)]
            elif UDP in pkt:
                f.extend([0, 1, 0, pkt[UDP].dport / 65535.0,
                           pkt[UDP].sport / 65535.0, 0, 0, 0, 0, 0])
            elif ICMP in pkt:
                f.extend([0, 0, 1] + [0] * 7)
            else:
                f.extend([0] * 10)
            f.append(len(pkt) / 65535.0)
            parts = pkt[IP].src.split('.')
            f += [int(p) / 255.0 for p in parts]
            f.append(pkt[IP].ttl / 255.0)
            while len(f) < 20:
                f.append(0.0)
            return f[:20]
        except:
            return None

    @staticmethod
    def generate_synthetic(n_samples=5000, input_dim=20):
        import numpy as np
        np.random.seed(42)
        half = n_samples // 2
        X_n = np.clip(np.random.randn(half, input_dim) * 0.3 + 0.4, 0, 1)
        X_a = np.clip(np.random.randn(half, input_dim) * 0.5 + 0.7, 0, 1)
        cols = np.random.choice(input_dim, min(5, input_dim), replace=False)
        X_a[:, cols] = np.clip(np.random.randn(half, len(cols)) * 0.2 + 0.9, 0.6, 1.0)
        X = np.vstack([X_n, X_a]).astype(np.float32)
        y = np.array([0] * half + [1] * half, dtype=np.int64)
        idx = np.random.permutation(n_samples)
        X, y = X[idx], y[idx]
        stats = {
            'total_samples': n_samples, 'total_features': input_dim,
            'normal_count': half, 'attack_count': half,
            'label_col': 'synthetic',
            'feature_names': [f'feature_{i}' for i in range(input_dim)],
        }
        return X, y, stats

    @staticmethod
    def preprocess(X, y, target_dim=20):
        import numpy as np
        scaler = StandardScaler()
        X_s = scaler.fit_transform(X)
        if X_s.shape[1] > target_dim:
            variances = np.var(X_s, axis=0)
            top_idx = np.argsort(variances)[::-1][:target_dim]
            X_s = X_s[:, top_idx]
        elif X_s.shape[1] < target_dim:
            pad = np.zeros((X_s.shape[0], target_dim - X_s.shape[1]))
            X_s = np.hstack([X_s, pad])
        return X_s.astype(np.float32), scaler


# ─────────────────────────────────────────────────────────────────────────────
# Training Thread
# ─────────────────────────────────────────────────────────────────────────────

class TrainingThread(QThread):
    progress_signal = pyqtSignal(int, str)
    epoch_signal    = pyqtSignal(dict)
    finished_signal = pyqtSignal(dict)
    log_signal      = pyqtSignal(str)

    def __init__(self, X, y, config):
        super().__init__()
        self.X = X
        self.y = y
        self.config = config
        self._stop = False

    def stop(self):
        self._stop = True

    def run(self):
        try:
            import numpy as np
            cfg = self.config
            self.emit_log("🔧 Preprocessing data...")
            self.progress_signal.emit(3, "Preprocessing...")

            X_proc, scaler = DataProcessor.preprocess(
                self.X, self.y, target_dim=cfg['input_dim']
            )

            X_tr, X_val, y_tr, y_val = train_test_split(
                X_proc, self.y, test_size=0.2, random_state=42,
                stratify=self.y if len(np.unique(self.y)) > 1 else None
            )
            self.emit_log(
                f"Train: {len(X_tr):,}  |  Val: {len(X_val):,}  |  "
                f"Features: {X_proc.shape[1]}"
            )
            self.progress_signal.emit(8, "Data ready")

            device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
            self.emit_log(f"💻 Device: {device}")

            train_dl = DataLoader(
                NetworkDataset(X_tr, y_tr),
                batch_size=cfg['batch_size'], shuffle=True, num_workers=0
            )
            val_dl = DataLoader(
                NetworkDataset(X_val, y_val),
                batch_size=cfg['batch_size'], shuffle=False, num_workers=0
            )

            model = GNNDetector(
                input_dim=cfg['input_dim'],
                hidden_dim=cfg['hidden_dim']
            ).to(device)
            self.emit_log(
                f"🧠 Parameters: {sum(p.numel() for p in model.parameters()):,}"
            )

            # Weighted loss to handle class imbalance
            weights = compute_class_weight(
                'balanced', classes=np.unique(y_tr), y=y_tr
            )
            criterion = nn.CrossEntropyLoss(
                weight=torch.FloatTensor(weights).to(device)
            )
            optimizer = optim.Adam(
                model.parameters(), lr=cfg['lr'], weight_decay=1e-4
            )
            scheduler = optim.lr_scheduler.ReduceLROnPlateau(
                optimizer, patience=3, factor=0.5
            )

            self.progress_signal.emit(10, "Training started")
            self.emit_log(f"\n{'─'*55}")
            self.emit_log(
                f"  {'Epoch':>5}  {'TrLoss':>7}  {'TrAcc':>6}  "
                f"{'VLoss':>7}  {'VAcc':>6}  {'F1':>6}"
            )
            self.emit_log(f"{'─'*55}")

            best_acc   = 0.0
            best_state = None
            history    = []
            epochs     = cfg['epochs']

            for ep in range(epochs):
                if self._stop:
                    self.emit_log("⛔ Stopped by user.")
                    break

                # ── Train ────────────────────────────────────────────────────
                model.train()
                tl = tc = tt = 0
                for xb, yb in train_dl:
                    xb, yb = xb.to(device), yb.to(device)
                    optimizer.zero_grad()
                    out  = model(xb)
                    loss = criterion(out, yb)
                    loss.backward()
                    nn.utils.clip_grad_norm_(model.parameters(), 1.0)
                    optimizer.step()
                    tl += loss.item() * len(yb)
                    tc += (out.argmax(1) == yb).sum().item()
                    tt += len(yb)

                tr_loss = tl / tt
                tr_acc  = 100.0 * tc / tt

                # ── Validate ─────────────────────────────────────────────────
                model.eval()
                vl = vc = vt = tp = fp = fn = 0
                with torch.no_grad():
                    for xb, yb in val_dl:
                        xb, yb = xb.to(device), yb.to(device)
                        out   = model(xb)
                        preds = out.argmax(1)
                        vl += criterion(out, yb).item() * len(yb)
                        vc += (preds == yb).sum().item()
                        vt += len(yb)
                        tp += ((preds == 1) & (yb == 1)).sum().item()
                        fp += ((preds == 1) & (yb == 0)).sum().item()
                        fn += ((preds == 0) & (yb == 1)).sum().item()

                v_loss = vl / vt
                v_acc  = 100.0 * vc / vt
                prec   = tp / (tp + fp + 1e-8) * 100
                rec    = tp / (tp + fn + 1e-8) * 100
                f1     = 2 * prec * rec / (prec + rec + 1e-8)
                lr_now = optimizer.param_groups[0]['lr']

                scheduler.step(v_loss)

                if v_acc > best_acc:
                    best_acc  = v_acc
                    best_state = {k: v.cpu().clone()
                                  for k, v in model.state_dict().items()}

                m = {
                    'epoch': ep + 1, 'epochs': epochs,
                    'train_loss': round(tr_loss, 4),
                    'train_acc':  round(tr_acc,  2),
                    'val_loss':   round(v_loss,  4),
                    'val_acc':    round(v_acc,   2),
                    'precision':  round(prec,    2),
                    'recall':     round(rec,     2),
                    'f1':         round(f1,      2),
                    'lr':         round(lr_now,  6),
                }
                history.append(m)
                self.epoch_signal.emit(m)

                pct = 10 + int((ep + 1) / epochs * 82)
                self.progress_signal.emit(
                    pct, f"Ep {ep+1}/{epochs} — Val {v_acc:.1f}% F1 {f1:.1f}%"
                )
                self.emit_log(
                    f"  {ep+1:5d}  {tr_loss:7.4f}  {tr_acc:5.1f}%  "
                    f"{v_loss:7.4f}  {v_acc:5.1f}%  {f1:5.1f}%"
                )

            # ── Save ─────────────────────────────────────────────────────────
            self.progress_signal.emit(94, "Saving model...")
            self.emit_log(f"{'─'*55}")
            self.emit_log(f"  Best Val Accuracy: {best_acc:.2f}%")

            models_dir = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                'models'
            )
            os.makedirs(models_dir, exist_ok=True)
            model_path = os.path.join(models_dir, 'gnn_model.pth')

            if best_state is None:
                best_state = {k: v.cpu() for k, v in model.state_dict().items()}

            torch.save({
                'state_dict': best_state,
                'input_dim':  cfg['input_dim'],
                'hidden_dim': cfg['hidden_dim'],
                'best_val_acc': best_acc,
                'trained_at': datetime.now().isoformat(),
            }, model_path)

            import pickle
            scaler_path = os.path.join(models_dir, 'scaler.pkl')
            with open(scaler_path, 'wb') as f:
                pickle.dump(scaler, f)

            hist_path = os.path.join(models_dir, 'training_history.json')
            with open(hist_path, 'w') as f:
                json.dump(history, f, indent=2)

            self.emit_log(f"  Saved → {model_path}")
            self.progress_signal.emit(100, "Done!")

            self.finished_signal.emit({
                'success':      True,
                'best_val_acc': best_acc,
                'model_path':   model_path,
                'epochs_done':  len(history),
                'history':      history,
            })

        except Exception as e:
            tb = traceback.format_exc()
            self.emit_log(f"❌ {e}\n{tb}")
            self.finished_signal.emit({'success': False, 'error': str(e)})

    def emit_log(self, msg):
        self.log_signal.emit(msg)


# ─────────────────────────────────────────────────────────────────────────────
# Simple canvas-based chart (no PyQt5.QtChart dependency needed)
# ─────────────────────────────────────────────────────────────────────────────

class SimpleChart(QWidget):
    """Lightweight line chart drawn with QPainter — no QtChart needed."""

    def __init__(self, title, y_label="", parent=None):
        super().__init__(parent)
        self.title   = title
        self.y_label = y_label
        self.series  = {}   # name -> list of (x,y)
        self.colors  = {'train': QColor('#00d9ff'), 'val': QColor('#ff6b6b'),
                        'f1': QColor('#7bff6b')}
        self.setMinimumHeight(140)
        self.setStyleSheet("background:#161616; border-radius:4px;")

    def add_point(self, name, x, y):
        if name not in self.series:
            self.series[name] = []
        self.series[name].append((x, y))
        self.update()

    def clear(self):
        self.series.clear()
        self.update()

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        W, H = self.width(), self.height()
        M = 36

        p.fillRect(0, 0, W, H, QColor('#161616'))

        # Title
        p.setPen(QColor('#888'))
        p.setFont(QFont('Segoe UI', 8))
        p.drawText(M, 14, W - M - 4, 16, Qt.AlignLeft, self.title)

        # Axes
        p.setPen(QPen(QColor('#333'), 1))
        p.drawLine(M, H - M, W - 8, H - M)
        p.drawLine(M, 20,    M,     H - M)

        # Grid
        p.setPen(QPen(QColor('#222'), 1, Qt.DashLine))
        for i in range(1, 5):
            gy = int(20 + (H - M - 20) * i / 4)
            p.drawLine(M + 1, gy, W - 8, gy)

        if not self.series:
            p.setPen(QColor('#444'))
            p.drawText(M, 20, W - M - 4, H - M - 20, Qt.AlignCenter, "No data yet")
            return

        # Find ranges
        all_x = [x for pts in self.series.values() for x, _ in pts]
        all_y = [y for pts in self.series.values() for _, y in pts]
        if not all_x:
            return
        min_x, max_x = min(all_x), max(all_x)
        min_y, max_y = min(all_y), max(all_y)
        if max_x == min_x:
            max_x = min_x + 1
        if max_y == min_y:
            max_y = min_y + 1

        def tx(x):
            return int(M + (x - min_x) / (max_x - min_x) * (W - M - 12))

        def ty(y):
            return int(H - M - (y - min_y) / (max_y - min_y) * (H - M - 24))

        # Y-axis labels
        p.setFont(QFont('Segoe UI', 7))
        p.setPen(QColor('#555'))
        for i in range(5):
            yv = min_y + (max_y - min_y) * i / 4
            gy = ty(yv)
            p.drawText(0, gy - 6, M - 3, 14, Qt.AlignRight, f"{yv:.1f}")

        # X-axis labels
        for i in range(min(5, len(all_x))):
            xv = min_x + (max_x - min_x) * i / 4
            gx = tx(xv)
            p.drawText(gx - 12, H - M + 3, 24, 12, Qt.AlignCenter, f"{int(xv)}")

        # Lines
        order = ['train', 'val', 'f1']
        for name in order:
            if name not in self.series:
                continue
            pts = self.series[name]
            if len(pts) < 1:
                continue
            col = self.colors.get(name, QColor('#ffffff'))
            pen = QPen(col, 2)
            p.setPen(pen)
            for i in range(1, len(pts)):
                x1, y1 = pts[i - 1]
                x2, y2 = pts[i]
                p.drawLine(tx(x1), ty(y1), tx(x2), ty(y2))
            # Last point dot
            lx, ly = pts[-1]
            p.setBrush(col)
            p.setPen(QPen(col, 1))
            p.drawEllipse(tx(lx) - 3, ty(ly) - 3, 6, 6)

        # Legend
        lx = W - 90
        for i, (name, col) in enumerate(self.colors.items()):
            if name in self.series:
                p.setPen(QPen(col, 2))
                p.drawLine(lx, 14 + i * 14, lx + 16, 14 + i * 14)
                p.setPen(QColor('#aaa'))
                p.setFont(QFont('Segoe UI', 7))
                p.drawText(lx + 20, 8 + i * 14, 60, 14, Qt.AlignLeft, name)


# ─────────────────────────────────────────────────────────────────────────────
# Dialog stylesheet
# ─────────────────────────────────────────────────────────────────────────────

STYLE = """
QDialog, QWidget {
    background-color: #1e1e1e;
    color: #e0e0e0;
    font-family: 'Segoe UI', Arial, sans-serif;
    font-size: 10pt;
}
QGroupBox {
    border: 1px solid #3a3a3a;
    border-radius: 6px;
    margin-top: 14px;
    padding-top: 10px;
    font-weight: bold;
    color: #00d9ff;
}
QGroupBox::title {
    subcontrol-origin: margin;
    left: 10px;
    padding: 0 5px;
}
QLabel { color: #e0e0e0; }
QLineEdit, QSpinBox, QDoubleSpinBox, QComboBox {
    background-color: #2b2b2b;
    border: 1px solid #3d3d3d;
    border-radius: 4px;
    color: #e0e0e0;
    padding: 4px 8px;
    min-height: 22px;
}
QComboBox::drop-down { border: none; width: 20px; }
QComboBox QAbstractItemView {
    background: #2b2b2b; color: #e0e0e0;
    selection-background-color: #00d9ff;
    selection-color: #000;
}
QPushButton {
    background-color: #2b2b2b;
    border: 1px solid #3d3d3d;
    border-radius: 4px;
    color: #e0e0e0;
    padding: 6px 16px;
    min-height: 28px;
}
QPushButton:hover { background-color: #383838; border-color: #00d9ff; }
QPushButton:disabled { color: #555; border-color: #252525; }
QPushButton#btn_start {
    background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
        stop:0 #006633, stop:1 #009944);
    border-color: #00cc55;
    color: white; font-weight: bold; font-size: 11pt;
}
QPushButton#btn_start:hover {
    background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
        stop:0 #007a3d, stop:1 #00bb55);
}
QPushButton#btn_stop {
    background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
        stop:0 #660000, stop:1 #990000);
    border-color: #cc0000; color: white; font-weight: bold;
}
QPushButton#btn_load {
    background: #1a3a5c; border-color: #00d9ff;
    color: #00d9ff; font-weight: bold;
}
QPushButton#btn_load:hover { background: #224466; }
QProgressBar {
    border: 1px solid #3d3d3d; border-radius: 4px;
    background: #2b2b2b; text-align: center;
    color: white; height: 22px;
}
QProgressBar::chunk {
    background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
        stop:0 #00d9ff, stop:1 #7b2fff);
    border-radius: 3px;
}
QTextEdit {
    background: #0d1117; color: #39d353;
    font-family: 'Courier New', monospace; font-size: 9pt;
    border: 1px solid #2a2a2a; border-radius: 4px;
}
QTabWidget::pane {
    border: 1px solid #3d3d3d; border-radius: 4px; background: #1e1e1e;
}
QTabBar::tab {
    background: #2b2b2b; color: #888;
    padding: 6px 16px; border: 1px solid #3d3d3d;
    border-bottom: none; border-radius: 4px 4px 0 0; margin-right: 2px;
}
QTabBar::tab:selected { background: #1e1e1e; color: #00d9ff; border-color: #00d9ff; }
QTableWidget {
    background: #161616; color: #e0e0e0;
    gridline-color: #2a2a2a; border: none;
}
QTableWidget::item:alternate { background: #1a1a1a; }
QHeaderView::section {
    background: #2b2b2b; color: #00d9ff;
    padding: 4px; border: 1px solid #3d3d3d; font-weight: bold;
}
QScrollBar:vertical { background: #1a1a1a; width: 8px; }
QScrollBar::handle:vertical { background: #3d3d3d; border-radius: 4px; }
"""


# ─────────────────────────────────────────────────────────────────────────────
# Main Dialog
# ─────────────────────────────────────────────────────────────────────────────

class ModelTrainingDialog(QDialog):

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("🧠  Train GNN Model — NIDPS ULTIMATE")
        self.setMinimumSize(960, 680)
        self.resize(1080, 740)
        self.setStyleSheet(STYLE)

        self._thread    = None
        self._X         = None
        self._y         = None
        self._stats     = None

        self._build_ui()

    # ──────────────────────────────────────────────────────────────────────────

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setSpacing(8)
        root.setContentsMargins(12, 12, 12, 12)

        # Header
        hdr = QLabel("🧠  Neural Network Training Studio")
        hdr.setStyleSheet(
            "font-size:14pt; font-weight:bold; color:#00d9ff; padding:4px 0;"
        )
        root.addWidget(hdr)

        splitter = QSplitter(Qt.Horizontal)
        splitter.setHandleWidth(5)
        root.addWidget(splitter, 1)

        # ── LEFT ──────────────────────────────────────────────────────────────
        left = QWidget()
        left.setMaximumWidth(340)
        left.setMinimumWidth(280)
        ll = QVBoxLayout(left)
        ll.setSpacing(8)
        ll.setContentsMargins(0, 0, 6, 0)

        # Data source
        dg = QGroupBox("📂  Data Source")
        df = QVBoxLayout(dg)
        df.setSpacing(6)

        self.cmb_source = QComboBox()
        self.cmb_source.addItems([
            "🧪  Synthetic Data (Quick Demo)",
            "📄  CSV File  (CICIDS2017 / NSL-KDD / Custom)",
            "📦  PCAP File",
            "💾  Use Live Captured Packets",
        ])
        self.cmb_source.currentIndexChanged.connect(self._on_source_change)
        df.addWidget(self.cmb_source)

        file_row = QHBoxLayout()
        self.txt_file = QLineEdit()
        self.txt_file.setPlaceholderText("No file selected")
        self.txt_file.setReadOnly(True)
        self.txt_file.setEnabled(False)
        file_row.addWidget(self.txt_file, 1)
        self.btn_browse = QPushButton("Browse")
        self.btn_browse.setEnabled(False)
        self.btn_browse.setMaximumWidth(65)
        self.btn_browse.clicked.connect(self._browse)
        file_row.addWidget(self.btn_browse)
        df.addLayout(file_row)

        lbl_row = QHBoxLayout()
        lbl_row.addWidget(QLabel("Label Col:"))
        self.txt_lbl = QLineEdit()
        self.txt_lbl.setPlaceholderText("Auto-detect")
        self.txt_lbl.setToolTip(
            "Leave blank to auto-detect.\n"
            "Common: ' Label', 'class', 'label', 'attack_cat'"
        )
        lbl_row.addWidget(self.txt_lbl, 1)
        df.addLayout(lbl_row)

        rows_row = QHBoxLayout()
        rows_row.addWidget(QLabel("Max Rows:"))
        self.spn_rows = QSpinBox()
        self.spn_rows.setRange(500, 2000000)
        self.spn_rows.setValue(100000)
        self.spn_rows.setSingleStep(10000)
        self.spn_rows.setSuffix(" rows")
        rows_row.addWidget(self.spn_rows, 1)
        df.addLayout(rows_row)

        self.btn_load = QPushButton("⬇  Load & Preview Dataset")
        self.btn_load.setObjectName("btn_load")
        self.btn_load.clicked.connect(self._load_data)
        df.addWidget(self.btn_load)

        self.lbl_stats = QLabel("No dataset loaded.")
        self.lbl_stats.setWordWrap(True)
        self.lbl_stats.setStyleSheet(
            "color:#aaa; font-size:9pt; padding:5px;"
            "background:#161616; border-radius:4px;"
        )
        df.addWidget(self.lbl_stats)
        ll.addWidget(dg)

        # Model config
        mg = QGroupBox("⚙️  Model Configuration")
        mf = QFormLayout(mg)
        mf.setSpacing(6)

        self.spn_in = QSpinBox()
        self.spn_in.setRange(5, 200)
        self.spn_in.setValue(20)
        self.spn_in.setToolTip(
            "Input features fed into the GNN.\n"
            "Must match input_dim in core/intrusion_detector.py (default 20).\n"
            "For CSV datasets with 78+ columns, top features are auto-selected."
        )
        mf.addRow("Input Features:", self.spn_in)

        self.spn_hid = QSpinBox()
        self.spn_hid.setRange(16, 512)
        self.spn_hid.setValue(64)
        mf.addRow("Hidden Units:", self.spn_hid)

        self.spn_ep = QSpinBox()
        self.spn_ep.setRange(1, 300)
        self.spn_ep.setValue(25)
        mf.addRow("Epochs:", self.spn_ep)

        self.spn_bs = QSpinBox()
        self.spn_bs.setRange(16, 4096)
        self.spn_bs.setValue(256)
        self.spn_bs.setSingleStep(64)
        mf.addRow("Batch Size:", self.spn_bs)

        self.cmb_lr = QComboBox()
        self.cmb_lr.addItems(["0.001", "0.0005", "0.0001", "0.00005"])
        mf.addRow("Learning Rate:", self.cmb_lr)

        ll.addWidget(mg)
        ll.addStretch()

        self.btn_start = QPushButton("▶   Start Training")
        self.btn_start.setObjectName("btn_start")
        self.btn_start.setEnabled(False)
        self.btn_start.clicked.connect(self._start)
        ll.addWidget(self.btn_start)

        self.btn_stop = QPushButton("⏹   Stop Training")
        self.btn_stop.setObjectName("btn_stop")
        self.btn_stop.setEnabled(False)
        self.btn_stop.clicked.connect(self._stop)
        ll.addWidget(self.btn_stop)

        btn_close = QPushButton("Close")
        btn_close.clicked.connect(self.close)
        ll.addWidget(btn_close)

        splitter.addWidget(left)

        # ── RIGHT ─────────────────────────────────────────────────────────────
        right = QWidget()
        rl = QVBoxLayout(right)
        rl.setSpacing(6)
        rl.setContentsMargins(6, 0, 0, 0)

        self.progress = QProgressBar()
        self.progress.setValue(0)
        rl.addWidget(self.progress)

        self.lbl_status = QLabel("Idle — load a dataset to begin.")
        self.lbl_status.setStyleSheet("color:#888; font-size:9pt;")
        rl.addWidget(self.lbl_status)

        self.tabs = QTabWidget()

        # Tab 1: Charts
        cw = QWidget()
        cl = QVBoxLayout(cw)
        self.chart_acc  = SimpleChart("Accuracy (%)",  "Accuracy")
        self.chart_loss = SimpleChart("Loss",           "Loss")
        cl.addWidget(self.chart_acc,  1)
        cl.addWidget(self.chart_loss, 1)
        self.tabs.addTab(cw, "📈  Live Charts")

        # Tab 2: Metrics table
        mw = QWidget()
        mlayout = QVBoxLayout(mw)
        self.tbl = QTableWidget()
        self.tbl.setColumnCount(9)
        self.tbl.setHorizontalHeaderLabels([
            "Epoch", "Train Loss", "Train Acc%",
            "Val Loss", "Val Acc%",
            "Precision%", "Recall%", "F1%", "LR"
        ])
        self.tbl.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.tbl.setAlternatingRowColors(True)
        self.tbl.setEditTriggers(QTableWidget.NoEditTriggers)
        mlayout.addWidget(self.tbl)
        self.tabs.addTab(mw, "📊  Epoch Metrics")

        # Tab 3: Log
        lw = QWidget()
        llayout = QVBoxLayout(lw)
        self.log = QTextEdit()
        self.log.setReadOnly(True)
        llayout.addWidget(self.log)
        log_btns = QHBoxLayout()
        b_clear = QPushButton("Clear")
        b_clear.clicked.connect(self.log.clear)
        b_export = QPushButton("Export Log")
        b_export.clicked.connect(self._export_log)
        log_btns.addWidget(b_clear)
        log_btns.addWidget(b_export)
        log_btns.addStretch()
        llayout.addLayout(log_btns)
        self.tabs.addTab(lw, "📋  Training Log")

        # Tab 4: Results
        rw = QWidget()
        rlayout = QVBoxLayout(rw)
        self.lbl_result = QLabel("Training results will appear here.")
        self.lbl_result.setWordWrap(True)
        self.lbl_result.setAlignment(Qt.AlignTop | Qt.AlignLeft)
        self.lbl_result.setStyleSheet(
            "font-size:11pt; color:#e0e0e0; padding:16px;"
            "background:#161616; border-radius:6px;"
        )
        rlayout.addWidget(self.lbl_result)
        self.tabs.addTab(rw, "🏆  Results")

        rl.addWidget(self.tabs, 1)
        splitter.addWidget(right)
        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)

    # ──────────────────────────────────────────────────────────────────────────
    # Slots
    # ──────────────────────────────────────────────────────────────────────────

    def _on_source_change(self, idx):
        needs_file = idx in (1, 2)
        self.btn_browse.setEnabled(needs_file)
        self.txt_file.setEnabled(needs_file)
        self.txt_lbl.setEnabled(idx == 1)
        if not needs_file:
            self.txt_file.setText("")

    def _browse(self):
        idx = self.cmb_source.currentIndex()
        if idx == 1:
            path, _ = QFileDialog.getOpenFileName(
                self, "Select CSV Dataset", "",
                "CSV Files (*.csv *.tsv);;All Files (*)"
            )
        else:
            path, _ = QFileDialog.getOpenFileName(
                self, "Select PCAP File", "",
                "PCAP Files (*.pcap *.pcapng);;All Files (*)"
            )
        if path:
            self.txt_file.setText(path)

    def _load_data(self):
        self._X = self._y = self._stats = None
        self.btn_start.setEnabled(False)
        self.lbl_stats.setText("⏳ Loading...")

        idx      = self.cmb_source.currentIndex()
        lbl_col  = self.txt_lbl.text().strip() or None
        max_rows = self.spn_rows.value()

        try:
            if idx == 0:
                self._X, self._y, self._stats = DataProcessor.generate_synthetic(
                    n_samples=5000, input_dim=self.spn_in.value()
                )
            elif idx == 1:
                path = self.txt_file.text().strip()
                if not path or not os.path.exists(path):
                    raise FileNotFoundError("Please select a valid CSV file.")
                self._X, self._y, self._stats = DataProcessor.load_csv(
                    path, label_col=lbl_col, max_rows=max_rows
                )
                self.spn_in.setValue(min(self._X.shape[1], 78))
            elif idx == 2:
                path = self.txt_file.text().strip()
                if not path or not os.path.exists(path):
                    raise FileNotFoundError("Please select a valid PCAP file.")
                self._X, self._y, self._stats = DataProcessor.load_pcap(path)
                self.spn_in.setValue(20)
            elif idx == 3:
                self._X, self._y, self._stats = self._load_live()

            s = self._stats
            html = (
                f"<b style='color:#00ff88'>✅ {s['total_samples']:,} samples loaded</b><br>"
                f"<span style='color:#aaa'>Features: {s['total_features']} &nbsp;|&nbsp; "
                f"Label col: <i>{s.get('label_col','?')}</i></span><br>"
                f"🟢 Normal: <b>{s.get('normal_count',0):,}</b> &nbsp; "
                f"🔴 Attack: <b>{s.get('attack_count',0):,}</b>"
            )
            if s.get('attack_types'):
                top = list(s['attack_types'].items())[:3]
                html += "<br><span style='color:#888;font-size:8pt;'>Top attacks: " + \
                        ", ".join(f"{k}({v})" for k, v in top) + "</span>"

            self.lbl_stats.setText(html)
            self.lbl_stats.setTextFormat(Qt.RichText)
            self.btn_start.setEnabled(True)
            self._log(f"✅ Dataset loaded: {s['total_samples']:,} samples, "
                      f"{s['total_features']} features")
            self.tabs.setCurrentIndex(2)

        except Exception as e:
            self.lbl_stats.setText(f"<span style='color:#ff6b6b'>❌ {e}</span>")
            self.lbl_stats.setTextFormat(Qt.RichText)
            QMessageBox.critical(self, "Load Error", str(e))

    def _load_live(self):
        parent = self.parent()
        if parent and hasattr(parent, 'intrusion_detector'):
            det = parent.intrusion_detector
            if not det.connection_tracker:
                raise ValueError(
                    "No live packets captured yet.\n"
                    "Start monitoring first to capture network traffic."
                )
        self._log("⚠️  Live capture mode: using synthetic fallback "
                  "(full live integration requires monitoring to be running).")
        return DataProcessor.generate_synthetic(n_samples=3000)

    def _start(self):
        if self._X is None:
            QMessageBox.warning(self, "No Data", "Please load a dataset first.")
            return

        self.chart_acc.clear()
        self.chart_loss.clear()
        self.tbl.setRowCount(0)
        self.log.clear()
        self.progress.setValue(0)
        self.lbl_result.setText("Training in progress...")

        cfg = {
            'input_dim': self.spn_in.value(),
            'hidden_dim': self.spn_hid.value(),
            'epochs':    self.spn_ep.value(),
            'batch_size': self.spn_bs.value(),
            'lr':        float(self.cmb_lr.currentText()),
        }

        self._log("=" * 58)
        self._log(f"  NIDPS Training — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        self._log(f"  {cfg}")
        self._log(f"  Samples: {len(self._X):,}  Features: {self._X.shape[1]}")
        self._log("=" * 58)
        self._log("")

        self._thread = TrainingThread(self._X, self._y, cfg)
        self._thread.progress_signal.connect(self._on_progress)
        self._thread.epoch_signal.connect(self._on_epoch)
        self._thread.log_signal.connect(self._log)
        self._thread.finished_signal.connect(self._on_done)
        self._thread.start()

        self.btn_start.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.tabs.setCurrentIndex(0)

    def _stop(self):
        if self._thread and self._thread.isRunning():
            self._thread.stop()
            self._thread.wait(4000)
        self.btn_start.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.lbl_status.setText("Stopped.")

    def _on_progress(self, pct, msg):
        self.progress.setValue(pct)
        color = "#00ff88" if pct == 100 else "#00d9ff"
        self.lbl_status.setText(msg)
        self.lbl_status.setStyleSheet(f"color:{color}; font-size:9pt;")

    def _on_epoch(self, m):
        # Charts
        self.chart_acc.add_point('train', m['epoch'], m['train_acc'])
        self.chart_acc.add_point('val',   m['epoch'], m['val_acc'])
        self.chart_acc.add_point('f1',    m['epoch'], m['f1'])
        self.chart_loss.add_point('train', m['epoch'], m['train_loss'])
        self.chart_loss.add_point('val',   m['epoch'], m['val_loss'])

        # Table
        r = self.tbl.rowCount()
        self.tbl.insertRow(r)
        vals = [
            m['epoch'], m['train_loss'], m['train_acc'],
            m['val_loss'], m['val_acc'],
            m['precision'], m['recall'], m['f1'], m['lr']
        ]
        for c, v in enumerate(vals):
            item = QTableWidgetItem(str(v))
            item.setTextAlignment(Qt.AlignCenter)
            if c == 4:  # val acc
                fv = float(v)
                item.setForeground(QColor(
                    "#00ff88" if fv >= 95 else
                    "#00d9ff" if fv >= 85 else
                    "#ffaa00" if fv >= 70 else "#ff6b6b"
                ))
            self.tbl.setItem(r, c, item)
        self.tbl.scrollToBottom()

    def _on_done(self, result):
        self.btn_start.setEnabled(True)
        self.btn_stop.setEnabled(False)

        if result.get('success'):
            acc = result['best_val_acc']
            grade = (
                "🏆 Excellent" if acc >= 95 else
                "✅ Good"      if acc >= 85 else
                "⚠️ Fair"      if acc >= 70 else
                "❌ Poor — try more data or epochs"
            )
            html = (
                f"<h2 style='color:#00d9ff;margin-bottom:12px;'>Training Complete!</h2>"
                f"<p style='font-size:16pt;color:#00ff88;'><b>{acc:.2f}%</b>  {grade}</p>"
                f"<p style='color:#aaa;'>Epochs: {result.get('epochs_done','?')}</p>"
                f"<p style='color:#aaa;'>Model saved to:<br>"
                f"<code style='color:#e0e0e0;font-size:8pt;'>"
                f"{result.get('model_path','?')}</code></p>"
                f"<hr style='border-color:#333;'>"
                f"<p style='color:#888;font-size:9pt;'>"
                f"The model is now saved and will be loaded automatically on next startup.<br>"
                f"A hot-reload into the live detector was attempted.</p>"
            )
            self.lbl_result.setText(html)
            self.lbl_result.setTextFormat(Qt.RichText)
            self.tabs.setCurrentIndex(3)

            self._hot_reload(result['model_path'])

            QMessageBox.information(
                self, "✅ Training Complete",
                f"Best Validation Accuracy: {acc:.2f}%\n"
                f"Model saved and ready to use.\n\n"
                f"Restart monitoring to apply the new model."
            )
        else:
            err = result.get('error', 'Unknown error')
            self.lbl_result.setText(f"❌ Training failed:\n\n{err}")
            QMessageBox.critical(self, "Training Failed", str(err))

    def _hot_reload(self, model_path):
        try:
            parent = self.parent()
            if parent and hasattr(parent, 'intrusion_detector'):
                det  = parent.intrusion_detector
                data = torch.load(model_path, map_location='cpu')
                sdct = data['state_dict'] if isinstance(data, dict) else data
                idim = data.get('input_dim', 20) if isinstance(data, dict) else 20
                hdim = data.get('hidden_dim', 64) if isinstance(data, dict) else 64
                m    = GNNDetector(input_dim=idim, hidden_dim=hdim)
                m.load_state_dict(sdct)
                m.eval()
                det.gnn_model = m.to(det.device)
                self._log("🔄 Model hot-reloaded into live detector!")
        except Exception as e:
            self._log(f"ℹ️  Hot-reload skipped: {e}")

    def _log(self, msg):
        ts = datetime.now().strftime("%H:%M:%S")
        self.log.append(f"[{ts}] {msg}")
        self.log.verticalScrollBar().setValue(
            self.log.verticalScrollBar().maximum()
        )

    def _export_log(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Log", "training_log.txt", "Text Files (*.txt)"
        )
        if path:
            with open(path, 'w') as f:
                f.write(self.log.toPlainText())
            QMessageBox.information(self, "Exported", f"Saved to:\n{path}")
