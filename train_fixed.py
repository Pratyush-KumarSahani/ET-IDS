"""
train_fixed.py — corrected version of your train.ipynb

Changes from original:
  1. [CRITICAL] Uses multiclass label column, not binary_label
     → model now actually learns BruteForce, DDoS, etc. as separate classes
  2. [CRITICAL] LabelEncoder saved BEFORE transform, classes verified
  3. [HIGH]     Class imbalance handled via scale_pos_weight / sample_weight
  4. [HIGH]     max_depth reduced 10→6 to prevent overfitting
  5. [MEDIUM]   SelectKBest removed (k=20/22 was pointless)
  6. [MEDIUM]   Per-class report printed so you can see rare-class performance
  7. [LOW]      Probability calibration added (isotonic regression)
  8.            feature_columns.pkl saved in correct order
  9.            Sanity check: live-like single-packet input tested
"""

import pandas as pd
import numpy as np
import joblib
import warnings
warnings.filterwarnings("ignore")

# ─────────────────────────────────────────────────────────────
# 1. Load & clean  (unchanged from your notebook)
# ─────────────────────────────────────────────────────────────
print("Loading data...")
df = pd.read_csv("../data/raw/unified_dataset.csv")

df.replace([np.inf, -np.inf], np.nan, inplace=True)
df.dropna(inplace=True)

for col in df.select_dtypes(include=np.number).columns:
    df = df[df[col] < 1e15]
    df = df[df[col] > -1e15]

print("After cleaning:", df.shape)
print("\nNaN:", df.isna().sum().sum())
print("Inf:", np.isinf(df.select_dtypes(include=np.number)).sum().sum())


# ─────────────────────────────────────────────────────────────
# 2. FIX #1 — Use the multiclass label, not binary_label
# ─────────────────────────────────────────────────────────────

# Check what label columns exist
print("\nAvailable columns with 'label' in name:")
label_cols = [c for c in df.columns if 'label' in c.lower()]
print(label_cols)

# ── CHANGE THIS to whichever column has the attack type names ──
# Common column names in CIC-IDS datasets:
#   'Label', 'label', 'attack_type', 'multiclass_label', 'category'
# If you only have binary and still want multiclass,
# use 'Label' (the original CIC column) which has: BENIGN, DoS, BruteForce...

LABEL_COLUMN = "Label"    # ← adjust if your column is named differently
                          #   e.g. "attack_type" or "multiclass_label"

# If you genuinely only have binary labels in your dataset,
# use binary_label but understand the model can only output 2 classes:
# LABEL_COLUMN = "binary_label"

print(f"\nUsing label column: '{LABEL_COLUMN}'")
print("Class distribution:")
print(df[LABEL_COLUMN].value_counts())
print("\nClass proportions:")
print(df[LABEL_COLUMN].value_counts(normalize=True).round(3))


# ─────────────────────────────────────────────────────────────
# 3. Feature engineering  (unchanged from your notebook)
# ─────────────────────────────────────────────────────────────
df['bytes_per_packet']   = df['total_bytes']   / (df['total_packets']   + 1e-6)
df['packets_per_second'] = df['total_packets'] / (df['flow_duration']   + 1e-6)
df['avg_packet_size']    = df['total_bytes']   / (df['total_packets']   + 1e-6)
df['byte_rate']          = df['total_bytes']   / (df['flow_duration']   + 1e-6)
df['burstiness']         = df['pkt_len_std']   / (df['avg_pkt_len']     + 1e-6)
df['flag_sum']           = (df['syn_flag'] + df['ack_flag'] +
                            df['rst_flag'] + df['psh_flag'])

selected_features = [
    'dst_port', 'protocol', 'flow_duration', 'total_packets', 'total_bytes',
    'min_pkt_len', 'max_pkt_len', 'avg_pkt_len', 'pkt_len_std', 'flow_rate',
    'iat', 'syn_flag', 'ack_flag', 'rst_flag', 'psh_flag', 'ttl',
    'bytes_per_packet', 'packets_per_second', 'avg_packet_size',
    'byte_rate', 'burstiness', 'flag_sum'
]

X = df[selected_features].astype(np.float32)
y_raw = df[LABEL_COLUMN]


# ─────────────────────────────────────────────────────────────
# 4. FIX #2 — Encode labels and verify classes
# ─────────────────────────────────────────────────────────────
from sklearn.preprocessing import LabelEncoder

le = LabelEncoder()
y  = le.fit_transform(y_raw)

print(f"\nLabel encoder classes ({len(le.classes_)}):")
for i, cls in enumerate(le.classes_):
    count = (y == i).sum()
    print(f"  [{i}] {cls:<30s}  n={count:,}")

# Sanity check: make sure BruteForce, DDoS etc. are in there
# (if you used binary_label they won't be — that's the bug)
attack_classes = [c for c in le.classes_ if c.upper() not in ("BENIGN","NORMAL")]
if not attack_classes:
    print("\n⚠️  WARNING: No attack classes found!")
    print("   Your label column only has BENIGN/NORMAL.")
    print(f"   Check if '{LABEL_COLUMN}' is the right column.")
    print("   Try: LABEL_COLUMN = 'Label' or 'attack_type'")


# ─────────────────────────────────────────────────────────────
# 5. FIX #6 — Check rare class sample counts
# ─────────────────────────────────────────────────────────────
print("\nRare class check (classes with < 100 samples):")
rare = [(le.classes_[i], (y==i).sum()) for i in range(len(le.classes_))
        if (y==i).sum() < 100]
if rare:
    for cls, n in rare:
        print(f"  ⚠️  {cls}: only {n} samples — may not generalise well")
else:
    print("  All classes have ≥ 100 samples ✓")


# ─────────────────────────────────────────────────────────────
# 6. Train / test split
# ─────────────────────────────────────────────────────────────
from sklearn.model_selection import train_test_split

X_train, X_test, y_train, y_test = train_test_split(
    X, y,
    test_size=0.2,
    stratify=y,
    random_state=42
)
print(f"\nTrain: {X_train.shape}  Test: {X_test.shape}")


# ─────────────────────────────────────────────────────────────
# 7. FIX #3 — Class imbalance: compute sample weights
# ─────────────────────────────────────────────────────────────
from sklearn.utils.class_weight import compute_sample_weight

sample_weights = compute_sample_weight(class_weight="balanced", y=y_train)
# This upweights rare attack classes so the model pays equal attention to them.
# Without this, the model sees 95% BENIGN and learns to just predict BENIGN.

print("\nSample weight range:",
      sample_weights.min().round(4), "→", sample_weights.max().round(4))


# ─────────────────────────────────────────────────────────────
# 8. FIX #4 & #5 — Build pipeline (no SelectKBest, lower max_depth)
# ─────────────────────────────────────────────────────────────
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from xgboost import XGBClassifier

n_classes = len(le.classes_)

pipeline = Pipeline([
    ('scaler', StandardScaler()),
    # SelectKBest REMOVED — k=20/22 adds noise, not signal

    ('model', XGBClassifier(
        n_estimators=300,
        max_depth=6,            # was 10 — reduced to prevent overfitting
        learning_rate=0.05,
        subsample=0.8,
        colsample_bytree=0.8,
        eval_metric='mlogloss' if n_classes > 2 else 'logloss',
        num_class=n_classes if n_classes > 2 else None,
        objective='multi:softprob' if n_classes > 2 else 'binary:logistic',
        use_label_encoder=False,
        random_state=42,
        n_jobs=-1,
    ))
])

print(f"\nTraining {'multiclass' if n_classes > 2 else 'binary'} model "
      f"({n_classes} classes)...")

pipeline.fit(
    X_train, y_train,
    model__sample_weight=sample_weights   # FIX #3: pass weights
)
print("Training complete ✓")


# ─────────────────────────────────────────────────────────────
# 9. FIX #7 — Calibrate probabilities
# ─────────────────────────────────────────────────────────────
from sklearn.calibration import CalibratedClassifierCV

print("\nCalibrating probabilities (isotonic)...")
# Calibration wraps the pipeline so predict_proba is more reliable.
# This makes the confidence threshold in inference_fix.py actually meaningful.
calibrated = CalibratedClassifierCV(pipeline, method="isotonic", cv=3)
calibrated.fit(X_train, y_train, sample_weight=sample_weights)
print("Calibration complete ✓")


# ─────────────────────────────────────────────────────────────
# 10. FIX #6 — Detailed evaluation (per-class report)
# ─────────────────────────────────────────────────────────────
from sklearn.metrics import classification_report, confusion_matrix

y_pred = calibrated.predict(X_test)

print("\n=== CLASSIFICATION REPORT ===")
print(classification_report(
    y_test, y_pred,
    target_names=le.classes_,
    zero_division=0
))

print("\n=== CONFUSION MATRIX ===")
cm = confusion_matrix(y_test, y_pred)
print(cm)

# Check false positive rate for BENIGN
benign_idx = list(le.classes_).index("BENIGN") if "BENIGN" in le.classes_ else 0
benign_total = (y_test == benign_idx).sum()
benign_wrong = cm[benign_idx].sum() - cm[benign_idx, benign_idx]
print(f"\nFalse positive rate (BENIGN flagged as attack): "
      f"{benign_wrong}/{benign_total} = {benign_wrong/max(benign_total,1)*100:.2f}%")


# ─────────────────────────────────────────────────────────────
# 11. Sanity check: simulate a live single-packet input
# ─────────────────────────────────────────────────────────────
print("\n=== SANITY CHECK: simulated live traffic ===")
# This is what the flow aggregator sends after collecting a short BENIGN flow
benign_flow = np.array([[
    443,    # dst_port
    6,      # protocol (TCP)
    2.5,    # flow_duration — REALISTIC (not 0.001)
    15,     # total_packets — REALISTIC flow
    8500,   # total_bytes
    40,     # min_pkt_len
    1460,   # max_pkt_len
    566,    # avg_pkt_len
    480,    # pkt_len_std
    6.0,    # flow_rate
    0.17,   # iat
    1,      # syn_flag
    1,      # ack_flag
    0,      # rst_flag
    1,      # psh_flag
    64,     # ttl
    566,    # bytes_per_packet
    6.0,    # packets_per_second
    566,    # avg_packet_size
    3400,   # byte_rate
    0.85,   # burstiness
    3,      # flag_sum
]], dtype=np.float32)

proba = calibrated.predict_proba(benign_flow)[0]
pred_idx = int(np.argmax(proba))
label = le.inverse_transform([pred_idx])[0]
confidence = proba[pred_idx]

print(f"  Predicted: {label} ({confidence*100:.1f}% confidence)")
print(f"  Expected:  BENIGN")
if label.upper() in ("BENIGN", "NORMAL"):
    print("  ✓ Correct — normal HTTPS traffic classified as BENIGN")
else:
    print(f"  ✗ Still misclassified — check your training data distribution")

# Top 3 predictions
top3 = np.argsort(proba)[::-1][:3]
print("\n  Top 3 predictions:")
for i in top3:
    print(f"    {le.classes_[i]:<30s} {proba[i]*100:.1f}%")


# ─────────────────────────────────────────────────────────────
# 12. Save everything
# ─────────────────────────────────────────────────────────────
print("\nSaving model files...")
joblib.dump(calibrated,        "../models/binary_pipeline.pkl")    # same filename, drop-in
joblib.dump(le,                "../models/binary_label_encoder.pkl")
joblib.dump(selected_features, "../models/feature_columns.pkl")

# Also save class names separately for easy inspection
import json
with open("../models/class_names.json", "w") as f:
    json.dump(list(le.classes_), f, indent=2)

print(f"Saved:")
print(f"  models/binary_pipeline.pkl        (calibrated model)")
print(f"  models/binary_label_encoder.pkl   (label encoder, {len(le.classes_)} classes)")
print(f"  models/feature_columns.pkl        (feature order)")
print(f"  models/class_names.json           (human-readable class list)")
print("\nDone! ✓")
