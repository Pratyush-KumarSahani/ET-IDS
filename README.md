# Encrypted Traffic IDS

FastAPI-based intrusion detection dashboard for encrypted traffic monitoring. The app captures packet metadata only, streams real-time logs to a browser dashboard, supports manual blocking from logs, and can use the trained `pipeline.pkl` plus `label_encoder.pkl` artifacts from `train.ipynb` when available.

## Setup

Use a stable Python release such as Python 3.11 or 3.12. Avoid Python alpha builds because compiled packages such as `pydantic-core`, `scikit-learn`, and `xgboost` may fail to import.

```powershell
pip install -r requirements.txt
```

Put model artifacts in one of these locations:

- `D:\ET-IDS\pipeline.pkl`
- `D:\ET-IDS\models\pipeline.pkl`
- `D:\models\pipeline.pkl`

The app also supports the newer two-stage ML model layout. If these files exist in `D:\ET-IDS\models`, they are loaded first and used for live attack/type decisions:

- `binary_pipeline.pkl`
- `binary_label_encoder.pkl`
- `attack_pipeline.pkl`
- `attack_label_encoder.pkl`
- `feature_columns.pkl`

Live attack labels are gated to reduce noisy false positives: a flow must have at least 8 packets, at least 2 seconds of observed duration, and attack confidence of 80% or higher before the dashboard shows a specific attack alert. Override the confidence threshold with:

```powershell
$env:IDS_ATTACK_CONFIDENCE_THRESHOLD="90"
```

Or configure explicit paths:

```powershell
$env:IDS_MODEL_PATH="D:\ET-IDS\models\pipeline.pkl"
$env:IDS_LABEL_ENCODER_PATH="D:\ET-IDS\models\label_encoder.pkl"
$env:IDS_BINARY_MODEL_PATH="D:\ET-IDS\models\binary_pipeline.pkl"
$env:IDS_ATTACK_MODEL_PATH="D:\ET-IDS\models\attack_pipeline.pkl"
```

## Run

For the full dashboard with dependency installation and live packet capture enabled:

```powershell
cd D:\ET-IDS\et-ids
.\start_ids.ps1
```

Open:

```text
http://localhost:8000
```

Run PowerShell as Administrator for live packet capture on Windows. Install Npcap first if capture does not start.

Useful options:

```powershell
.\start_ids.ps1 -OpenDashboard
.\start_ids.ps1 -CaptureInterface "Ethernet" -CaptureFilter "tcp port 443"
.\start_ids.ps1 -NoCapture
.\start_ids.ps1 -UseWindowsFirewall
.\start_ids.ps1 -SkipInstall
```

Manual server run:

```powershell
uvicorn fastapi_ids_backend:app --host 0.0.0.0 --port 8000
```

Open:

```text
http://localhost:8000
```

Live capture usually requires Npcap on Windows and may require running the terminal as Administrator.

You can also start the IDS appliance with the helper script:

```powershell
.\start_ids.ps1 -Port 8000 -CaptureFilter "tcp port 443"
```

For a specific interface:

```powershell
.\start_ids.ps1 -CaptureInterface "Ethernet" -CaptureFilter "host 192.168.1.10"
```

The app stores device identity, logs, and blocked IPs in:

```text
D:\ET-IDS\et-ids\data
```

Override that location with:

```powershell
$env:IDS_DATA_DIR="D:\ET-IDS\data"
```

## Blocking Mode

By default, blocking is an in-app blocklist used by the dashboard and live logs:

```powershell
$env:IDS_BLOCK_MODE="memory"
```

To create Windows Firewall block rules from the dashboard:

```powershell
$env:IDS_BLOCK_MODE="windows_firewall"
```

Use the firewall mode carefully because it changes host firewall rules.

## Device Deployment Idea

For a host-based IDS, install this project on the web server or target device and capture the active network interface. For a network IDS, connect the device to a mirrored switch port or traffic mirror so it can see packets for the protected public IP. Passive capture can detect and log; blocking requires either local firewall mode or integration with the gateway firewall.
