from __future__ import annotations

import platform
import socket
import uuid
from pathlib import Path


def load_device_identity(data_dir: str | Path) -> dict[str, str]:
    data_path = Path(data_dir).expanduser().resolve()
    data_path.mkdir(parents=True, exist_ok=True)
    identity_path = data_path / "device_id"

    if identity_path.is_file():
        device_id = identity_path.read_text(encoding="utf-8").strip()
    else:
        device_id = str(uuid.uuid4())
        identity_path.write_text(device_id, encoding="utf-8")

    return {
        "device_id": device_id,
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
    }
