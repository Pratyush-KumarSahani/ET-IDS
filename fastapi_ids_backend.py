from __future__ import annotations

import asyncio
import functools
import logging
import os
import shutil
import tempfile
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, File, HTTPException, Request, UploadFile, WebSocket, WebSocketDisconnect, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field

from ids_device import load_device_identity
from ids_realtime import BlockManager, RealtimeIDS, export_logs_to_csv
from ids_storage import IDSStorage
from intrusion_detection import (
    DEFAULT_ATTACK_LABEL_ENCODER_FILENAME,
    DEFAULT_ATTACK_MODEL_FILENAME,
    DEFAULT_BINARY_CONFIDENCE_THRESHOLD,
    DEFAULT_BINARY_LABEL_ENCODER_FILENAME,
    DEFAULT_BINARY_MODEL_FILENAME,
    DEFAULT_FEATURE_COLUMNS_FILENAME,
    DEFAULT_LABEL_ENCODER_FILENAME,
    DEFAULT_MODEL_FILENAME,
    IntrusionDetector,
    TwoStageIntrusionDetector,
)


LOGGER = logging.getLogger("ids_api")
PROJECT_ROOT = Path(__file__).resolve().parent
STATIC_DIR = PROJECT_ROOT / "static"
DATA_DIR = Path(os.getenv("IDS_DATA_DIR", PROJECT_ROOT / "data")).expanduser()
DATABASE_PATH = DATA_DIR / "ids.db"
LOG_EXPORT_PATH = DATA_DIR / "exports" / "ids_logs.csv"

# FIX (stop button): must be > AsyncSniffer join timeout (3s) + buffer
STOP_CONFIRM_TIMEOUT_S = 5.0
STOP_POLL_INTERVAL_S = 0.05


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class DetectionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    features: dict[str, Any] = Field(
        ..., min_length=1,
        description="Feature mapping matching the columns used during model training.",
    )


class DetectionResponse(BaseModel):
    prediction: str


class CaptureRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    interface: str | None = Field(default=None, description="Optional network interface name.")
    packet_filter: str | None = Field(
        default=None, description="Optional BPF filter, for example 'tcp or udp'.",
    )


class BlockRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    ip: str = Field(..., description="IP address to block.")
    reason: str = Field(default="Manual block from IDS log", max_length=300)


# Friend's addition
class BlockModeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    mode: str = Field(..., description="Blocking mode: memory or windows_firewall.")


class PcapAnalyzeResponse(BaseModel):
    filename: str
    processed_packets: int
    alert_count: int
    packet_limit: int


class HealthResponse(BaseModel):
    status: str
    device: dict[str, str]
    model_loaded: bool
    model_path: str | None
    model_info: dict[str, Any] | None
    label_encoder_loaded: bool
    expected_features: list[str] | None
    capture: dict[str, Any]
    metrics: dict[str, int]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _configure_logging() -> None:
    if logging.getLogger().handlers:
        return
    logging.basicConfig(
        level=os.getenv("IDS_LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )


def _resolve_optional_artifact(env_name: str, default_filename: str) -> Path | None:
    configured_value = os.getenv(env_name)
    candidates = [Path(configured_value)] if configured_value else []
    candidates.extend([
        PROJECT_ROOT / default_filename,
        PROJECT_ROOT / "models" / default_filename,
        PROJECT_ROOT.parent / "models" / default_filename,
    ])
    for candidate in candidates:
        candidate_path = candidate.expanduser().resolve()
        if candidate_path.is_file():
            return candidate_path
    return None


def _load_detector_from_env() -> IntrusionDetector | None:
    binary_model_path = _resolve_optional_artifact("IDS_BINARY_MODEL_PATH", DEFAULT_BINARY_MODEL_FILENAME)
    attack_model_path = _resolve_optional_artifact("IDS_ATTACK_MODEL_PATH", DEFAULT_ATTACK_MODEL_FILENAME)

    if binary_model_path is not None and attack_model_path is not None:
        # FIX: pass binary_threshold from env so it's tunable without code changes
        binary_threshold = float(
            os.getenv("IDS_BINARY_CONFIDENCE_THRESHOLD", str(DEFAULT_BINARY_CONFIDENCE_THRESHOLD))
        )
        return TwoStageIntrusionDetector(
            binary_model_path=binary_model_path,
            attack_model_path=attack_model_path,
            binary_label_encoder_path=_resolve_optional_artifact(
                "IDS_BINARY_LABEL_ENCODER_PATH", DEFAULT_BINARY_LABEL_ENCODER_FILENAME,
            ),
            attack_label_encoder_path=_resolve_optional_artifact(
                "IDS_ATTACK_LABEL_ENCODER_PATH", DEFAULT_ATTACK_LABEL_ENCODER_FILENAME,
            ),
            feature_columns_path=_resolve_optional_artifact(
                "IDS_FEATURE_COLUMNS_PATH", DEFAULT_FEATURE_COLUMNS_FILENAME,
            ),
            # Friend uses 85.0 as default — kept
            attack_threshold=float(os.getenv("IDS_ATTACK_CONFIDENCE_THRESHOLD", "85.0")),
            binary_threshold=binary_threshold,
        )

    model_path = _resolve_optional_artifact("IDS_MODEL_PATH", DEFAULT_MODEL_FILENAME)
    if model_path is None:
        LOGGER.warning("No model artifact found. Live capture will run with metadata-only rules.")
        return None

    label_encoder_path = _resolve_optional_artifact(
        "IDS_LABEL_ENCODER_PATH", DEFAULT_LABEL_ENCODER_FILENAME,
    )
    return IntrusionDetector(model_path=model_path, label_encoder_path=label_encoder_path)


def _blocking_stop(realtime_ids: RealtimeIDS) -> None:
    """
    Sync wrapper for stop_capture() to run in a thread executor.
    stop_capture() joins the AsyncSniffer thread (blocks up to 3s) — must not
    run on the asyncio event loop or it will freeze all WebSocket clients.
    """
    import asyncio as _asyncio
    loop = _asyncio.new_event_loop()
    try:
        loop.run_until_complete(realtime_ids.stop_capture())
    finally:
        loop.close()


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    _configure_logging()

    detector = None
    try:
        detector = _load_detector_from_env()
    except Exception:
        LOGGER.exception("Failed to load intrusion detection artifacts during startup")

    storage = IDSStorage(DATABASE_PATH)
    block_manager = BlockManager(
        mode=os.getenv("IDS_BLOCK_MODE", "memory"),
        blocked_ips=storage.list_blocked_ips(),
        on_block=storage.save_blocked_ip,
        on_unblock=storage.remove_blocked_ip,
    )
    app.state.detector = detector
    app.state.storage = storage
    app.state.device = load_device_identity(DATA_DIR)
    app.state.realtime_ids = RealtimeIDS(
        detector=detector,
        block_manager=block_manager,
        storage=storage,
    )

    if os.getenv("IDS_AUTO_START", "false").strip().lower() in {"1", "true", "yes"}:
        try:
            await app.state.realtime_ids.start_capture(
                interface=os.getenv("IDS_CAPTURE_INTERFACE") or None,
                packet_filter=os.getenv("IDS_CAPTURE_FILTER") or None,
            )
        except Exception:
            LOGGER.exception("Auto-start packet capture failed")

    yield

    await app.state.realtime_ids.stop_capture()


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------

def create_app() -> FastAPI:
    app = FastAPI(
        title="Encrypted Traffic IDS",
        version="3.1.0",
        description="Real-time metadata-based IDS dashboard for encrypted network traffic.",
        lifespan=lifespan,
    )
    allowed_origins = os.getenv("IDS_CORS_ORIGINS", "*").split(",")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_credentials="*" not in allowed_origins,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    if STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    @app.exception_handler(ValueError)
    async def value_error_handler(_: Request, exc: ValueError) -> JSONResponse:
        return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content={"detail": str(exc)})

    @app.exception_handler(RuntimeError)
    async def runtime_error_handler(_: Request, exc: RuntimeError) -> JSONResponse:
        return JSONResponse(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, content={"detail": str(exc)})

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(_: Request, exc: Exception) -> JSONResponse:
        LOGGER.exception("Unhandled application error", exc_info=exc)
        return JSONResponse(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, content={"detail": "Internal server error"})

    # ------------------------------------------------------------------
    # Static / dashboard
    # ------------------------------------------------------------------

    @app.get("/", include_in_schema=False)
    async def dashboard() -> FileResponse:
        index_path = STATIC_DIR / "index.html"
        if not index_path.is_file():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Dashboard assets are missing.")
        return FileResponse(index_path)

    # ------------------------------------------------------------------
    # Health
    # ------------------------------------------------------------------

    @app.get("/health", response_model=HealthResponse, tags=["system"])
    async def health_check(request: Request) -> HealthResponse:
        detector: IntrusionDetector | None = request.app.state.detector
        realtime_ids: RealtimeIDS = request.app.state.realtime_ids
        storage: IDSStorage = request.app.state.storage
        return HealthResponse(
            status="ok",
            device=request.app.state.device,
            model_loaded=detector is not None,
            model_path=str(detector.model_path) if detector is not None else None,
            model_info=(
                detector.model_info()
                if detector is not None and hasattr(detector, "model_info")
                else None
            ),
            label_encoder_loaded=bool(detector and detector.label_encoder is not None),
            expected_features=detector.expected_features() if detector is not None else None,
            capture=realtime_ids.status(),
            metrics=storage.summary(),
        )

    # ------------------------------------------------------------------
    # Detection
    # ------------------------------------------------------------------

    @app.post("/detect", response_model=DetectionResponse, tags=["detection"])
    async def detect_intrusion(payload: DetectionRequest, request: Request) -> DetectionResponse:
        detector: IntrusionDetector | None = request.app.state.detector
        if detector is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Model is not loaded. Configure IDS_MODEL_PATH or place pipeline.pkl in the project.",
            )
        prediction = detector.predict(payload.features)
        return DetectionResponse(prediction=prediction)

    # ------------------------------------------------------------------
    # Capture
    # ------------------------------------------------------------------

    @app.post("/capture/start", tags=["capture"])
    async def start_capture(payload: CaptureRequest, request: Request) -> dict[str, Any]:
        realtime_ids: RealtimeIDS = request.app.state.realtime_ids
        return await realtime_ids.start_capture(payload.interface, payload.packet_filter)

    @app.post("/capture/stop", tags=["capture"])
    async def stop_capture(request: Request) -> dict[str, Any]:
        """
        FIX (stop button): stop_capture() now joins the AsyncSniffer internal
        thread (blocks up to 3s). We run it in a thread executor so the asyncio
        event loop stays responsive and WebSocket clients don't freeze.
        Response is only sent after is_running is confirmed False.
        """
        realtime_ids: RealtimeIDS = request.app.state.realtime_ids

        # Run blocking join in executor — keeps event loop responsive
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, functools.partial(_blocking_stop, realtime_ids))

        # Brief confirmation poll — should be instant since thread is joined above
        elapsed = 0.0
        while realtime_ids.is_running and elapsed < STOP_CONFIRM_TIMEOUT_S:
            await asyncio.sleep(STOP_POLL_INTERVAL_S)
            elapsed += STOP_POLL_INTERVAL_S

        if realtime_ids.is_running:
            LOGGER.warning("Capture still running after %.1fs — forcing null", STOP_CONFIRM_TIMEOUT_S)
            realtime_ids._sniffer = None
            realtime_ids._simulation_active = False

        LOGGER.info("Stop endpoint returning: running=%s", realtime_ids.is_running)
        return realtime_ids.status()

    @app.get("/capture/status", tags=["capture"])
    async def capture_status(request: Request) -> dict[str, Any]:
        realtime_ids: RealtimeIDS = request.app.state.realtime_ids
        return realtime_ids.status()

    @app.get("/capture/interfaces", tags=["capture"])
    async def capture_interfaces() -> dict[str, Any]:
        return {"interfaces": RealtimeIDS.list_interfaces()}

    # ------------------------------------------------------------------
    # Logs
    # ------------------------------------------------------------------

    @app.get("/logs", tags=["logs"])
    async def get_logs(request: Request, limit: int = 100, history: bool = False) -> dict[str, Any]:
        realtime_ids: RealtimeIDS = request.app.state.realtime_ids
        storage: IDSStorage = request.app.state.storage
        # history=True → DB logs (for export / review of past runs)
        # history=False (default) → session logs only (live dashboard)
        logs = storage.recent_logs(limit) if history else realtime_ids.recent_logs(limit)
        return {
            "logs": logs,
            "session": realtime_ids.status(),
        }

    @app.post("/logs/export", tags=["logs"])
    async def export_logs(request: Request) -> dict[str, str]:
        storage: IDSStorage = request.app.state.storage
        # Export always reads from DB to get all historical logs
        exported_path = export_logs_to_csv(storage.recent_logs(5000), LOG_EXPORT_PATH)
        return {"path": str(exported_path)}

    # Friend's addition: clear all logs
    @app.delete("/logs", tags=["logs"])
    async def clear_logs(request: Request) -> dict[str, str]:
        storage: IDSStorage = request.app.state.storage
        realtime_ids: RealtimeIDS = request.app.state.realtime_ids
        storage.clear_packet_logs()
        realtime_ids.logs.clear()
        realtime_ids._history_logs.clear()
        realtime_ids._packet_counter = 0
        realtime_ids._session_counter = 0
        realtime_ids._publish({"type": "snapshot", "data": []})
        return {"status": "cleared"}

    # ------------------------------------------------------------------
    # PCAP
    # ------------------------------------------------------------------

    @app.post("/pcap/analyze", response_model=PcapAnalyzeResponse, tags=["offline-analysis"])
    async def analyze_pcap(
        request: Request,
        file: UploadFile = File(...),
        packet_limit: int = 5000,
    ) -> PcapAnalyzeResponse:
        filename = Path(file.filename or "capture.pcap").name
        if not filename.lower().endswith((".pcap", ".pcapng", ".cap")):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Upload a .pcap, .pcapng, or .cap file.",
            )

        suffix = Path(filename).suffix or ".pcap"
        realtime_ids: RealtimeIDS = request.app.state.realtime_ids

        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as temp_file:
            temp_path = Path(temp_file.name)
            shutil.copyfileobj(file.file, temp_file)

        try:
            result = realtime_ids.analyze_pcap(temp_path, packet_limit=packet_limit)
        except FileNotFoundError as exc:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
        except Exception as exc:
            LOGGER.exception("Failed to analyze uploaded PCAP")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Could not analyze PCAP: {exc}",
            ) from exc
        finally:
            temp_path.unlink(missing_ok=True)
            await file.close()

        return PcapAnalyzeResponse(
            filename=filename,
            processed_packets=result["processed_packets"],
            alert_count=result["alert_count"],
            packet_limit=result["packet_limit"],
        )

    # ------------------------------------------------------------------
    # Blocklist & response
    # ------------------------------------------------------------------

    @app.get("/blocklist", tags=["response"])
    async def get_blocklist(request: Request) -> dict[str, Any]:
        realtime_ids: RealtimeIDS = request.app.state.realtime_ids
        snapshot = realtime_ids.status()
        return {
            "blocked_ips": snapshot["blocked_ips"],
            "blocked_entries": snapshot["blocked_entries"],
            "block_mode": snapshot["block_mode"],
            "warning_counts": snapshot["warning_counts"],
        }

    @app.post("/blocklist", tags=["response"])
    async def block_ip(payload: BlockRequest, request: Request) -> dict[str, str]:
        realtime_ids: RealtimeIDS = request.app.state.realtime_ids
        return realtime_ids.block_ip(payload.ip, payload.reason)

    @app.delete("/blocklist/{ip_address}", tags=["response"])
    async def unblock_ip(ip_address: str, request: Request) -> dict[str, str]:
        realtime_ids: RealtimeIDS = request.app.state.realtime_ids
        return realtime_ids.unblock_ip(ip_address)

    # Friend's addition: switch block mode at runtime
    @app.post("/response/mode", tags=["response"])
    async def set_block_mode(payload: BlockModeRequest, request: Request) -> dict[str, Any]:
        realtime_ids: RealtimeIDS = request.app.state.realtime_ids
        return realtime_ids.set_block_mode(payload.mode)

    # ------------------------------------------------------------------
    # WebSocket
    # ------------------------------------------------------------------

    @app.websocket("/ws/logs")
    async def logs_websocket(websocket: WebSocket) -> None:
        await websocket.accept()
        realtime_ids: RealtimeIDS = websocket.app.state.realtime_ids
        queue = realtime_ids.subscribe()

        try:
            # FIX (counter accumulation): self.logs is session-only — cleared on
            # start_capture() — so this snapshot is empty between runs and never
            # inflates the packet counter with old DB history.
            await websocket.send_json({
                "type": "snapshot",
                "data": realtime_ids.recent_logs(100),
            })
            # Send authoritative session counter so frontend syncs immediately
            await websocket.send_json({
                "type": "session_status",
                "data": realtime_ids.status(),
            })
            while True:
                event = await queue.get()
                await websocket.send_json(event)
        except WebSocketDisconnect:
            LOGGER.info("Live log client disconnected")
        finally:
            realtime_ids.unsubscribe(queue)

    return app


app = create_app()
