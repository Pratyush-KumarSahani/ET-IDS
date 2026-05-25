from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

import joblib
import numpy as np
import pandas as pd


LOGGER = logging.getLogger(__name__)

DEFAULT_MODEL_FILENAME = "pipeline.pkl"
DEFAULT_LABEL_ENCODER_FILENAME = "label_encoder.pkl"
DEFAULT_BINARY_MODEL_FILENAME = "binary_pipeline.pkl"
DEFAULT_BINARY_LABEL_ENCODER_FILENAME = "binary_label_encoder.pkl"
DEFAULT_ATTACK_MODEL_FILENAME = "attack_pipeline.pkl"
DEFAULT_ATTACK_LABEL_ENCODER_FILENAME = "attack_label_encoder.pkl"
DEFAULT_FEATURE_COLUMNS_FILENAME = "feature_columns.pkl"
DEFAULT_ATTACK_CONFIDENCE_THRESHOLD = 80.0

# FIX: Binary Stage 1 threshold raised from implicit 50% → 65%.
# Flows the model is only slightly unsure about are treated as benign
# until they cross this higher bar — cuts medium-confidence false positives.
DEFAULT_BINARY_CONFIDENCE_THRESHOLD = 65.0

_DEFAULT_DETECTOR: "IntrusionDetector | None" = None


@dataclass(frozen=True)
class DetectionResult:
    prediction: str
    threat: str
    confidence: float | None
    binary_label: str | None = None
    attack_label: str | None = None
    # FIX: expose raw binary-class probability separately from attack confidence
    # so ids_realtime can apply its own consensus logic independently.
    binary_confidence: float | None = None


def _resolve_artifact_path(path_value: str | Path) -> Path:
    resolved_path = Path(path_value).expanduser().resolve()
    if not resolved_path.is_file():
        raise FileNotFoundError(f"Artifact file not found: {resolved_path}")
    return resolved_path


def _load_artifact(path_value: str | Path) -> Any:
    artifact_path = _resolve_artifact_path(path_value)
    return joblib.load(artifact_path)


def _coerce_feature_frame(features: Mapping[str, Any]) -> pd.DataFrame:
    if not features:
        raise ValueError("Feature payload cannot be empty.")
    return pd.DataFrame([dict(features)])


def _scale_features_for_inference(features: Mapping[str, Any]) -> dict[str, Any]:
    """
    Scale live flow features to the units used during model training.

    The trained datasets expect durations and inter-arrival values in microseconds,
    while the runtime capture pipeline builds them in seconds.

    Also strips internal routing keys (prefixed with '_') that must never
    reach the model's feature matrix.
    """
    # Strip internal keys used for routing in ids_realtime (_src_port, etc.)
    scaled = {k: v for k, v in features.items() if not str(k).startswith("_")}

    flow_duration_sec = float(features.get("flow_duration") or 0.0)
    iat_sec = float(features.get("iat") or 0.0)
    flow_duration_us = flow_duration_sec * 1_000_000.0
    iat_us = iat_sec * 1_000_000.0

    scaled["flow_duration"] = flow_duration_us
    scaled["iat"] = iat_us

    total_packets = int(features.get("total_packets") or 0)
    total_bytes = int(features.get("total_bytes") or 0)
    scaled["flow_rate"] = total_packets / (flow_duration_sec + 1e-6)
    scaled["packets_per_second"] = total_packets / (flow_duration_us + 1e-6)
    scaled["byte_rate"] = total_bytes / (flow_duration_us + 1e-6)

    if "avg_packet_size" not in scaled or scaled["avg_packet_size"] == 0.0:
        scaled["avg_packet_size"] = total_bytes / (total_packets + 1e-6)

    # Strip internal routing keys that must not reach the model
    for key in ("classify_counter",):
        scaled.pop(key, None)

    return scaled


class IntrusionDetector:
    def __init__(
        self,
        model_path: str | Path,
        label_encoder_path: str | Path | None = None,
    ):
        self.model_path = _resolve_artifact_path(model_path)
        self.model = _load_artifact(self.model_path)
        self.label_encoder_path = (
            _resolve_artifact_path(label_encoder_path)
            if label_encoder_path is not None
            else None
        )
        self.label_encoder = (
            _load_artifact(self.label_encoder_path)
            if self.label_encoder_path is not None
            else None
        )

        LOGGER.info("Loaded detection pipeline from %s", self.model_path)
        if self.label_encoder_path is not None:
            LOGGER.info("Loaded label encoder from %s", self.label_encoder_path)

    def expected_features(self) -> list[str] | None:
        if hasattr(self.model, "feature_names_in_"):
            return list(self.model.feature_names_in_)

        selector = getattr(
            getattr(self.model, "named_steps", {}), "get", lambda *_: None
        )("selector")
        if selector is not None and hasattr(selector, "feature_names_in_"):
            return list(selector.feature_names_in_)

        return None

    def _prepare_input(self, features: Mapping[str, Any]) -> pd.DataFrame:
        feature_frame = _coerce_feature_frame(features)
        expected_features = self.expected_features()

        if expected_features is None:
            return feature_frame

        missing_features = [
            name for name in expected_features if name not in feature_frame.columns
        ]
        if missing_features:
            raise ValueError(
                "Missing required model features: "
                + ", ".join(sorted(missing_features))
            )

        return feature_frame.reindex(columns=expected_features)

    def _decode_prediction(self, raw_prediction: Any) -> str:
        if self.label_encoder is not None:
            decoded = self.label_encoder.inverse_transform(
                np.asarray([raw_prediction])
            )[0]
            return str(decoded)
        return str(raw_prediction)

    def predict(self, features: Mapping[str, Any]) -> str:
        scaled = _scale_features_for_inference(features)
        model_input = self._prepare_input(scaled)
        raw_prediction = self.model.predict(model_input)[0]
        prediction = self._decode_prediction(raw_prediction)

        if prediction.strip().lower() != "benign":
            LOGGER.warning("Threat detected with label=%s", prediction)
        else:
            LOGGER.info("Benign traffic prediction generated")

        return prediction

    def predict_details(self, features: Mapping[str, Any]) -> DetectionResult:
        scaled = _scale_features_for_inference(features)
        model_input = self._prepare_input(scaled)
        raw_prediction = self.model.predict(model_input)[0]
        prediction = self._decode_prediction(raw_prediction)
        normalized_prediction = prediction.strip().lower()
        is_benign = normalized_prediction in {"benign", "normal"}

        confidence: float | None = None
        if hasattr(self.model, "predict_proba"):
            probs = self.model.predict_proba(model_input)
            confidence = round(float(np.max(probs)) * 100, 2)

        return DetectionResult(
            prediction="Benign" if is_benign else prediction,
            threat="None" if is_benign else prediction,
            confidence=confidence,
            binary_label=prediction,
            attack_label=None if is_benign else prediction,
            binary_confidence=confidence,
        )

    def model_info(self) -> dict[str, Any]:
        return {
            "type": "single_stage",
            "model_path": str(self.model_path),
            "label_encoder_path": (
                str(self.label_encoder_path) if self.label_encoder_path else None
            ),
            "expected_features": self.expected_features(),
            "attack_threshold": None,
            "binary_threshold": DEFAULT_BINARY_CONFIDENCE_THRESHOLD,
        }


class TwoStageIntrusionDetector:
    def __init__(
        self,
        *,
        binary_model_path: str | Path,
        attack_model_path: str | Path,
        binary_label_encoder_path: str | Path | None = None,
        attack_label_encoder_path: str | Path | None = None,
        feature_columns_path: str | Path | None = None,
        attack_threshold: float = DEFAULT_ATTACK_CONFIDENCE_THRESHOLD,
        # FIX: explicit binary threshold — tunable via env var
        binary_threshold: float = DEFAULT_BINARY_CONFIDENCE_THRESHOLD,
    ) -> None:
        self.binary_model_path = _resolve_artifact_path(binary_model_path)
        self.attack_model_path = _resolve_artifact_path(attack_model_path)
        self.binary_model = _load_artifact(self.binary_model_path)
        self.attack_model = _load_artifact(self.attack_model_path)
        self.binary_label_encoder_path = (
            _resolve_artifact_path(binary_label_encoder_path)
            if binary_label_encoder_path is not None
            else None
        )
        self.attack_label_encoder_path = (
            _resolve_artifact_path(attack_label_encoder_path)
            if attack_label_encoder_path is not None
            else None
        )
        self.binary_label_encoder = (
            _load_artifact(self.binary_label_encoder_path)
            if self.binary_label_encoder_path is not None
            else None
        )
        self.attack_label_encoder = (
            _load_artifact(self.attack_label_encoder_path)
            if self.attack_label_encoder_path is not None
            else None
        )
        self.feature_columns_path = (
            _resolve_artifact_path(feature_columns_path)
            if feature_columns_path is not None
            else None
        )
        self.feature_columns = (
            list(_load_artifact(self.feature_columns_path))
            if self.feature_columns_path is not None
            else None
        )
        self.attack_threshold = attack_threshold
        self.binary_threshold = binary_threshold

        LOGGER.info(
            "Loaded two-stage detector binary=%s attack=%s binary_threshold=%.1f%%",
            self.binary_model_path,
            self.attack_model_path,
            self.binary_threshold,
        )

    @property
    def model_path(self) -> Path:
        return self.binary_model_path

    @property
    def label_encoder(self) -> Any | None:
        return self.binary_label_encoder

    def expected_features(self) -> list[str] | None:
        return self.feature_columns

    def _prepare_input(self, features: Mapping[str, Any]) -> pd.DataFrame:
        feature_frame = _coerce_feature_frame(features)

        if self.feature_columns is None:
            return feature_frame

        missing_features = [
            name for name in self.feature_columns if name not in feature_frame.columns
        ]
        if missing_features:
            raise ValueError(
                "Missing required two-stage model features: "
                + ", ".join(sorted(missing_features))
            )

        return feature_frame.reindex(columns=self.feature_columns)

    @staticmethod
    def _decode(label_encoder: Any | None, raw_prediction: Any) -> str:
        if label_encoder is None:
            return str(raw_prediction)
        decoded = label_encoder.inverse_transform(np.asarray([raw_prediction]))[0]
        return str(decoded)

    @staticmethod
    def _confidence(model: Any, model_input: pd.DataFrame) -> float | None:
        if not hasattr(model, "predict_proba"):
            return None
        probabilities = model.predict_proba(model_input)
        return round(float(np.max(probabilities)) * 100, 2)

    @staticmethod
    def _malicious_confidence(model: Any, model_input: pd.DataFrame) -> float | None:
        """
        Return the probability of the MALICIOUS class specifically.

        FIX: The old np.max(predict_proba) could pick the BENIGN class
        probability when the model was very confident something was benign,
        accidentally passing a high number as the malicious confidence.
        Now we find the malicious class index explicitly.
        """
        if not hasattr(model, "predict_proba"):
            return None
        probabilities = model.predict_proba(model_input)
        classes = getattr(model, "classes_", None)
        if classes is not None:
            for idx, cls in enumerate(classes):
                if str(cls).strip().lower() not in {"benign", "normal", "0", "0.0"}:
                    return round(float(probabilities[0][idx]) * 100, 2)
        # Fallback: assume index 1 is malicious (binary 0/1 encoding)
        if probabilities.shape[1] == 2:
            return round(float(probabilities[0][1]) * 100, 2)
        return round(float(np.max(probabilities)) * 100, 2)

    def predict(self, features: Mapping[str, Any]) -> str:
        return self.predict_details(features).prediction

    def predict_details(self, features: Mapping[str, Any]) -> DetectionResult:
        scaled = _scale_features_for_inference(features)
        model_input = self._prepare_input(scaled)

        binary_raw = self.binary_model.predict(model_input)[0]
        binary_label = self._decode(self.binary_label_encoder, binary_raw)

        # FIX: Use MALICIOUS-class probability for Stage 1 threshold,
        # not the generic max probability.
        binary_malicious_conf = self._malicious_confidence(self.binary_model, model_input)
        binary_confidence = self._confidence(self.binary_model, model_input)

        # FIX: Apply raised binary threshold (65% instead of implicit 50%).
        # If the model's malicious-class probability doesn't cross this bar,
        # treat as benign regardless of what predict() returned.
        is_benign_label = binary_label.strip().lower() in {"benign", "normal"}
        is_below_threshold = (
            binary_malicious_conf is not None
            and binary_malicious_conf < self.binary_threshold
        )

        if is_benign_label or is_below_threshold:
            return DetectionResult(
                prediction="Benign",
                threat="None",
                confidence=binary_confidence,
                binary_label=binary_label,
                binary_confidence=binary_malicious_conf,
            )

        # Stage 2: classify attack type
        attack_raw = self.attack_model.predict(model_input)[0]
        attack_label = self._decode(self.attack_label_encoder, attack_raw)
        attack_confidence = self._confidence(self.attack_model, model_input)

        if attack_confidence is not None and attack_confidence < self.attack_threshold:
            return DetectionResult(
                prediction="Suspicious",
                threat="Suspicious",
                confidence=attack_confidence,
                binary_label=binary_label,
                attack_label=attack_label,
                binary_confidence=binary_malicious_conf,
            )

        return DetectionResult(
            prediction=attack_label,
            threat=attack_label,
            confidence=attack_confidence,
            binary_label=binary_label,
            attack_label=attack_label,
            binary_confidence=binary_malicious_conf,
        )

    def model_info(self) -> dict[str, Any]:
        return {
            "type": "two_stage",
            "binary_model_path": str(self.binary_model_path),
            "attack_model_path": str(self.attack_model_path),
            "binary_label_encoder_path": (
                str(self.binary_label_encoder_path)
                if self.binary_label_encoder_path
                else None
            ),
            "attack_label_encoder_path": (
                str(self.attack_label_encoder_path)
                if self.attack_label_encoder_path
                else None
            ),
            "feature_columns_path": (
                str(self.feature_columns_path) if self.feature_columns_path else None
            ),
            "expected_features": self.expected_features(),
            "attack_threshold": self.attack_threshold,
            "binary_threshold": self.binary_threshold,
        }


def load_detector(
    model_path: str | Path,
    label_encoder_path: str | Path | None = None,
) -> IntrusionDetector:
    return IntrusionDetector(model_path, label_encoder_path)


def configure_default_model(
    model_path: str | Path,
    label_encoder_path: str | Path | None = None,
) -> None:
    global _DEFAULT_DETECTOR
    _DEFAULT_DETECTOR = IntrusionDetector(model_path, label_encoder_path)


def detect(features: Mapping[str, Any]) -> str:
    """
    Predict the traffic class for a single feature payload.

    Call `configure_default_model(...)` during service startup before using
    this helper directly.
    """
    if _DEFAULT_DETECTOR is None:
        raise RuntimeError(
            "No default model configured. "
            "Call configure_default_model(model_path, label_encoder_path) first."
        )
    return _DEFAULT_DETECTOR.predict(features)
