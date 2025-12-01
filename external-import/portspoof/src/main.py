"""PortSpoofPro OpenCTI Connector - RabbitMQ consumer for STIX 2.1 synchronization."""

import json
import logging
import os
import sys
import time
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

import pika
from dotenv import load_dotenv
from pydantic import BaseModel, ConfigDict, Field
from synchronizer import StixSynchronizer, build_config_from_env

load_dotenv()

log_level = os.getenv("LOG_LEVEL", "INFO")
log_format = "%(asctime)s - %(levelname)s - %(message)s"
log_handlers = [logging.StreamHandler()]

log_file = os.getenv("PS_LOG_FILE")
if log_file:
    try:
        log_handlers.append(logging.FileHandler(log_file, mode="a"))
        print(f"[INFO] File logging enabled: {log_file}", file=sys.stderr)
    except Exception as e:
        print(
            f"[WARN] Failed to open log file '{log_file}': {e}. File logging disabled.",
            file=sys.stderr,
        )

logging.basicConfig(level=log_level, format=log_format, handlers=log_handlers)

RABBITMQ_URL = os.getenv("RABBITMQ_URL", "amqp://guest:guest@rabbitmq:5672/")
FULL_STATE_EXCHANGE = "portspoof-full-state-updates"
QUEUE_NAME = os.getenv("RABBITMQ_QUEUE_NAME", "opencti-connector-queue")
DLQ_EXCHANGE = "opencti-connector-dlq"
DLQ_QUEUE = "opencti-connector-dlq-queue"
PREFETCH_COUNT = int(os.getenv("PREFETCH_COUNT", "10"))
MAX_RETRIES = int(os.getenv("MAX_RETRIES", "3"))

OPENCTI_URL = os.getenv("OPENCTI_URL")
OPENCTI_TOKEN = os.getenv("OPENCTI_TOKEN")

DEBUG_FULL_DUMPS = os.getenv("PS_DEBUG_FULL_DUMPS", "0") == "1"


class Detection(BaseModel):
    """Individual detection record"""

    name: str
    description: str
    confidence: float = Field(ge=0.0, le=1.0)
    contribution: float = Field(ge=0.0)
    mitre_ttp: Optional[str] = None
    attributes: Optional[Dict[str, Any]] = None


class ProbedPortsDetail(BaseModel):
    """Probed ports categorized by scan technique"""

    syn_scan: List[int] = Field(default_factory=list)
    fin_scan: List[int] = Field(default_factory=list)
    null_scan: List[int] = Field(default_factory=list)
    xmas_scan: List[int] = Field(default_factory=list)
    ack_scan: List[int] = Field(default_factory=list)
    udp_port_scan: List[int] = Field(default_factory=list)
    full_connect_scan: List[int] = Field(default_factory=list)


class FullSessionState(BaseModel):
    """Full session state from aggregator"""

    session_id: str = Field(min_length=1)
    source_ip: str = Field(min_length=7)
    session_start_time: str
    last_activity_time: str
    last_event_type: str = Field(
        pattern=r"^(scanner_detected|scanner_update|scanner_session_ended)$"
    )
    risk_score: float = Field(ge=0.0)
    alert_level: int = Field(ge=0, le=3)
    total_ports_seen: int = Field(ge=0)
    total_hosts_probed: int = Field(ge=0)
    total_attacker_time_wasted_secs: Optional[float] = Field(default=None)

    session_end_time: Optional[str] = None
    total_session_duration_secs: Optional[float] = Field(default=None, ge=0.0)
    sensor_id: Optional[str] = None
    sensor_hostname: Optional[str] = None
    full_probed_ports: Optional[ProbedPortsDetail] = None
    full_probed_hosts: Optional[List[str]] = None
    full_detection_chain: List[Detection] = Field(default_factory=list)
    full_mitre_ttp_chain: List[str] = Field(default_factory=list)
    service_metrics: Optional[Dict[str, Any]] = None
    connection_profile: Optional[Dict[str, Any]] = None

    model_config = ConfigDict(extra="allow")


class ErrorType(Enum):
    """Error classification for retry strategy"""

    PERMANENT = "permanent"
    TRANSIENT = "transient"


def classify_error(exception: Exception) -> ErrorType:
    """Classify exception as permanent or transient for retry strategy."""
    if isinstance(exception, (json.JSONDecodeError, ValueError, TypeError, KeyError)):
        return ErrorType.PERMANENT
    else:
        return ErrorType.TRANSIENT


def datetime_serializer(obj):
    """JSON serializer for datetime objects"""
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Type {type(obj)} not serializable")


def safe_dump(data, max_length=1000):
    """Serialize data to JSON with optional truncation for logging."""
    try:
        dumped = json.dumps(data, default=datetime_serializer)
        if DEBUG_FULL_DUMPS:
            return dumped
        if len(dumped) > max_length:
            return dumped[:max_length] + f"... (truncated, {len(dumped)} total chars)"
        return dumped
    except Exception as e:
        return f"<Failed to serialize: {e}>"


def decode_and_validate(body: bytes) -> FullSessionState:
    """Decode JSON and validate session state structure."""
    state_dict = json.loads(body)
    validated_state = FullSessionState(**state_dict)
    return validated_state


def process_session_state(synchronizer: StixSynchronizer, state: FullSessionState):
    """Process session state through OpenCTI synchronizer."""
    state_dict = state.model_dump(mode="python", exclude_none=False)
    synchronizer.sync_session(state_dict)


class OpenCTIConsumer:
    """RabbitMQ consumer with automatic reconnection and retry logic."""

    def __init__(self, synchronizer: StixSynchronizer):
        self.synchronizer = synchronizer
        self.connection = None
        self.channel = None

        self.stats = {
            "total_messages_processed": 0,
            "scanner_detected_count": 0,
            "scanner_update_count": 0,
            "scanner_session_ended_count": 0,
            "sync_errors": 0,
            "validation_errors": 0,
        }
        self.message_counter = 0
        self.last_stats_log = time.time()

    def log_statistics(self):
        """Log connector statistics."""
        sync_stats = self.synchronizer.stats

        logging.info("=" * 80)
        logging.info("OpenCTI Connector Statistics")
        logging.info("=" * 80)

        logging.info("Message Processing:")
        logging.info(
            f"  Total messages processed:  {self.stats['total_messages_processed']:,}"
        )
        logging.info(
            f"  - Scanner detected:        {self.stats['scanner_detected_count']:,}"
        )
        logging.info(
            f"  - Scanner updates:         {self.stats['scanner_update_count']:,}"
        )
        logging.info(
            f"  - Sessions ended:          {self.stats['scanner_session_ended_count']:,}"
        )
        logging.info("")

        logging.info("STIX Objects Created/Updated:")
        logging.info(
            f"  Threat Actors created:     {sync_stats['threat_actors_created']:,}"
        )
        logging.info(
            f"  Threat Actors updated:     {sync_stats['threat_actors_updated']:,}"
        )
        logging.info(
            f"  Infrastructures created:   {sync_stats['infrastructures_created']:,}"
        )
        logging.info(
            f"  Observed Data created:     {sync_stats['observed_data_created']:,}"
        )
        logging.info(f"  Tools created:             {sync_stats['tools_created']:,}")
        logging.info(
            f"  Attack Patterns created:   {sync_stats['attack_patterns_created']:,}"
        )
        logging.info(f"  Reports created:           {sync_stats['reports_created']:,}")
        logging.info("")

        logging.info("STIX Relationships & Sightings:")
        logging.info(
            f"  Sightings created:         {sync_stats['sightings_created']:,}"
        )
        logging.info(
            f"  Relationships created:     {sync_stats['relationships_created']:,}"
        )
        logging.info("")

        logging.info("Sessions:")
        logging.info(f"  Sessions synced:           {sync_stats['sessions_synced']:,}")
        logging.info("")

        logging.info("Errors:")
        logging.info(
            f"  Validation errors:         {self.stats['validation_errors']:,}"
        )
        logging.info(f"  Sync errors:               {self.stats['sync_errors']:,}")
        total_errors = self.stats["validation_errors"] + self.stats["sync_errors"]
        success_rate = (
            (
                (self.stats["total_messages_processed"] - total_errors)
                / self.stats["total_messages_processed"]
                * 100
            )
            if self.stats["total_messages_processed"] > 0
            else 0
        )
        logging.info(f"  Success rate:              {success_rate:.2f}%")

        logging.info("=" * 80)

    def setup_connection(self):
        """Setup RabbitMQ connection, channels, and exchanges/queues."""
        logging.info(f"Connecting to RabbitMQ at {RABBITMQ_URL}...")
        self.connection = pika.BlockingConnection(pika.URLParameters(RABBITMQ_URL))
        self.channel = self.connection.channel()

        self.channel.exchange_declare(
            exchange=FULL_STATE_EXCHANGE, exchange_type="fanout", durable=True
        )

        self.channel.exchange_declare(
            exchange=DLQ_EXCHANGE, exchange_type="direct", durable=True
        )
        self.channel.queue_declare(
            queue=DLQ_QUEUE,
            durable=True,
            arguments={
                "x-max-length": 10000,  # 10K failed messages max (~22 MB for full-state msgs)
                "x-overflow": "drop-head",  # Drop oldest failures (keep recent errors for debugging)
            },
        )
        self.channel.queue_bind(
            exchange=DLQ_EXCHANGE, queue=DLQ_QUEUE, routing_key="failed"
        )

        self.channel.queue_declare(
            queue=QUEUE_NAME,
            durable=True,
            auto_delete=False,  # Queue persists when consumer offline
            arguments={
                "x-dead-letter-exchange": DLQ_EXCHANGE,
                "x-dead-letter-routing-key": "failed",
                "x-queue-mode": "lazy",
                "x-max-length": 100000,
                "x-overflow": "drop-head",
                "x-message-ttl": 3600000,
            },
        )
        self.channel.queue_bind(exchange=FULL_STATE_EXCHANGE, queue=QUEUE_NAME)

        self.channel.basic_qos(prefetch_count=PREFETCH_COUNT)

        logging.info(f"Ready. Waiting for full state updates in queue '{QUEUE_NAME}'.")

    def on_message(self, ch, method, properties, body):
        """Message callback with error handling and retry logic."""
        delivery_count = 0
        if properties.headers and "x-death" in properties.headers:
            x_death = properties.headers["x-death"]
            if isinstance(x_death, list) and len(x_death) > 0:
                delivery_count = x_death[0].get("count", 0)

        try:
            state = decode_and_validate(body)

            event_type = state.last_event_type
            if event_type == "scanner_detected":
                self.stats["scanner_detected_count"] += 1
            elif event_type == "scanner_update":
                self.stats["scanner_update_count"] += 1
            elif event_type == "scanner_session_ended":
                self.stats["scanner_session_ended_count"] += 1

            process_session_state(self.synchronizer, state)

            try:
                ch.basic_ack(delivery_tag=method.delivery_tag)
            except pika.exceptions.AMQPError as ack_error:
                logging.warning(
                    f"Failed to ack message (channel likely closed): {ack_error}"
                )
                # Channel closed - will reconnect in outer loop

            self.stats["total_messages_processed"] += 1
            self.message_counter += 1

            current_time = time.time()
            if (
                self.message_counter >= 50
                or (current_time - self.last_stats_log) >= 300
            ):
                self.log_statistics()
                self.message_counter = 0
                self.last_stats_log = current_time

        except Exception as e:
            error_type = classify_error(e)

            if error_type == ErrorType.PERMANENT:
                logging.error(
                    f"Permanent error processing message: {type(e).__name__}: {e}"
                )
                try:
                    body_str = (
                        body.decode("utf-8") if isinstance(body, bytes) else str(body)
                    )
                    if DEBUG_FULL_DUMPS:
                        logging.error(f"Problematic message body: {body_str}")
                    else:
                        logging.error(
                            f"Problematic message body: {body_str[:1000]}... (truncated)"
                        )
                except:
                    pass

                try:
                    ch.basic_nack(delivery_tag=method.delivery_tag, requeue=False)
                except pika.exceptions.AMQPError as nack_error:
                    logging.warning(
                        f"Failed to nack message (channel likely closed): {nack_error}"
                    )
                    # Channel closed - will reconnect in outer loop

                self.stats["validation_errors"] += 1

            elif error_type == ErrorType.TRANSIENT:
                should_requeue = delivery_count < MAX_RETRIES

                if should_requeue:
                    logging.warning(
                        f"Transient error processing message (attempt {delivery_count + 1}/{MAX_RETRIES}): {type(e).__name__}: {e}"
                    )
                    try:
                        ch.basic_nack(delivery_tag=method.delivery_tag, requeue=True)
                    except pika.exceptions.AMQPError as nack_error:
                        logging.warning(
                            f"Failed to nack message for retry (channel likely closed): {nack_error}"
                        )
                        # Channel closed - will reconnect in outer loop
                else:
                    logging.error(
                        f"Message exceeded retry limit ({MAX_RETRIES} attempts), sending to DLQ: {type(e).__name__}: {e}"
                    )
                    try:
                        ch.basic_nack(delivery_tag=method.delivery_tag, requeue=False)
                    except pika.exceptions.AMQPError as nack_error:
                        logging.warning(
                            f"Failed to nack message to DLQ (channel likely closed): {nack_error}"
                        )
                        # Channel closed - will reconnect in outer loop

                self.stats["sync_errors"] += 1

    def start_consuming(self):
        """Start consuming messages with automatic reconnection."""
        retry_delay = 10
        max_retry_delay = 300

        while True:
            try:
                self.setup_connection()

                retry_delay = 10

                self.channel.basic_consume(
                    queue=QUEUE_NAME, on_message_callback=self.on_message
                )

                logging.info(
                    "Successfully connected to RabbitMQ, consuming messages..."
                )
                self.channel.start_consuming()

            except pika.exceptions.AMQPConnectionError as e:
                logging.error(
                    f"RabbitMQ connection failed: {type(e).__name__}: {e}. Retrying in {retry_delay}s..."
                )
                time.sleep(retry_delay)
                retry_delay = min(retry_delay * 2, max_retry_delay)

            except pika.exceptions.AMQPError as e:
                logging.error(
                    f"RabbitMQ error: {type(e).__name__}: {e}. Retrying in {retry_delay}s...",
                    exc_info=True,
                )
                time.sleep(retry_delay)
                retry_delay = min(retry_delay * 2, max_retry_delay)

            except KeyboardInterrupt:
                logging.info("Received shutdown signal, stopping gracefully...")
                if self.connection and not self.connection.is_closed:
                    self.connection.close()
                break

            except Exception as e:
                logging.error(
                    f"Unexpected error in consumer loop: {type(e).__name__}: {e}",
                    exc_info=True,
                )
                time.sleep(retry_delay)
                retry_delay = min(retry_delay * 2, max_retry_delay)

            finally:
                time.sleep(10)


def main():
    logging.info("=" * 80)
    logging.info("OpenCTI Connector Starting")
    logging.info("=" * 80)
    logging.info("Configuration:")
    logging.info(f"  Log Level:          {os.getenv('LOG_LEVEL', 'INFO')}")
    logging.info(f"  Log File:           {os.getenv('PS_LOG_FILE', 'disabled')}")
    logging.info(
        f"  Debug Full Dumps:   {'ENABLED (full telemetry)' if DEBUG_FULL_DUMPS else 'disabled (truncated)'}"
    )
    logging.info(f"  OpenCTI URL:        {OPENCTI_URL}")
    logging.info(f"  Prefetch Count:     {PREFETCH_COUNT} messages")
    logging.info(f"  Max Retries:        {MAX_RETRIES} attempts")
    logging.info("=" * 80)

    if not OPENCTI_URL or not OPENCTI_TOKEN:
        logging.error(
            "FATAL: OPENCTI_URL and OPENCTI_TOKEN must be set in environment."
        )
        sys.exit(1)

    try:
        config = build_config_from_env()
        logging.info(f"Built connector config: ID={config['connector']['id'][:36]}...")
        logging.info(f"  Connector type: {config['connector']['type']}")
        logging.info(f"  Connector name: {config['connector']['name']}")
        logging.info(f"  Connector scope: {config['connector']['scope']}")

        synchronizer = StixSynchronizer(config)
        logging.info("Successfully initialized OpenCTI connector")
        logging.info(f"Connector registered: {synchronizer.helper.connect_id}")
        logging.info(f"Connector name: {synchronizer.helper.connect_name}")

    except Exception as e:
        logging.error(
            f"FATAL: Failed to initialize OpenCTI Connector: {type(e).__name__}: {e}"
        )
        sys.exit(1)

    consumer = OpenCTIConsumer(synchronizer)
    consumer.start_consuming()


if __name__ == "__main__":
    main()
