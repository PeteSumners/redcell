"""
C2 Tasking Module

Manages task queuing, implant tracking, and command execution for C2 operations.
"""

import uuid
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field, asdict
from enum import Enum


class TaskStatus(Enum):
    """Task execution status."""
    PENDING = "pending"
    SENT = "sent"
    COMPLETED = "completed"
    FAILED = "failed"


class ImplantStatus(Enum):
    """Implant status."""
    ACTIVE = "active"
    INACTIVE = "inactive"
    COMPROMISED = "compromised"


@dataclass
class Task:
    """Represents a task for an implant."""
    task_id: str
    implant_id: str
    command: str
    arguments: Dict[str, Any] = field(default_factory=dict)
    status: TaskStatus = TaskStatus.PENDING
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    sent_at: Optional[str] = None
    completed_at: Optional[str] = None
    result: Optional[Any] = None
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert task to dictionary."""
        data = asdict(self)
        data['status'] = self.status.value
        return data


@dataclass
class Implant:
    """Represents an implant/beacon."""
    implant_id: str
    hostname: str
    username: str
    ip_address: str
    operating_system: str
    status: ImplantStatus = ImplantStatus.ACTIVE
    first_seen: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    last_seen: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    encryption_key: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def update_last_seen(self):
        """Update last seen timestamp."""
        self.last_seen = datetime.utcnow().isoformat()

    def to_dict(self) -> Dict[str, Any]:
        """Convert implant to dictionary."""
        data = asdict(self)
        data['status'] = self.status.value
        return data


class TaskingManager:
    """
    Manages tasks and implants for C2 operations.

    Thread-safe implementation for handling multiple concurrent implants.
    """

    def __init__(self):
        """Initialize the tasking manager."""
        self.implants: Dict[str, Implant] = {}
        self.tasks: Dict[str, Task] = {}
        self.task_queues: Dict[str, List[str]] = {}  # implant_id -> list of task_ids
        self.lock = threading.Lock()

    def register_implant(
        self,
        hostname: str,
        username: str,
        ip_address: str,
        operating_system: str,
        encryption_key: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Register a new implant.

        Args:
            hostname: Target hostname
            username: Current user
            ip_address: IP address
            operating_system: OS information
            encryption_key: Encryption key for this implant
            metadata: Additional metadata

        Returns:
            Implant ID
        """
        with self.lock:
            implant_id = str(uuid.uuid4())
            implant = Implant(
                implant_id=implant_id,
                hostname=hostname,
                username=username,
                ip_address=ip_address,
                operating_system=operating_system,
                encryption_key=encryption_key,
                metadata=metadata or {}
            )
            self.implants[implant_id] = implant
            self.task_queues[implant_id] = []
            return implant_id

    def update_implant_checkin(self, implant_id: str) -> bool:
        """
        Update implant check-in timestamp.

        Args:
            implant_id: Implant identifier

        Returns:
            True if successful, False if implant not found
        """
        with self.lock:
            if implant_id in self.implants:
                self.implants[implant_id].update_last_seen()
                return True
            return False

    def create_task(
        self,
        implant_id: str,
        command: str,
        arguments: Optional[Dict[str, Any]] = None
    ) -> Optional[str]:
        """
        Create a new task for an implant.

        Args:
            implant_id: Target implant ID
            command: Command to execute
            arguments: Command arguments

        Returns:
            Task ID if successful, None if implant not found
        """
        with self.lock:
            if implant_id not in self.implants:
                return None

            task_id = str(uuid.uuid4())
            task = Task(
                task_id=task_id,
                implant_id=implant_id,
                command=command,
                arguments=arguments or {}
            )
            self.tasks[task_id] = task
            self.task_queues[implant_id].append(task_id)
            return task_id

    def get_pending_tasks(self, implant_id: str) -> List[Task]:
        """
        Get all pending tasks for an implant.

        Args:
            implant_id: Implant identifier

        Returns:
            List of pending tasks
        """
        with self.lock:
            if implant_id not in self.task_queues:
                return []

            pending_tasks = []
            for task_id in self.task_queues[implant_id]:
                task = self.tasks.get(task_id)
                if task and task.status == TaskStatus.PENDING:
                    task.status = TaskStatus.SENT
                    task.sent_at = datetime.utcnow().isoformat()
                    pending_tasks.append(task)

            return pending_tasks

    def complete_task(
        self,
        task_id: str,
        result: Any = None,
        error: Optional[str] = None
    ) -> bool:
        """
        Mark a task as completed.

        Args:
            task_id: Task identifier
            result: Task result
            error: Error message if task failed

        Returns:
            True if successful, False if task not found
        """
        with self.lock:
            if task_id not in self.tasks:
                return False

            task = self.tasks[task_id]
            task.status = TaskStatus.COMPLETED if error is None else TaskStatus.FAILED
            task.completed_at = datetime.utcnow().isoformat()
            task.result = result
            task.error = error
            return True

    def get_task(self, task_id: str) -> Optional[Task]:
        """
        Get a task by ID.

        Args:
            task_id: Task identifier

        Returns:
            Task object or None
        """
        return self.tasks.get(task_id)

    def get_implant(self, implant_id: str) -> Optional[Implant]:
        """
        Get an implant by ID.

        Args:
            implant_id: Implant identifier

        Returns:
            Implant object or None
        """
        return self.implants.get(implant_id)

    def get_all_implants(self) -> List[Implant]:
        """
        Get all registered implants.

        Returns:
            List of all implants
        """
        with self.lock:
            return list(self.implants.values())

    def get_active_implants(self, timeout_seconds: int = 300) -> List[Implant]:
        """
        Get implants that have checked in recently.

        Args:
            timeout_seconds: Seconds before an implant is considered inactive

        Returns:
            List of active implants
        """
        with self.lock:
            cutoff_time = datetime.utcnow() - timedelta(seconds=timeout_seconds)
            active = []

            for implant in self.implants.values():
                last_seen = datetime.fromisoformat(implant.last_seen)
                if last_seen > cutoff_time:
                    active.append(implant)

            return active

    def get_implant_tasks(self, implant_id: str) -> List[Task]:
        """
        Get all tasks for an implant.

        Args:
            implant_id: Implant identifier

        Returns:
            List of tasks
        """
        with self.lock:
            if implant_id not in self.task_queues:
                return []

            return [self.tasks[task_id] for task_id in self.task_queues[implant_id]
                    if task_id in self.tasks]

    def remove_implant(self, implant_id: str) -> bool:
        """
        Remove an implant from tracking.

        Args:
            implant_id: Implant identifier

        Returns:
            True if successful, False if not found
        """
        with self.lock:
            if implant_id in self.implants:
                del self.implants[implant_id]
                if implant_id in self.task_queues:
                    del self.task_queues[implant_id]
                return True
            return False
