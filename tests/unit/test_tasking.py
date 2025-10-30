"""
Unit tests for C2 tasking module.
"""

import pytest
import time
from datetime import datetime
from c2.server.tasking import TaskingManager, Task, Implant, TaskStatus, ImplantStatus


class TestTaskingManager:
    """Test TaskingManager functionality."""

    def test_register_implant(self):
        """Test implant registration."""
        manager = TaskingManager()

        implant_id = manager.register_implant(
            hostname='test-host',
            username='testuser',
            ip_address='192.168.1.100',
            operating_system='Linux 5.15.0',
            encryption_key='test_key_123'
        )

        assert implant_id is not None
        assert implant_id in manager.implants
        assert implant_id in manager.task_queues

        implant = manager.get_implant(implant_id)
        assert implant.hostname == 'test-host'
        assert implant.username == 'testuser'
        assert implant.encryption_key == 'test_key_123'

    def test_update_implant_checkin(self):
        """Test updating implant check-in time."""
        manager = TaskingManager()
        implant_id = manager.register_implant(
            hostname='test-host',
            username='testuser',
            ip_address='192.168.1.100',
            operating_system='Linux'
        )

        implant = manager.get_implant(implant_id)
        original_last_seen = implant.last_seen

        time.sleep(0.1)  # Small delay

        success = manager.update_implant_checkin(implant_id)
        assert success

        implant = manager.get_implant(implant_id)
        assert implant.last_seen != original_last_seen

    def test_update_nonexistent_implant(self):
        """Test updating non-existent implant returns False."""
        manager = TaskingManager()
        success = manager.update_implant_checkin('nonexistent_id')
        assert not success

    def test_create_task(self):
        """Test task creation."""
        manager = TaskingManager()
        implant_id = manager.register_implant(
            hostname='test-host',
            username='testuser',
            ip_address='192.168.1.100',
            operating_system='Linux'
        )

        task_id = manager.create_task(
            implant_id=implant_id,
            command='shell',
            arguments={'cmd': 'whoami'}
        )

        assert task_id is not None
        task = manager.get_task(task_id)
        assert task.command == 'shell'
        assert task.arguments == {'cmd': 'whoami'}
        assert task.status == TaskStatus.PENDING

    def test_create_task_for_nonexistent_implant(self):
        """Test task creation for non-existent implant returns None."""
        manager = TaskingManager()
        task_id = manager.create_task(
            implant_id='nonexistent',
            command='shell',
            arguments={}
        )
        assert task_id is None

    def test_get_pending_tasks(self):
        """Test retrieving pending tasks."""
        manager = TaskingManager()
        implant_id = manager.register_implant(
            hostname='test-host',
            username='testuser',
            ip_address='192.168.1.100',
            operating_system='Linux'
        )

        # Create multiple tasks
        task_id1 = manager.create_task(implant_id, 'shell', {'cmd': 'ls'})
        task_id2 = manager.create_task(implant_id, 'sysinfo', {})

        # Get pending tasks
        pending = manager.get_pending_tasks(implant_id)
        assert len(pending) == 2

        # Tasks should now be marked as SENT
        task1 = manager.get_task(task_id1)
        task2 = manager.get_task(task_id2)
        assert task1.status == TaskStatus.SENT
        assert task2.status == TaskStatus.SENT

        # Getting pending tasks again should return empty list
        pending = manager.get_pending_tasks(implant_id)
        assert len(pending) == 0

    def test_complete_task(self):
        """Test task completion."""
        manager = TaskingManager()
        implant_id = manager.register_implant(
            hostname='test-host',
            username='testuser',
            ip_address='192.168.1.100',
            operating_system='Linux'
        )

        task_id = manager.create_task(implant_id, 'shell', {'cmd': 'whoami'})

        # Complete task with result
        result = {'stdout': 'testuser', 'stderr': '', 'returncode': 0}
        success = manager.complete_task(task_id, result=result)
        assert success

        task = manager.get_task(task_id)
        assert task.status == TaskStatus.COMPLETED
        assert task.result == result
        assert task.completed_at is not None

    def test_complete_task_with_error(self):
        """Test task completion with error."""
        manager = TaskingManager()
        implant_id = manager.register_implant(
            hostname='test-host',
            username='testuser',
            ip_address='192.168.1.100',
            operating_system='Linux'
        )

        task_id = manager.create_task(implant_id, 'shell', {'cmd': 'invalid'})

        # Complete task with error
        success = manager.complete_task(task_id, error='Command not found')
        assert success

        task = manager.get_task(task_id)
        assert task.status == TaskStatus.FAILED
        assert task.error == 'Command not found'

    def test_get_all_implants(self):
        """Test getting all implants."""
        manager = TaskingManager()

        # Register multiple implants
        id1 = manager.register_implant('host1', 'user1', '192.168.1.1', 'Linux')
        id2 = manager.register_implant('host2', 'user2', '192.168.1.2', 'Windows')

        all_implants = manager.get_all_implants()
        assert len(all_implants) == 2

        hostnames = [i.hostname for i in all_implants]
        assert 'host1' in hostnames
        assert 'host2' in hostnames

    def test_get_active_implants(self):
        """Test getting active implants based on timeout."""
        manager = TaskingManager()

        # Register implant
        implant_id = manager.register_implant(
            hostname='test-host',
            username='testuser',
            ip_address='192.168.1.100',
            operating_system='Linux'
        )

        # Should be active immediately
        active = manager.get_active_implants(timeout_seconds=300)
        assert len(active) == 1

        # With very short timeout, might not be active
        active = manager.get_active_implants(timeout_seconds=0)
        assert len(active) == 0

    def test_get_implant_tasks(self):
        """Test getting all tasks for an implant."""
        manager = TaskingManager()
        implant_id = manager.register_implant(
            hostname='test-host',
            username='testuser',
            ip_address='192.168.1.100',
            operating_system='Linux'
        )

        # Create multiple tasks
        manager.create_task(implant_id, 'shell', {'cmd': 'ls'})
        manager.create_task(implant_id, 'sysinfo', {})
        manager.create_task(implant_id, 'pwd', {})

        tasks = manager.get_implant_tasks(implant_id)
        assert len(tasks) == 3

    def test_remove_implant(self):
        """Test removing an implant."""
        manager = TaskingManager()
        implant_id = manager.register_implant(
            hostname='test-host',
            username='testuser',
            ip_address='192.168.1.100',
            operating_system='Linux'
        )

        # Create some tasks
        manager.create_task(implant_id, 'shell', {})

        # Remove implant
        success = manager.remove_implant(implant_id)
        assert success

        # Implant and task queue should be gone
        assert manager.get_implant(implant_id) is None
        assert implant_id not in manager.task_queues

        # Removing again should return False
        success = manager.remove_implant(implant_id)
        assert not success

    def test_thread_safety(self):
        """Test basic thread safety."""
        import threading

        manager = TaskingManager()
        implant_id = manager.register_implant(
            hostname='test-host',
            username='testuser',
            ip_address='192.168.1.100',
            operating_system='Linux'
        )

        def create_tasks():
            for i in range(10):
                manager.create_task(implant_id, f'command_{i}', {})

        # Create tasks from multiple threads
        threads = [threading.Thread(target=create_tasks) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Should have created 50 tasks total
        tasks = manager.get_implant_tasks(implant_id)
        assert len(tasks) == 50


class TestTask:
    """Test Task dataclass."""

    def test_task_creation(self):
        """Test task creation."""
        task = Task(
            task_id='test-123',
            implant_id='implant-456',
            command='shell',
            arguments={'cmd': 'whoami'}
        )

        assert task.task_id == 'test-123'
        assert task.implant_id == 'implant-456'
        assert task.command == 'shell'
        assert task.status == TaskStatus.PENDING

    def test_task_to_dict(self):
        """Test task serialization to dictionary."""
        task = Task(
            task_id='test-123',
            implant_id='implant-456',
            command='shell',
            arguments={'cmd': 'whoami'}
        )

        task_dict = task.to_dict()
        assert task_dict['task_id'] == 'test-123'
        assert task_dict['command'] == 'shell'
        assert task_dict['status'] == 'pending'


class TestImplant:
    """Test Implant dataclass."""

    def test_implant_creation(self):
        """Test implant creation."""
        implant = Implant(
            implant_id='test-123',
            hostname='testhost',
            username='testuser',
            ip_address='192.168.1.100',
            operating_system='Linux'
        )

        assert implant.implant_id == 'test-123'
        assert implant.hostname == 'testhost'
        assert implant.status == ImplantStatus.ACTIVE

    def test_implant_update_last_seen(self):
        """Test updating last seen timestamp."""
        implant = Implant(
            implant_id='test-123',
            hostname='testhost',
            username='testuser',
            ip_address='192.168.1.100',
            operating_system='Linux'
        )

        original_last_seen = implant.last_seen
        time.sleep(0.1)
        implant.update_last_seen()

        assert implant.last_seen != original_last_seen

    def test_implant_to_dict(self):
        """Test implant serialization to dictionary."""
        implant = Implant(
            implant_id='test-123',
            hostname='testhost',
            username='testuser',
            ip_address='192.168.1.100',
            operating_system='Linux'
        )

        implant_dict = implant.to_dict()
        assert implant_dict['implant_id'] == 'test-123'
        assert implant_dict['hostname'] == 'testhost'
        assert implant_dict['status'] == 'active'
