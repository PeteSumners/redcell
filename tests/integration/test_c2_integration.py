"""
Integration tests for C2 server and implant communication.

These tests verify the complete C2 workflow.
"""

import pytest
import threading
import time
from c2.server.crypto import C2Crypto
from c2.server.tasking import TaskingManager, TaskStatus


class TestC2Integration:
    """Integration tests for C2 operations."""

    def test_implant_registration_flow(self):
        """Test complete implant registration workflow."""
        manager = TaskingManager()

        # Simulate implant registration
        implant_id = manager.register_implant(
            hostname='target-host',
            username='compromised_user',
            ip_address='192.168.1.50',
            operating_system='Ubuntu 22.04',
            encryption_key='test_key_abc123',
            metadata={'method': 'sql_injection', 'vulnerability': 'login_bypass'}
        )

        assert implant_id is not None

        # Verify implant is tracked
        implant = manager.get_implant(implant_id)
        assert implant is not None
        assert implant.hostname == 'target-host'
        assert implant.metadata['vulnerability'] == 'login_bypass'

    def test_task_creation_and_execution_flow(self):
        """Test complete task lifecycle."""
        manager = TaskingManager()

        # Register implant
        implant_id = manager.register_implant(
            hostname='target',
            username='user',
            ip_address='192.168.1.1',
            operating_system='Linux'
        )

        # Operator creates task
        task_id = manager.create_task(
            implant_id=implant_id,
            command='shell',
            arguments={'cmd': 'uname -a'}
        )

        # Implant checks in and gets tasks
        pending_tasks = manager.get_pending_tasks(implant_id)
        assert len(pending_tasks) == 1
        assert pending_tasks[0].command == 'shell'

        # Implant executes and returns result
        result = {
            'stdout': 'Linux target 5.15.0-generic',
            'stderr': '',
            'returncode': 0
        }
        manager.complete_task(task_id, result=result)

        # Verify task completion
        task = manager.get_task(task_id)
        assert task.status == TaskStatus.COMPLETED
        assert task.result['stdout'] == 'Linux target 5.15.0-generic'

    def test_encrypted_communication_flow(self):
        """Test encrypted C2 communications."""
        # Create crypto instance for C2 server
        c2_crypto = C2Crypto()
        key_b64 = c2_crypto.get_key_b64()

        # Simulate sharing key with implant
        implant_crypto = C2Crypto.from_b64_key(key_b64)

        # Implant sends encrypted beacon
        beacon_data = {
            'status': 'alive',
            'results': [
                {
                    'task_id': 'task-123',
                    'result': {'stdout': 'whoami output'},
                    'error': None
                }
            ]
        }

        encrypted_beacon = implant_crypto.encrypt_json(beacon_data)

        # C2 server decrypts beacon
        decrypted_beacon = c2_crypto.decrypt_json(encrypted_beacon)
        assert decrypted_beacon['status'] == 'alive'
        assert len(decrypted_beacon['results']) == 1

        # C2 server sends encrypted response
        response_data = {
            'tasks': [
                {
                    'task_id': 'task-456',
                    'command': 'sysinfo',
                    'arguments': {}
                }
            ]
        }

        encrypted_response = c2_crypto.encrypt_json(response_data)

        # Implant decrypts response
        decrypted_response = implant_crypto.decrypt_json(encrypted_response)
        assert len(decrypted_response['tasks']) == 1
        assert decrypted_response['tasks'][0]['command'] == 'sysinfo'

    def test_multiple_implants_concurrent_operations(self):
        """Test managing multiple implants concurrently."""
        manager = TaskingManager()

        # Register multiple implants
        implant1 = manager.register_implant('host1', 'user1', '192.168.1.1', 'Linux')
        implant2 = manager.register_implant('host2', 'user2', '192.168.1.2', 'Windows')
        implant3 = manager.register_implant('host3', 'user3', '192.168.1.3', 'Linux')

        # Create tasks for each implant
        task1 = manager.create_task(implant1, 'shell', {'cmd': 'ls'})
        task2 = manager.create_task(implant2, 'shell', {'cmd': 'dir'})
        task3 = manager.create_task(implant3, 'sysinfo', {})

        # Each implant gets only its tasks
        tasks1 = manager.get_pending_tasks(implant1)
        tasks2 = manager.get_pending_tasks(implant2)
        tasks3 = manager.get_pending_tasks(implant3)

        assert len(tasks1) == 1
        assert len(tasks2) == 1
        assert len(tasks3) == 1

        assert tasks1[0].arguments['cmd'] == 'ls'
        assert tasks2[0].arguments['cmd'] == 'dir'
        assert tasks3[0].command == 'sysinfo'

    def test_implant_timeout_detection(self):
        """Test detection of inactive implants."""
        manager = TaskingManager()

        implant_id = manager.register_implant(
            hostname='test-host',
            username='user',
            ip_address='192.168.1.1',
            operating_system='Linux'
        )

        # Immediately after registration, should be active
        active = manager.get_active_implants(timeout_seconds=5)
        assert len(active) == 1

        # Wait longer than timeout
        time.sleep(0.2)

        # With very short timeout, should be inactive
        active = manager.get_active_implants(timeout_seconds=0)
        assert len(active) == 0

        # Update check-in
        manager.update_implant_checkin(implant_id)

        # Should be active again
        active = manager.get_active_implants(timeout_seconds=5)
        assert len(active) == 1

    def test_task_queue_ordering(self):
        """Test that tasks are delivered in order."""
        manager = TaskingManager()

        implant_id = manager.register_implant('host', 'user', '192.168.1.1', 'Linux')

        # Create multiple tasks in sequence
        task_ids = []
        for i in range(5):
            task_id = manager.create_task(implant_id, f'command_{i}', {'index': i})
            task_ids.append(task_id)

        # Get pending tasks
        pending = manager.get_pending_tasks(implant_id)
        assert len(pending) == 5

        # Verify order
        for i, task in enumerate(pending):
            assert task.command == f'command_{i}'
            assert task.arguments['index'] == i

    def test_error_handling_in_task_execution(self):
        """Test error handling during task execution."""
        manager = TaskingManager()

        implant_id = manager.register_implant('host', 'user', '192.168.1.1', 'Linux')
        task_id = manager.create_task(implant_id, 'shell', {'cmd': 'invalid_command'})

        # Get task
        pending = manager.get_pending_tasks(implant_id)
        assert len(pending) == 1

        # Simulate execution failure
        manager.complete_task(
            task_id,
            result=None,
            error='Command not found: invalid_command'
        )

        # Verify error is recorded
        task = manager.get_task(task_id)
        assert task.status == TaskStatus.FAILED
        assert 'Command not found' in task.error

    @pytest.mark.slow
    def test_concurrent_tasking_operations(self):
        """Test thread safety with concurrent operations."""
        manager = TaskingManager()
        implant_id = manager.register_implant('host', 'user', '192.168.1.1', 'Linux')

        def operator_thread():
            """Simulate operator creating tasks."""
            for i in range(10):
                manager.create_task(implant_id, f'cmd_{i}', {})
                time.sleep(0.01)

        def implant_thread():
            """Simulate implant checking in."""
            for i in range(5):
                pending = manager.get_pending_tasks(implant_id)
                for task in pending:
                    manager.complete_task(task.task_id, result={'success': True})
                time.sleep(0.02)

        # Run threads concurrently
        threads = [
            threading.Thread(target=operator_thread),
            threading.Thread(target=implant_thread)
        ]

        for t in threads:
            t.start()

        for t in threads:
            t.join()

        # Verify all tasks were created and processed
        all_tasks = manager.get_implant_tasks(implant_id)
        assert len(all_tasks) == 10

        # At least some tasks should be completed
        completed = [t for t in all_tasks if t.status == TaskStatus.COMPLETED]
        assert len(completed) > 0
