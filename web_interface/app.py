from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, emit
import sys
import os
import asyncio
import json
from threading import Thread, Event
from queue import Queue
from datetime import datetime
from typing import List

# Add parent directory to path so we can import the main script
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from main import run_pentest_team

def load_config():
    """Load configuration from config.txt file."""
    config = {}
    config_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'config.txt')
    with open(config_path, 'r') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                if '=' in line:
                    key, value = line.split('=', 1)
                    key = key.strip()
                    value = value.strip()
                    
                    # Handle different value types
                    if value.startswith('[') and value.endswith(']'):
                        # Parse list
                        value = json.loads(value)
                    elif value.startswith('{') and value.endswith('}'):
                        # Parse dictionary
                        value = json.loads(value)
                    elif value.lower() in ('true', 'false'):
                        # Parse boolean
                        value = value.lower() == 'true'
                    elif value.isdigit():
                        # Parse integer
                        value = int(value)
                    elif value.startswith('"') and value.endswith('"'):
                        # Parse string with quotes
                        value = value[1:-1]
                    
                    config[key] = value
    return config

# Load configuration
config = load_config()

app = Flask(__name__)
app.config['SECRET_KEY'] = config['SECRET_KEY']
socketio = SocketIO(app)

# Queue to store messages for replay
message_queue = Queue()

# Globals to manage running pentest
pentest_thread: Thread | None = None
cancel_event: Event | None = None

def format_tool_output(output):
    """Format tool output for better display"""
    if isinstance(output, str):
        # Add syntax highlighting for JSON
        if output.strip().startswith('{') or output.strip().startswith('['):
            try:
                parsed = json.loads(output)
                return f'<pre class="json">{json.dumps(parsed, indent=2)}</pre>'
            except:
                pass
        
        # Add syntax highlighting for command output
        if '$ ' in output or '\n' in output:
            return f'<pre class="command-output">{output}</pre>'
        
    return f'<pre>{output}</pre>'

def handle_message(message_type, content, agent_name=None):
    """Process and emit different types of messages"""
    timestamp = datetime.now().strftime('%H:%M:%S')
    
    message_data = {
        'timestamp': timestamp,
        'type': message_type,
        'content': content,
        'agent': agent_name
    }
    
    # Store in queue for replay
    message_queue.put(message_data)
    
    # Emit to connected clients
    socketio.emit('new_message', message_data)

class WebUIMessageHandler:
    """Handler for messages from the pentest team to the web UI"""
    
    def handle_agent_message(self, agent_name, message):
        """Handle regular agent messages"""
        handle_message('agent', message, agent_name)
    
    def handle_tool_call(self, agent_name, tool_name, args):
        """Handle tool call messages"""
        formatted = f"Tool Call: {tool_name}\nArguments: {json.dumps(args, indent=2)}"
        handle_message('tool_call', formatted, agent_name)
    
    def handle_tool_result(self, agent_name, tool_name, result):
        """Handle tool result messages"""
        formatted_result = format_tool_output(result)
        handle_message('tool_result', formatted_result, agent_name)
    
    def handle_error(self, error_message):
        """Handle error messages"""
        handle_message('error', error_message)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/tools')
def get_tools():
    # Flatten tool categories into a single list
    tools = []
    for category in config['TOOL_CATEGORIES'].values():
        tools.extend(category)
    return jsonify(tools)

@app.route('/defaults')
def get_defaults():
    return jsonify({
        'planner_prompt': config['PLANNER_SYSTEM_MESSAGE'],
        'selector_prompt': config['SELECTOR_SYSTEM_MESSAGE']
    })

@app.route('/start', methods=['POST'])
def start_pentest():
    global pentest_thread, cancel_event

    if pentest_thread and pentest_thread.is_alive():
        return jsonify({'error': 'A pentest is already running. Please stop it first.'}), 400

    data = request.json
    urls: List[str] = data.get('urls') or []
    if not urls:
        return jsonify({'error': 'At least one URL is required'}), 400

    # Use default web model from config
    data['web_model'] = config['DEFAULT_WEB_MODEL']

    # Prompt overrides
    planner_prompt = data.get('planner_prompt')
    selector_prompt = data.get('selector_prompt')

    # Get selected tool names
    tool_names = data.get('tools')

    # Clear existing message queue
    while not message_queue.empty():
        message_queue.get()

    # Message handler and cancel event
    message_handler = WebUIMessageHandler()
    cancel_event = Event()

    async def run_async():
        await run_pentest_team(
            target_urls=urls,
            message_handler=message_handler,
            cancel_event=cancel_event,
            planner_model=data['planner_model'],
            web_model=data['web_model'],
            planner_prompt_override=planner_prompt,
            selector_prompt_override=selector_prompt,
            tool_names=tool_names,
        )

    def run_test():
        asyncio.run(run_async())

    pentest_thread = Thread(target=run_test, daemon=True)
    pentest_thread.start()

    return jsonify({'status': 'started'})

@app.route('/stop', methods=['POST'])
def stop_pentest():
    global cancel_event, pentest_thread
    if cancel_event:
        cancel_event.set()
    if pentest_thread:
        pentest_thread.join(timeout=2)
    pentest_thread = None
    cancel_event = None
    return jsonify({'status': 'stopped'})

@app.route('/messages')
def get_messages():
    """Get all messages for replay"""
    messages = []
    while not message_queue.empty():
        messages.append(message_queue.get())
    return jsonify(messages)

if __name__ == '__main__':
    socketio.run(app, 
                host='0.0.0.0', 
                port=config['DEFAULT_PORT'],
                debug=config['DEBUG_MODE']) 