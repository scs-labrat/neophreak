from flask import Flask, render_template, request, jsonify, send_file
import os
import subprocess
import threading
import re
import shodan
import csv
from concurrent.futures import ThreadPoolExecutor
import logging
from telcotool import load_ips, run_tests_concurrently, save_results
import shutil
import json
from werkzeug.utils import secure_filename
import time

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['RESULTS_FOLDER'] = 'results'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['RESULTS_FOLDER'], exist_ok=True)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

executor = ThreadPoolExecutor(max_workers=5)
tasks = {}
results = {}  # Store results in memory for simplicity
telco_target_process = None
stop_event = threading.Event()

# Port-protocol mapping
port_protocol_mapping = {
    3868: [("Diameter", 'cyan')],
    2905: [("M3UA (Sigtran)", 'green')],
    2915: [("SUA (Sigtran)", 'yellow')],
    36412: [("SCTP Heartbeat", 'magenta')],
    1812: [("RADIUS (Diameter Compatibility)", 'blue')],
    1813: [("RADIUS Accounting (Diameter Compatibility)", 'red')],
    3565: [("M2PA (Sigtran)", 'cyan')],
    2904: [("M2UA (Sigtran)", 'green')],
    9900: [("IUA (ISDN User Adaptation)", 'yellow')],
    2944: [("H.248/MEGACO", 'magenta')],
    2123: [("GTP-C (GPRS Tunneling Protocol)", 'blue')],
    2152: [("GTP-U (GPRS Tunneling Protocol)", 'red')]
}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return "No file part", 400
    file = request.files['file']
    if file.filename == '':
        return "No selected file", 400
    filename = secure_filename(file.filename)  # Sanitize filename
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)
    logging.info(f"File uploaded: {filepath}")
    return jsonify({'filepath': filepath})

@app.route('/save_ips', methods=['POST'])
def save_ips():
    data = request.json
    ips = data.get('ips', [])

    if not ips:
        return jsonify({"error": "No IPs provided"}), 400

    # Validate IPs
    ip_regex = re.compile(r'^(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)){3}$')
    valid_ips = [ip for ip in ips if ip_regex.match(ip)]
    if not valid_ips:
        return jsonify({"error": "No valid IPs provided"}), 400

    # Create a unique filename with timestamp
    timestamp = int(time.time())
    filename = f"target_ips_{timestamp}.txt"
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    try:
        with open(filepath, 'w') as f:
            for ip in valid_ips:
                f.write(f"{ip}\n")
        logging.info(f"Target IPs saved: {filepath}")
        return jsonify({'filepath': filepath}), 200
    except Exception as e:
        logging.error(f"Error saving target IPs: {str(e)}")
        return jsonify({"error": "Failed to save IPs"}), 500

@app.route('/find_telco_targets', methods=['POST'])
def find_telco_targets():
    global telco_target_process, stop_event
    if telco_target_process and telco_target_process.poll() is None:
        return jsonify({"message": "Discovery already running"}), 400

    stop_event.clear()

    # Command to discover Telco targets
    # Ensure that the commands and tools used here generate 'telco-results.json' correctly
    command = (
        "sudo ip4scout random --ports=3868,2905,2915,36412,1812,1813,3565,2904,9900,2944,2123,2152 "
        "| tee telco-results.json | l9filter transform -i l9 -o human | tee telco-humanreadable.txt"
    )

    def run_discovery():
        global telco_target_process
        with open("discovery_output.log", "w") as log_file:
            telco_target_process = subprocess.Popen(
                command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )
            while not stop_event.is_set():
                line = telco_target_process.stdout.readline()
                if line:
                    log_file.write(line)
                    log_file.flush()
                elif telco_target_process.poll() is not None:
                    break

    threading.Thread(target=run_discovery, daemon=True).start()
    logging.info("Telco target discovery started.")
    return jsonify({"message": "Telco target discovery started"}), 200

@app.route('/stop_telco_targets', methods=['POST'])
def stop_telco_targets():
    global telco_target_process, stop_event
    if telco_target_process and telco_target_process.poll() is None:
        stop_event.set()
        telco_target_process.terminate()
        telco_target_process = None
        logging.info("Telco target discovery stopped.")
        return jsonify({"message": "Telco target discovery stopped"}), 200
    else:
        return jsonify({"message": "No discovery process running"}), 400

@app.route('/fetch_discovery_output', methods=['GET'])
def fetch_discovery_output():
    try:
        with open("discovery_output.log", "r") as log_file:
            return log_file.read(), 200
    except FileNotFoundError:
        return "No discovery output available yet.", 200

@app.route('/check_dependencies', methods=['POST'])
def check_dependencies():
    dependencies = [
        ("ip4scout", "https://github.com/LeakIX/ip4scout/releases/download/v1.0.0-beta.2/ip4scout-linux-64"),
        ("l9filter", "https://github.com/LeakIX/l9filter/releases/download/v1.1.0/l9filter-linux-64")
    ]
    missing = []
    for dep, url in dependencies:
        if not shutil.which(dep):
            missing.append({"name": dep, "url": url})
    return jsonify({"missing": missing}), 200

@app.route('/run_tests', methods=['POST'])
def run_tests():
    data = request.json
    filepath = data.get('filepath')
    mode = data.get('mode', 'all')
    workers = int(data.get('workers', 5))
    msisdn = data.get('msisdn', '1234567890')

    if not filepath or not os.path.isfile(filepath):
        return jsonify({'error': 'Invalid or missing filepath'}), 400

    ips = load_ips(filepath)

    if not ips:
        return jsonify({'error': 'No valid IPs in file'}), 400

    # Create a unique results filename
    timestamp = int(time.time())
    results_filename = f"results_{timestamp}.csv"
    output_path = os.path.join(app.config['RESULTS_FOLDER'], results_filename)
    future = executor.submit(run_tests_concurrently, ips, workers, msisdn, mode)
    tasks[future] = output_path

    def get_results():
        try:
            result = future.result()
            save_results(output_path, result)
            logging.info(f"Tests completed and results saved to {output_path}")
        except Exception as e:
            logging.error(f"Error during test execution: {str(e)}")

    future.add_done_callback(lambda _: get_results())
    return jsonify({'message': 'Test started', 'results_path': output_path}), 200

@app.route('/stop_tests', methods=['POST'])
def stop_tests():
    # Implement logic to stop ongoing tests
    # This could involve cancelling futures or terminating subprocesses
    # For simplicity, we'll clear all tasks
    global tasks
    if tasks:
        for future in list(tasks):
            future.cancel()
            del tasks[future]
        logging.info("All ongoing tests have been stopped.")
        return jsonify({"message": "All ongoing tests have been stopped."}), 200
    else:
        return jsonify({"message": "No ongoing tests to stop."}), 400

@app.route('/parse_results', methods=['POST'])
def parse_results():
    data = request.json
    filename = data.get('filename', 'telco-humanreadable.txt')

    try:
        with open(filename, 'r') as file:
            lines = file.readlines()  # Read each line as a separate JSON object

        # Extract IPs and Ports
        parsed_results = []
        for line in lines:
            try:
                # Parse each JSON object
                entry = json.loads(line)
                ip = entry.get("ip")
                port = entry.get("port")

                # Skip entries with missing IP or Port
                if not ip or not port:
                    continue

                # Append to the parsed results
                parsed_results.append({
                    "IP": ip,
                    "Port": int(port),  # Ensure the port is an integer
                    "Protocols": []  # Protocols can be added if available
                })
            except json.JSONDecodeError:
                continue  # Skip invalid JSON lines

        # Return the structured response
        return jsonify({"parsed_results": parsed_results}), 200

    except FileNotFoundError:
        return jsonify({"error": f"{filename} file not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/export_to_csv', methods=['POST'])
def export_to_csv():
    data = request.json
    csv_filename = data.get('filename', 'export.csv')
    parsed_data = []

    # Read from the parsed results file
    try:
        with open('telco-results.json', 'r') as file:
            for line in file:
                entry = json.loads(line)
                ip = entry.get("ip")
                port = entry.get("port")
                protocols = entry.get("protocols", [])
                parsed_data.append([ip, port, ', '.join(protocols)])
    except FileNotFoundError:
        return jsonify({"error": "telco-results.json file not found"}), 404
    except json.JSONDecodeError:
        return jsonify({"error": "Invalid JSON format in telco-results.json"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    # Write to CSV
    try:
        csv_path = os.path.join(app.config['RESULTS_FOLDER'], csv_filename)
        with open(csv_path, 'w', newline='') as csv_file:
            writer = csv.writer(csv_file)
            writer.writerow(["IP", "Port", "Protocols"])
            writer.writerows(parsed_data)
        return send_file(csv_path, as_attachment=True)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/query_shodan', methods=['POST'])
def query_shodan():
    SHODAN_API_KEY = os.getenv('SHODAN_API_KEY')
    if not SHODAN_API_KEY:
        return jsonify({"error": "Shodan API key not configured"}), 500

    api = shodan.Shodan(SHODAN_API_KEY)
    # Example query: Search for devices on specified ports
    ports = ','.join([str(port) for port in port_protocol_mapping.keys()])
    query = f'port:{ports}'

    try:
        results = api.search(query)
        # Limit the number of matches returned to prevent overwhelming the frontend
        limited_matches = results.get('matches', [])[:10]  # Adjust as needed
        return jsonify({
            "total": results.get('total', 0),
            "matches": limited_matches
        }), 200
    except shodan.APIError as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
