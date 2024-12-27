import logging
import random
import time
import os
import re
import shutil
import threading
from typing import List, Dict, Union
from concurrent.futures import ThreadPoolExecutor, as_completed
from scapy.all import IP, TCP, UDP, SCTP, sr1, send
from scapy.contrib.diameter import DiamReq
from scapy.contrib.gtp import GTP_U_Header, GTP_PDCP_PDU_ExtensionHeader
from sccp_custom import SCCP, XUDT
import csv
import argparse
import pyshark
from tqdm import tqdm
import ipaddress
from subprocess import run, TimeoutExpired, CalledProcessError
from termcolor import colored
import pyfiglet
import shodan
from pathlib import Path
from prettytable import PrettyTable
import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(), logging.FileHandler("telco_testing.log")]
)

# Helper function to check if a tool is available
def is_tool_installed(tool: str) -> bool:
    result = run(["which", tool], capture_output=True, text=True)
    return result.returncode == 0

# Validate IP addresses
def validate_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        logging.warning(f"Invalid IP address: {ip}")
        return False

# Load IP addresses from a file
def load_ips(filepath: str) -> List[str]:
    try:
        with open(filepath, 'r') as file:
            ips = [line.strip() for line in file.readlines() if line.strip()]
            return [ip for ip in ips if validate_ip(ip)]
    except FileNotFoundError:
        logging.error(f"File not found: {filepath}")
        return []
    except Exception as e:
        logging.error(f"Error loading IPs from {filepath}: {e}")
        return []

# Save results to CSV
def save_results(filepath: str, results: List[Dict[str, Union[str, float]]]):
    try:
        with open(filepath, 'w', newline='') as file:
            fieldnames = results[0].keys() if results else []
            writer = csv.DictWriter(file, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(results)
        logging.info(f"Results saved to {filepath}.")
    except IOError as e:
        logging.error(f"Error saving results: {e}")

# Generate HTML Report with Custom Styling
def generate_html_report(filepath: str, results: list):
    try:
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        table = PrettyTable()
        keys = results[0].keys() if results else []
        table.field_names = keys
        for row in results:
            table.add_row([row.get(field, "") for field in keys])
        custom_style = """
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; }
            h1 { color: #333; }
            table { border-collapse: collapse; width: 100%; }
            th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
            th { background-color: #f4f4f4; }
        </style>
        """
        with open(filepath, 'w') as f:
            f.write(f"<html><head>{custom_style}</head><body>")
            f.write(f"<h1>Telco Security Testing Report</h1>")
            f.write(f"<p>Generated at: {timestamp}</p>")
            f.write(table.get_html_string(attributes={"border": "1"}))
            f.write(f"</body></html>")
        logging.info(f"HTML report saved as: {filepath}")
    except Exception as e:
        logging.error(f"Error generating HTML report: {e}")

# Send Diameter packets with error handling
def send_diameter_packet(target_ip: str, avps: dict, port: int = 3868) -> Dict[str, Union[str, float]]:
    try:
        logging.info(f"Sending Diameter packet to {target_ip}:{port} with AVPs: {avps}")
        start_time = time.time()
        diameter_packet = IP(dst=target_ip) / TCP(dport=port) / DiamReq(avps=avps)
        response = sr1(diameter_packet, timeout=3, verbose=False)
        response_time = round((time.time() - start_time) * 1000, 2)
        if response:
            return {
                "Response": response.summary(),
                "Response Time (ms)": response_time,
                "Success": True
            }
        else:
            logging.warning(f"No response received from {target_ip}:{port}.")
            return {"Response": "No response", "Response Time (ms)": response_time, "Success": False}
    except Exception as e:
        logging.error(f"Error sending Diameter packet to {target_ip}:{port}: {e}")
        return {"Error": str(e), "Success": False}

# Test for subscriber information disclosure
def test_subscriber_information_disclosure(target_ip: str) -> bool:
    avps = {
        "User-Name": "testuser",
        "Destination-Realm": "example.com"
    }
    result = send_diameter_packet(target_ip, avps)
    if result["Success"] and "Response" in result:
        logging.warning(f"Potential information disclosure detected: {result['Response']}")
        return True
    return False

# Test for network information disclosure
def test_network_information_disclosure(target_ip: str) -> bool:
    try:
        logging.info(f"Scanning {target_ip} for open Diameter ports...")
        result = run(["nmap", "-p", "3868", target_ip], capture_output=True, text=True, timeout=10)
        if "open" in result.stdout:
            logging.warning(f"Open Diameter port detected on {target_ip}. Review configuration.")
            return True
        else:
            logging.info(f"No open Diameter ports found on {target_ip}.")
            return False
    except TimeoutExpired:
        logging.error(f"Nmap scan timed out for {target_ip}.")
        return False
    except Exception as e:
        logging.error(f"Error during network information disclosure test: {e}")
        return False

# Test for fraudulent activity
def test_fraudulent_activity(target_ip: str) -> bool:
    avps = {
        "User-Name": "testuser",
        "Requested-Service-Unit": {"CC-Time": random.randint(100, 3600)}
    }
    result = send_diameter_packet(target_ip, avps)
    if result["Success"] and "Response" in result:
        logging.warning(f"Potential fraud vulnerability detected: {result['Response']}")
        return True
    return False

# Test for error code exploitation
def test_error_code_exploitation(target_ip: str) -> bool:
    avps = {
        "Unknown-AVP": "malformed_value"
    }
    result = send_diameter_packet(target_ip, avps)
    if result["Success"] and "Response" in result:
        logging.warning(f"Received error response: {result['Response']}")
        return True
    return False

# Test for randomized and malformed Diameter packets
def test_malformed_diameter_packets(target_ip: str) -> bool:
    try:
        logging.info(f"Testing malformed Diameter packets on {target_ip}")
        avps = {"Malformed-AVP": random.choice(["", None, "malformed_data"])}
        result = send_diameter_packet(target_ip, avps)
        if result["Success"] and "Response" in result:
            logging.warning(f"Malformed packet detected server-side: {result['Response']}")
            return True
        return False
    except Exception as e:
        logging.error(f"Error during malformed packet test: {e}")
        return False

# Summarize test results
def summarize_results(results: List[Dict[str, Union[str, float]]]):
    logging.info("\n--- Test Summary ---")
    summary = {}
    protocol_summary = {}
    for result in results:
        for key, value in result.items():
            if key != "IP" and isinstance(value, bool):
                summary[key] = summary.get(key, 0) + int(value)

                protocol = key.split()[0]
                protocol_summary[protocol] = protocol_summary.get(protocol, 0) + int(value)

    logging.info(f"Detailed Summary by Category: {summary}")
    logging.info(f"Summary by Protocol: {protocol_summary}")

# CLI Menu for User Interaction
def cli_menu():
    while True:
        print("\n--- Telco Testing Tool Menu ---")
        print("1. Run All Tests")
        print("2. View Test Results")
        print("3. Import Target List")
        print("4. Generate HTML Report")
        print("5. Exit")
        choice = input("Select an option: ").strip()

        if choice == "1":
            input_file = input("Enter the path to the input file: ").strip()
            output_file = input("Enter the path to save results: ").strip()
            workers = int(input("Enter the number of worker threads (default 5): ").strip() or 5)
            interface = input("Enter the network interface (default eth0): ").strip() or "eth0"

            target_ips = load_ips(input_file)
            if not target_ips:
                logging.error("No valid IPs loaded. Exiting.")
                continue

            results = run_tests_concurrently(target_ips, workers=min(workers, len(target_ips)))
            save_results(output_file, results)
            summarize_results(results)

        elif choice == "2":
            results_file = input("Enter the path to the results file: ").strip()
            try:
                with open(results_file, 'r') as file:
                    print(file.read())
            except FileNotFoundError:
                logging.error(f"Results file {results_file} not found.")

        elif choice == "3":
            target_list = input("Enter the path to the target list file: ").strip()
            ips = load_ips(target_list)
            if ips:
                logging.info(f"Loaded {len(ips)} targets from {target_list}.")
            else:
                logging.error("No valid targets loaded.")

        elif choice == "4":
            results_file = input("Enter the path to the results file: ").strip()
            html_file = input("Enter the path to save the HTML report: ").strip()
            try:
                with open(results_file, 'r') as file:
                    results = list(csv.DictReader(file))
                generate_html_report(html_file, results)
            except FileNotFoundError:
                logging.error(f"Results file {results_file} not found.")

        elif choice == "5":
            logging.info("Exiting. Goodbye!")
            break

        else:
            logging.warning("Invalid choice. Please try again.")

# Concurrent Execution of Tests
def run_tests_concurrently(
    ips: List[str],
    workers: int,
    msisdn: str,
    mode: str,
    segment_lengths: List[int] = [30, 40, 30]
) -> List[Dict[str, Union[str, float]]]:
    """
    Concurrently execute tests for specified protocol mode.

    Parameters:
        ips (List[str]): List of target IP addresses.
        workers (int): Number of threads for concurrent testing.
        msisdn (str): MSISDN used for Diameter and SCCP tests.
        mode (str): Test mode to execute ("all", "diameter", "gtp", or "sccp").
        segment_lengths (List[int]): Segment lengths for SCCP-specific payloads.

    Returns:
        List[Dict[str, Union[str, float]]]: Results of all executed tests.
    """
    results = []
    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_ip = {
            executor.submit(run_all_tests, ip, msisdn, mode, segment_lengths): ip for ip in ips
        }
        for future in tqdm(as_completed(future_to_ip), total=len(future_to_ip), desc="Testing Progress"):
            try:
                results.append(future.result())
            except Exception as e:
                logging.error(f"Error executing tests on an IP: {e}")
    return results

# Run all tests on a single IP
def run_all_tests(ip: str, msisdn: str, mode: str, segment_lengths: List[int]) -> Dict[str, Union[str, float]]:
    """
    Run all or mode-specific tests on the specified IP.

    Parameters:
        ip (str): Target IP address.
        msisdn (str): MSISDN used for Diameter and SCCP tests.
        mode (str): Mode to run ("all", "diameter", "gtp", or "sccp").
        segment_lengths (List[int]): Segment lengths for SCCP payloads.

    Returns:
        dict: Test results for the target IP.
    """
    logging.info(f"Running {mode.upper()} tests on {ip}...")
    results = {"IP": ip}

    try:
        # Run Diameter tests
        if mode in ["all", "diameter"]:
            results["Subscriber Info Disclosure"] = test_subscriber_information_disclosure(ip)
            results["Fraudulent Activity"] = test_fraudulent_activity(ip)
            results["Malformed Packets"] = test_malformed_diameter_packets(ip)

        # Run GTP tests
        if mode in ["all", "gtp"]:
            results["GTP Anomalies"] = test_gtp_anomalies(ip)

        # Run SCCP tests
        if mode in ["all", "sccp"]:
            results["SCCP Routing Error"] = test_sccp_routing_error(ip, msisdn, target_sccp="99.44.0")
            results["SCCP Segmentation"] = test_sccp_segmentation(ip, msisdn, segment_lengths)

    except Exception as e:
        logging.error(f"Error running tests on {ip}: {e}")
        results["Error"] = str(e)

    return results

# Granular Telco CLI Menu Implementation
def cli_menu_v2(ips: List[str]):
    """
    Improved CLI Menu for managing granular options in Telco Security Testing.
    """
    while True:
        # Banner and Main Menu
        print("\n" + pyfiglet.figlet_format("Telco Tester", font="slant"))
        print(colored("=== Main Menu ===", "cyan"))
        print("1. Run ALL Protocol Tests")
        print("2. Run Diameter Protocol Tests")
        print("3. Run GTP Protocol Tests")
        print("4. Run SCCP Protocol Tests")
        print("5. Monitor IoT Traffic")
        print("6. View Detailed Results")
        print("7. Customize / Save Test Configurations")
        print("8. Exit")

        try:
            choice = input(colored("Enter your choice: ", "yellow")).strip()
            if choice == "1":
                results = run_tests_concurrently(ips, workers=5, msisdn="1234567890", mode="all")
                save_results("results.csv", results)
                print(colored("Results saved successfully!", "green"))

            elif choice == "2":
                diameter_test_submenu(ips)

            elif choice == "3":
                gtp_test_submenu(ips)

            elif choice == "4":
                sccp_test_submenu(ips)

            elif choice == "5":
                interface = input("Enter the network interface (default `eth0`): ") or "eth0"
                monitor_traffic(interface)

            elif choice == "6":
                print_results("results.csv")

            elif choice == "7":
                customize_save_configurations()

            elif choice == "8":
                print("Exiting the tool. Goodbye!")
                break
            else:
                print("Invalid choice, please try again.")

        except KeyboardInterrupt:
            print("\nTool interrupted manually. Exiting safely.")
            break


# Diameter Protocol Submenu
def diameter_test_submenu(ips: List[str]):
    """
    Menu for Diameter-specific tests.
    """
    while True:
        print("\n=== Diameter Tests ===")
        print("1. Subscriber Information Disclosure")
        print("2. Fraudulent Activity Testing")
        print("3. Malformed Packet Stress Test")
        print("4. Run All Diameter Tests")
        print("5. Back to Main Menu")
        choice = input("Enter your choice: ").strip()

        if choice == "1":
            for ip in ips:
                test_subscriber_information_disclosure(ip)
        elif choice == "2":
            for ip in ips:
                test_fraudulent_activity(ip)
        elif choice == "3":
            for ip in ips:
                test_malformed_diameter_packets(ip)
        elif choice == "4":
            for ip in ips:
                run_all_tests(ip)
        elif choice == "5":
            break
        else:
            print("Invalid choice, please try again.")


# GTP Protocol Submenu
def gtp_test_submenu(ips: List[str]):
    """
    Menu for GTP-specific tests.
    """
    while True:
        print("\n=== GTP Tests ===")
        print("1. Anomaly Detection Test")
        print("2. Malformed PDP Context Creation")
        print("3. Run All GTP Tests")
        print("4. Back to Main Menu")
        choice = input("Enter your choice: ").strip()

        if choice == "1":
            for ip in ips:
                test_gtp_anomalies(ip)
        elif choice == "2":
            print("Custom PDP Context Test not implemented yet.")
        elif choice == "3":
            for ip in ips:
                run_all_tests(ip, mode="gtp")
        elif choice == "4":
            break
        else:
            print("Invalid choice, please try again.")


# SCCP Protocol Submenu
def sccp_test_submenu(ips: List[str]):
    """
    Menu for SCCP-specific tests.
    """
    while True:
        print("\n=== SCCP Tests ===")
        print("1. SCCP Routing Error Simulation")
        print("2. SCCP Segmented Payload Test")
        print("3. Run All SCCP Tests")
        print("4. Back to Main Menu")
        choice = input("Enter your choice: ").strip()

        if choice == "1":
            msisdn = input("Enter MSISDN for routing error test: ")
            for ip in ips:
                test_sccp_routing_error(ip, msisdn, target_sccp="99.44.0")
        elif choice == "2":
            msisdn = input("Enter MSISDN for segmentation test: ")
            segment_lengths = [30, 40, 40]
            for ip in ips:
                test_sccp_segmentation(ip, msisdn, segment_lengths)
        elif choice == "3":
            for ip in ips:
                run_all_tests(ip, mode="sccp")
        elif choice == "4":
            break
        else:
            print("Invalid choice, please try again.")


# Showing Saved/Generated Results
def print_results(filepath: str):
    """
    Display results stored in the given CSV file.
    """
    try:
        with open(filepath, 'r') as file:
            print(file.read())
    except FileNotFoundError:
        print("Results file not found.")


# Customization and Saving Test Configurations
def customize_save_configurations():
    """
    Allow users to customize and save frequently used test options.
    """
    print("\n=== Test Configuration ===")
    msisdn = input("Enter default MSISDN (e.g., 1234567890): ") or "1234567890"
    target_sccp = input("Enter SCCP Target Address (e.g., 99.44.0): ") or "99.44.0"
    segment_lengths = input("Enter default segment lengths (comma-separated): ") or "30,40,30"
    try:
        with open("config.txt", "w") as config_file:
            config_file.write(f"MSISDN={msisdn}\n")
            config_file.write(f"TargetSCCP={target_sccp}\n")
            config_file.write(f"SegmentLengths={segment_lengths}\n")
        print("Configuration saved successfully!")
    except IOError:
        print("Error saving configuration.")


# Entry Point with Detailed CLI Menu
def main_with_granular_menu():
    parser = argparse.ArgumentParser(description="Granular Telco Testing CLI")
    parser.add_argument("--input", required=True, help="Path to input file containing target IPs.")
    parser.add_argument("--workers", type=int, default=5, help="Number of worker threads.")
    args = parser.parse_args()

    ips = load_ips(args.input)
    if not ips:
        print("No valid IPs found. Exiting.")
        return

    cli_menu_v2(ips)

# Test for GTP Protocol anomalies - undefined implementation
def test_gtp_anomalies(ip: str) -> dict:
    """Simulates GTP anomalies for vulnerability analysis."""
    try:
        logging.info(f"Simulating GTP anomaly on {ip}...")
        packet = IP(dst=ip) / UDP(dport=2152) / GTP_U_Header(teid=0xdeadbeef) / GTP_PDCP_PDU_ExtensionHeader(payload="test_payload")
        start_time = time.time()
        response = sr1(packet, timeout=5, verbose=False)
        response_time = round((time.time() - start_time) * 1000, 2)
        if response:
            return {"Response": response.summary(), "Response Time (ms)": response_time, "Success": True}
        return {"Response": "No response", "Response Time (ms)": response_time, "Success": False}
    except Exception as e:
        logging.error(f"Error during GTP anomaly test on {ip}: {e}")
        return {"Error": str(e), "Success": False}


# Simulating SCCP Routing Errors - undefined implementation
def test_sccp_routing_error(ip: str, msisdn: str, target_sccp: str) -> dict:
    """Simulates SCCP routing errors by crafting incorrect SCCP messages."""
    try:
        logging.info(f"Simulating SCCP routing error on {ip}...")
        packet = (
            IP(dst=ip) /
            SCTP() /
            SCCP(
                message_class=1,
                message_type='UDT',
                called_party_address=target_sccp,
                calling_party_address=msisdn
            )
        )
        response = sr1(packet, timeout=5, verbose=False)
        if response:
            return {"Response": response.summary(), "Success": True}
        return {"Response": "No response", "Success": False}
    except Exception as e:
        logging.error(f"Error during SCCP routing test on {ip}: {e}")
        return {"Error": str(e), "Success": False}


# Testing SCCP Segmented Payloads - undefined implementation
def test_sccp_segmentation(ip: str, msisdn: str, segment_lengths: List[int]) -> dict:
    """Simulates SCCP segmentation vulnerabilities."""
    try:
        logging.info(f"Testing SCCP segmentation for {ip}...")
        map_payload = f"MAP-SRI for MSISDN {msisdn}"
        segments = [map_payload[i:i + length] for length in segment_lengths for i in range(0, len(map_payload), length)]
        packet = (
            IP(dst=ip) /
            SCTP() /
            SCCP(message_class=1, message_type='XUDT') /
            XUDT(payload="".join(segments), segmentation=len(segments))
        )
        response = sr1(packet, timeout=5, verbose=False)
        if response:
            return {"Response": response.summary(), "Success": True}
        return {"Response": "No response", "Success": False}
    except Exception as e:
        logging.error(f"Error during SCCP segmentation test on {ip}: {e}")
        return {"Error": str(e), "Success": False}


# Network Traffic Monitoring - undefined implementation
def monitor_traffic(interface: str, duration: int = 10):
    """Monitor Diameter and TCP traffic using pyshark."""
    try:
        logging.info(f"Monitoring traffic on {interface} for {duration} seconds...")
        capture = pyshark.LiveCapture(interface=interface, bpf_filter="tcp port 3868")
        capture.sniff(timeout=duration)
        for packet in capture.sniff_continuously(packet_count=10):
            if hasattr(packet, 'diameter'):
                logging.info(f"Captured Diameter traffic: {packet.summary()}")
    except ImportError:
        logging.error("Pyshark module required for monitoring is not installed.")
    except Exception as e:
        logging.error(f"Error during traffic monitoring on {interface}: {e}")


# Displaying Generated Results - undefined implementation
def print_results(filepath: str):
    """Print saved results from the specified file."""
    try:
        logging.info(f"Loading results from file {filepath}...")
        with open(filepath, 'r') as file:
            print(file.read())
    except FileNotFoundError:
        logging.error(f"Results file {filepath} does not exist.")
    except Exception as e:
        logging.error(f"Error displaying results from {filepath}: {e}")


# Customize and Save Configurations - undefined implementation
def customize_save_configurations():
    """Allow the user to customize and save frequently used settings."""
    try:
        print("=== Customize Test Configuration ===")
        msisdn = input("Enter default MSISDN (e.g., '1234567890'): ") or "1234567890"
        segment_lengths = input("Enter default segment lengths (comma-separated, e.g., '30,40,50'): ") or "30,40,50"

        with open("config.txt", "w") as config_file:
            config_file.write(f"MSISDN={msisdn}\n")
            config_file.write(f"SegmentLengths={segment_lengths}\n")
        logging.info("Configuration saved successfully.")
    except IOError as e:
        logging.error(f"Error saving configurations: {e}")
    except Exception as e:
        logging.error(f"Unexpected error: {e}")

def main():
    parser = argparse.ArgumentParser(description="Unified Telco Testing Tool")
    parser.add_argument("--input", required=True, help="Path to the input file containing target IPs.")
    parser.add_argument("--output", required=True, help="Path to save the test results.")
    parser.add_argument("--interface", default="eth0", help="Network interface for IoT traffic monitoring.")
    parser.add_argument("--workers", type=int, default=5, help="Number of concurrent workers.")
    parser.add_argument("--mode", choices=["all", "diameter", "gtp", "sccp"], help="Specify which protocol tests to run.")
    parser.add_argument("--msisdn", help="MSISDN to be used for testing.")
    parser.add_argument("--segment-lengths", type=str, help="Comma-separated segment lengths for SCCP payload segmentation.")
    parser.add_argument("--menu", action="store_true", help="Launch interactive CLI menu.")
    args = parser.parse_args()

    # Check for required system tools
    if not is_tool_installed("nmap"):
        logging.error("Nmap is not installed. Please install it and try again.")
        return

    # Load target IPs from the specified input
    target_ips = load_ips(args.input)
    if not target_ips:
        logging.error("No valid IPs loaded. Exiting.")
        return

    # If CLI menu is selected, launch the interactive menu
    if args.menu:
        cli_menu_v2(target_ips)
        return

    # Check if either mode or menu is invoked
    if not args.mode:
        logging.error("No mode or menu specified. Use --menu or specify --mode to start the tool.")
        return

    # Handle mode-based execution (no CLI)
    logging.info(f"Starting {args.mode.upper()} protocol tests with {len(target_ips)} IPs...")

    # Defaults for SCCP-related arguments if provided
    segment_lengths = [int(x.strip()) for x in args.segment_lengths.split(",")] if args.segment_lengths else [30, 40, 30]
    msisdn = args.msisdn if args.msisdn else "1234567890"  # Default MSISDN if not provided

    results = run_tests_concurrently(
        ips=target_ips,
        workers=min(args.workers, len(target_ips)),
        msisdn=msisdn,
        mode=args.mode,
        segment_lengths=segment_lengths
    )

    # Save results to the specified output path
    save_results(args.output, results)
    summarize_results(results)
    logging.info("Testing completed and results saved.")

if __name__ == "__main__":
    main()
