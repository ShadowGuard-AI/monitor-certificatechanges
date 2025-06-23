import argparse
import logging
import os
import hashlib
import json

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description="Monitor changes in trusted certificates.")
    parser.add_argument("--cert-dir", type=str, default="/etc/ssl/certs",
                        help="Path to the directory containing certificate files (default: /etc/ssl/certs)")
    parser.add_argument("--state-file", type=str, default="certificate_state.json",
                        help="File to store the state of the certificates (default: certificate_state.json)")
    parser.add_argument("--log-level", type=str, default="INFO",
                        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
                        help="Set the logging level (default: INFO)")
    return parser.parse_args()

def get_certificate_hashes(cert_dir):
    """
    Calculates SHA256 hashes for all certificate files in the given directory.

    Args:
        cert_dir (str): The path to the directory containing certificate files.

    Returns:
        dict: A dictionary where keys are certificate filenames and values are their SHA256 hashes.
              Returns None if an error occurs.
    """
    certificate_hashes = {}
    try:
        for filename in os.listdir(cert_dir):
            filepath = os.path.join(cert_dir, filename)
            if os.path.isfile(filepath):
                try:
                    with open(filepath, "rb") as f:
                        cert_data = f.read()
                        sha256_hash = hashlib.sha256(cert_data).hexdigest()
                        certificate_hashes[filename] = sha256_hash
                except OSError as e:
                    logging.error(f"Error reading certificate file {filename}: {e}")
    except OSError as e:
        logging.error(f"Error accessing certificate directory {cert_dir}: {e}")
        return None
    return certificate_hashes

def load_previous_state(state_file):
    """
    Loads the previous state of the certificates from the specified JSON file.

    Args:
        state_file (str): The path to the JSON file storing the previous state.

    Returns:
        dict: A dictionary representing the previous state of the certificates.
              Returns an empty dictionary if the file does not exist or an error occurs.
    """
    try:
        with open(state_file, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        logging.info(f"State file {state_file} not found.  Assuming initial run.")
        return {}
    except json.JSONDecodeError as e:
        logging.error(f"Error decoding JSON from state file {state_file}: {e}")
        return {}
    except OSError as e:
        logging.error(f"Error opening state file {state_file}: {e}")
        return {}

def save_current_state(state_file, current_state):
    """
    Saves the current state of the certificates to the specified JSON file.

    Args:
        state_file (str): The path to the JSON file to store the current state.
        current_state (dict): A dictionary representing the current state of the certificates.
    """
    try:
        with open(state_file, "w") as f:
        # Ensure data is serialized securely, disable ASCII escaping, handle non-ASCII characters
            json.dump(current_state, f, indent=4, sort_keys=True, ensure_ascii=False)  # indent for readability
    except OSError as e:
        logging.error(f"Error writing to state file {state_file}: {e}")

def compare_certificate_states(previous_state, current_state):
    """
    Compares the previous and current states of the certificates and reports any changes.

    Args:
        previous_state (dict): A dictionary representing the previous state of the certificates.
        current_state (dict): A dictionary representing the current state of the certificates.
    """
    added_certificates = set(current_state.keys()) - set(previous_state.keys())
    removed_certificates = set(previous_state.keys()) - set(current_state.keys())
    modified_certificates = {
        cert for cert in current_state if cert in previous_state and current_state[cert] != previous_state[cert]
    }

    if added_certificates:
        logging.warning(f"Added certificates: {added_certificates}")
    if removed_certificates:
        logging.warning(f"Removed certificates: {removed_certificates}")
    if modified_certificates:
        logging.warning(f"Modified certificates: {modified_certificates}")

    if not added_certificates and not removed_certificates and not modified_certificates:
        logging.info("No certificate changes detected.")

def main():
    """
    Main function to monitor certificate changes.
    """
    args = setup_argparse()

    # Configure logging level based on CLI arguments
    logging.getLogger().setLevel(args.log_level)

    cert_dir = args.cert_dir
    state_file = args.state_file

    # Input validation for directory existence
    if not os.path.isdir(cert_dir):
        logging.error(f"Certificate directory '{cert_dir}' does not exist.")
        return

    # Ensure state file exists
    if not os.path.exists(state_file) and os.path.dirname(state_file):
        try:
            os.makedirs(os.path.dirname(state_file), exist_ok=True)
        except OSError as e:
            logging.error(f"Error creating directory for state file: {e}")
            return

    previous_state = load_previous_state(state_file)
    current_state = get_certificate_hashes(cert_dir)

    if current_state is None:
        # An error occurred while getting certificate hashes, exit gracefully
        return

    compare_certificate_states(previous_state, current_state)
    save_current_state(state_file, current_state)

if __name__ == "__main__":
    main()