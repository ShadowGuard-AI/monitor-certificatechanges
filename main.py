import argparse
import logging
import os
import sys
import hashlib
import json

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    parser = argparse.ArgumentParser(description="Monitor changes in trusted certificates.")
    parser.add_argument("--cert-dir", type=str, default="/etc/ssl/certs",
                        help="Path to the directory containing certificate files (default: /etc/ssl/certs)")
    parser.add_argument("--state-file", type=str, default="certificate_state.json",
                        help="File to store the state of the certificates (default: certificate_state.json)")
    parser.add_argument("--log-level", type=str, default="INFO",
                        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
                        help="Set the logging level (default: INFO)")
    return parser.parse_args()

def get_certificate_hashes(cert_dir, state_file=None):
    certificate_hashes = {}
    state_resolved = os.path.realpath(state_file) if state_file else None
    try:
        for filename in os.listdir(cert_dir):
            filepath = os.path.join(cert_dir, filename)
            if state_resolved and os.path.realpath(filepath) == state_resolved:
                continue
            if os.path.isfile(filepath):
                try:
                    with open(filepath, "rb") as f:
                        cert_data = f.read()
                        sha256_hash = hashlib.sha256(cert_data).hexdigest()
                        # State is keyed by bare file name and the directory is read
                        # one level deep, so this is a flat inventory. Certificates
                        # in a subdirectory are outside it entirely, and a symlink is
                        # hashed at its target's contents under the link's name.
                        certificate_hashes[filename] = sha256_hash
                # A file I cannot read drops out of the current state without
                # a marker. The comparison below then reports it as removed,
                # and because the state is saved at the end of the run, it
                # comes back as added on the first run that can read it
                # again. Permission trouble therefore looks exactly like
                # certificate churn in my output.
                except OSError as e:
                    logging.error(f"Error reading certificate file {filename}: {e}")
    except OSError as e:
        logging.error(f"Error accessing certificate directory {cert_dir}: {e}")
        return None
    return certificate_hashes

def load_previous_state(state_file):
    """Returns (state, is_baseline). Returns (None, False) on corrupt or unreadable state."""
    try:
        with open(state_file, "r") as f:
            return json.load(f), False
    except FileNotFoundError:
        logging.info(f"State file {state_file} not found. Capturing baseline.")
        return {}, True
    except json.JSONDecodeError as e:
        logging.error(f"Error decoding JSON from state file {state_file}: {e}")
        return None, False
    except OSError as e:
        logging.error(f"Error opening state file {state_file}: {e}")
        return None, False

def save_current_state(state_file, current_state):
    try:
        with open(state_file, "w") as f:
            json.dump(current_state, f, indent=4, sort_keys=True, ensure_ascii=False)
        return True
    except OSError as e:
        logging.error(f"Error writing to state file {state_file}: {e}")
        return False

def compare_certificate_states(previous_state, current_state):
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
    args = setup_argparse()
    logging.getLogger().setLevel(args.log_level)
    cert_dir = args.cert_dir
    state_file = args.state_file
    if not os.path.isdir(cert_dir):
        logging.error(f"Certificate directory '{cert_dir}' does not exist.")
        sys.exit(1)
    if not os.path.exists(state_file) and os.path.dirname(state_file):
        try:
            os.makedirs(os.path.dirname(state_file), exist_ok=True)
        except OSError as e:
            logging.error(f"Error creating directory for state file: {e}")
            sys.exit(1)
    # The loaded state is trusted to be a mapping of names to
    # hashes because a previous version of me wrote it that way.
    # A state file holding valid JSON of another shape, a list,
    # a bare string, reaches the comparison and fails there with
    # an attribute error rather than being named as unusable.
    previous_state, is_baseline = load_previous_state(state_file)
    if previous_state is None:
        logging.error(f"State file {state_file} is corrupt or unreadable. Refusing to overwrite it.")
        sys.exit(1)
    current_state = get_certificate_hashes(cert_dir, state_file)
    if current_state is None:
        sys.exit(1)
    logging.info(f"Files hashed: {len(current_state)}")
    if len(current_state) == 0:
        logging.error("Nothing scanned: 0 files could be hashed.")
        sys.exit(1)
    if is_baseline:
        logging.info(f"Baseline captured: {len(current_state)} files hashed.")
    else:
        # This is a one shot comparison, not a watcher. The state is
        # overwritten at the end of every successful run, so each
        # change is reported exactly once, by the first run after it
        # happens, and a run whose log nobody read has still consumed
        # the change.
        compare_certificate_states(previous_state, current_state)
    # Detected changes never move the exit code: main falls off
    # the end after this and exits 0 whether the comparison found
    # an added trust anchor or nothing at all. Only failures to
    # scan or to save produce a nonzero exit, so a caller has to
    # read the log, not the code, to learn about changes.
    if not save_current_state(state_file, current_state):
        sys.exit(1)

if __name__ == "__main__":
    main()
