![Banner](banner.png)

# monitor-certificatechanges
Monitors changes in trusted certificates, highlighting additions or removals of root or intermediate certificates which could indicate a compromise. - Focused on System monitoring and alerts

This tool uses only the Python standard library. No installs are needed and there is no requirements.txt.

## Install
`git clone https://github.com/ShadowGuardAI/monitor-certificatechanges`

## Usage
`python3 main.py [--cert-dir DIR] [--state-file FILE] [--log-level LEVEL]`

Each run hashes the regular files in the certificate directory with SHA256, states the count of files hashed, and compares the result with the state file. On the first run, when no state file exists, the run captures a silent baseline and states that a baseline was captured, instead of reporting every file as added. If the state file exists but is corrupt, the run exits with status 1 and does not overwrite the state file. If the certificate directory does not exist, hashing fails at the directory level, the state file cannot be saved, or no files could be hashed, the run exits with status 1. When no files could be hashed, the run states that nothing was scanned. The state file itself is excluded from the hashing set, even when it is placed inside the certificate directory.

## Parameters
- `-h`: Show help message and exit
- `--cert-dir`: Path to the directory containing certificate files (default: /etc/ssl/certs)
- `--state-file`: File to store the state of the certificates (default: certificate_state.json)
- `--log-level`: Set the logging level (default: INFO)

## License
Copyright (c) ShadowGuardAI
