# Veracode Verify Scan Results:
## Overview

This script checks for the results of the latest scan for an application profile (and optionally a sandbox) and returns all the results that meet a minimum severity criteria.
Can optionally consider SCA results and fail a build.

## Installation

Clone this repository:

    git clone https://github.com/cadonuno/Veracode-Verify-Scan-Results.git

Install dependencies:

    cd Veracode-Verify-Scan-Results
    pip install -r requirements.txt

### Getting Started

It is highly recommended that you store veracode API credentials on disk, in a secure file that has 
appropriate file protections in place.

(Optional) Save Veracode API credentials in `~/.veracode/credentials`

    [default]
    veracode_api_key_id = <YOUR_API_KEY_ID>
    veracode_api_key_secret = <YOUR_API_KEY_SECRET>

### Running the script
    py veracode-verify-scan-results.py -a <application_name> -m <minimum_severity> [--sandbox_name <sandbox_name>] [-s] [-f (fail if results are found)] [-l] [-d]"
        Reads the results of the latest scan for the application called <application_name>, (and optionally a sandbox called <sandbox_name>).
        Returns all the results that are of severity <minimum_severity> or greater (optionally including SCA results if -s is passed)
        Passing the -f flag will return an error code equal to the number of findings identified.
        Passing the -l flag will return the results in a multiline format, instead of 1 finding per line.

If a credentials file is not created, you can export the following environment variables:

    export VERACODE_API_KEY_ID=<YOUR_API_KEY_ID>
    export VERACODE_API_KEY_SECRET=<YOUR_API_KEY_SECRET>
    py veracode-verify-scan-results.py -a <application_name> -m <minimum_severity> [--sandbox_name <sandbox_name>] [-s] [-f (fail if results are found)] [-l] [-d]

## License

[![MIT license](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

See the [LICENSE](LICENSE) file for details
