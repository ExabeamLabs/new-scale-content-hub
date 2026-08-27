# Exabeam Bad Parsing Identifier

Author: Andrew Quan - andrew.quan@exabeam.com

The **Bad Parsing Identifier** is a command-line utility designed to help security teams and Exabeam administrators proactively detect log parsing anomalies. The script programmatically executes a suite of predefined Exabeam searches over the past 7 days of ingested logs to flag common indicators of bad or partial parsing (such as placeholder values, incorrect characters, or corrupted values in key fields like user, host, email, DNS, and processes).

Whenever potential parsing issues are detected, the tool generates direct, pre-formatted search deep-links pointing directly to your Exabeam console, and writes the results to a CSV file for remediation tracking.

## Features

- **Predefined Search Checks**: Evaluates fields such as `user`, `email_address`, `process_name`, `process_path`, `dns_query`, `dest_host`, `src_host`, and `host` for known misparsing characteristics.
- **Multi-threaded Execution**: Leverages Python's `ThreadPoolExecutor` to perform API calls concurrently, significantly speeding up detection times.
- **Deep-link Generation**: Compresses and base64 encodes search queries to construct direct URL deep-links pointing to the identified event logs in your Exabeam Search UI.
- **Customizable Scope**: Accepts an optional search query prefix to isolate analysis (e.g., target a specific vendor, product, or log source).
- **CSV Export**: Automatically exports all successfully matched anomalies and their direct drill-down links to a local `output.csv`.

## Future features (todo):
- Add output of vendor, product query to confirm that all vendors and products are expected. Unexpected vendors and products may indicate misparsing. 

## Prerequisites

Make sure Python 3 is installed. It is highly recommended to run this tool within a Python virtual environment (`venv`) to keep your dependencies isolated.

### 1. Set up a Virtual Environment

Create and activate a virtual environment in the script's directory:

*   **macOS / Linux:**
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```
*   **Windows (Command Prompt):**
    ```cmd
    python -m venv venv
    venv\Scripts\activate
    ```

### 2. Install Required Libraries

With the virtual environment activated, install the dependencies:
```bash
pip install requests python-dotenv colorama
```

## Credentials Setup

This script requires a valid API Client ID and Secret to fetch access tokens from Exabeam. https://docs.exabeam.com/en/apis/all/api-get-started-guide/api-keys/create-an-api-key.html 

Create a `.env` file (e.g., `credentials.env`) in your working directory with the following variables:

> ⚠️ **Important:** Ensure that your `.env` or `credentials.env` files are added to your `.gitignore` so they are never committed to your public repository.

```env
CLIENT_ID="your_client_id_here"
CLIENT_SECRET="your_client_secret_here"
```

## Usage

Execute the script from the command line using the required positional arguments:

```bash
python bad-parsing-identifier.py <region> <env_name> <token_file> [options]
```

### Arguments and Parameters

| Argument / Option | Required? | Description |
| :--- | :---: | :--- |
| `region` | **Yes** | The cloud region where your Exabeam instance resides (e.g., `us-west`, `us-east`, `ca`, `sg`, `jp`, `eu`, `au`, `ch`, `sa`, `uk`). |
| `env_name` | **Yes** | Your unique Exabeam tenant / environment prefix. This is the part that preceeds exabeam.cloud (e.g., `mycompany.exabeam.cloud`) |
| `token_file` | **Yes** | Path to the `.env` file containing API credentials. |
| `--prefix` | No | Prepend a filter query to all executed searches (e.g., `'vendor=="Palo Alto Networks"'`). |
| `--threads` | No | Define the number of concurrent search worker threads. Defaults to `10`. |

### Example Commands

**Standard run against all data:**
```bash
python bad-parsing-identifier.py us-west mycompany-prod credentials.env
```

**Scoping checks to a specific vendor with a thread limit of 15:**
```bash
python bad-parsing-identifier.py us-east mycompany-prod credentials.env --prefix 'vendor=="Fortinet"' --threads 15
```

## Output

Upon completion, the tool provides two forms of output:

1. **Terminal Console Output**: Color-coded CLI outputs (via `colorama`) highlighting identified parsing problems with direct logs URLs immediately clickable in the terminal.
2. **`output.csv`**: A CSV spreadsheet consisting of the following fields for simple parsing-issue reporting:
   - `query`: The exact search string that returned parsing anomaly events.
   - `url`: A direct deep-link into your Exabeam UI to quickly review and remediate the affected raw logs.

---

*Note: The script also displays a final link recommending checking your lower event-count parsers, which frequently correlate with misparsing errors.*