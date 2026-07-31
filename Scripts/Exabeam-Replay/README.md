# Exabeam Replay

Exabeam Replay is a small desktop and command-line utility for replaying raw log samples to Webhook and Syslog collectors during ingestion and parser testing.

> Independent community project. It is not an official Exabeam product.

## Features

- Paste UTF-8 logs or upload a log file.
- Replay to Webhook, Syslog UDP, Syslog TCP, or Syslog TLS.
- Repeat a source for a selected number of passes with an interval between passes.
- Test destination connectivity before replay.
- Optionally save destination settings and an encrypted Webhook token.
- Optionally save JSON run reports in the default `reports/` directory.

## Requirements

- Python 3.10 or newer
- Tkinter
- `cryptography` on macOS and Linux only

Install Python dependencies:

```bash
python -m pip install -r requirements.txt
```

Tkinter is included with standard Windows and macOS Python installers. On Debian or Ubuntu:

```bash
sudo apt install python3-tk
```

Windows uses built-in DPAPI for credential encryption and does not require `cryptography`.

## Run

Desktop application:

```bash
python exabeam-replay.py
```

Windows:

```bat
python exabeam-replay.py
```

CLI help:

```bash
python cli.py --help
```

## Basic use

1. Choose **Paste logs** or **Upload sample**.
2. Select and configure a destination.
3. Use **Test connection** to verify network connectivity.
4. Set the number of passes and interval under **Control**.
5. Choose whether to save a run report.
6. Start the replay and confirm ingestion in Exabeam Search or Live Tail.

## Destination behavior

| Destination | Replay behavior |
|---|---|
| Webhook Collector | Sends each source record as an `application/octet-stream` POST body. |
| Syslog UDP | Sends each physical source record as one datagram. Records larger than 1,024 bytes are rejected. |
| Syslog TCP | Uses one persistent connection and RFC 6587 octet-counting framing. |
| Syslog TLS | Uses RFC 6587 octet-counting framing over TLS. Certificate verification and a custom CA are supported. |

### Why TCP/TLS use octet counting

A TCP log can legitimately begin with digits followed by a space, such as `07 27 2026 ...`. Some collectors interpret those first digits as an RFC 6587 length field. That can truncate the event—for example, `07 ` can be interpreted as a seven-byte message length.

Exabeam Replay prevents this ambiguity by explicitly sending:

```text
<message-byte-length><space><complete-message-bytes>
```

The collector removes the transport length prefix and receives the complete original message. The prefix is transport framing and is not part of the log message.

## Saved destination settings

Enable **Save destination for future sessions** to store destination configuration in `destination.json`. The Webhook Bearer token is encrypted before it is written. Unchecking the option deletes the saved file.

Locations:

**Windows**

```text
%APPDATA%\exabeam-replay\destination.json
```

Usually:

```text
C:\Users\<username>\AppData\Roaming\exabeam-replay\destination.json
```

**macOS**

```text
~/Library/Application Support/exabeam-replay/destination.json
```

**Linux**

```text
${XDG_CONFIG_HOME:-~/.config}/exabeam-replay/destination.json
```

Windows encrypts the token with current-user DPAPI. macOS and Linux use authenticated encryption derived for the current user and machine. No plaintext token or standalone plaintext key file is created.

## Reports

Under **Control > Evidence**, enable **Save run reports to the reports folder** to write JSON reports to `reports/`. The option is disabled by default; when it is unchecked, no report file is created.

## Build executables

```bash
python -m pip install "pyinstaller>=6.0"
python build.py
```

Build output is written to `dist/`.

## Troubleshooting

- **TCP/TLS connects but no event appears:** verify protocol, host, port, firewall rules, and that the collector accepts RFC 6587 octet-counted Syslog.
- **UDP replay fails:** keep each record at or below 1,024 bytes and verify the listener protocol.
- **TLS validation fails:** use the certificate hostname and the CA that signed the collector certificate.
- **Webhook returns a non-2xx response:** verify the RAW collector URL and Bearer token.
- **Saved token cannot be decrypted:** delete or uncheck the saved destination and save it again under the current user account.
- **`ModuleNotFoundError: cryptography` on macOS/Linux:** run `python -m pip install -r requirements.txt`. Windows does not require it.

## To do

- Add an optional TCP/TLS framing selector for collectors that require newline-delimited Syslog.
- Add automated parser-result verification against an Exabeam tenant.
- Add source-file snapshotting to guard against files changing during a replay.
- Add a run-history view and report comparison.
- Add signed release artifacts and automated cross-platform builds.
- Expand automated tests on Windows, macOS, and Linux.

## Security

- Replay logs only to systems you are authorized to test.
- Saved Webhook tokens are encrypted and excluded from reports.
- TLS certificate verification is enabled by default.
- Connection tests do not send source-log content.
- Automatic application-level retries are disabled to reduce duplicate-event risk.

## Project layout

```text
exabeam-replay/
├── assets/
├── exabeam-replay.py
├── credential_store.py
├── replay_core.py
├── cli.py
├── requirements.txt
├── pyproject.toml
├── build.py
├── README.md
├── LICENSE
└── NOTICE
```

## License

Apache License 2.0. See `LICENSE`.
