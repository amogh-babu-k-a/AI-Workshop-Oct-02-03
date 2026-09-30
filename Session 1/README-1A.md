# APK Feature Extractor

Run `apk_features.py` to extract static metadata and selected API features from an Android APK and save the results as JSON. The script does not install or execute the APK; no Android device or emulator is required.

## Prerequisites

- Python 3 with `pip` and virtual environment support.
- The supplied `apk_features.py` script.
- An APK file to analyze.
- Internet access to install Python dependencies.

## 1. Prepare your folder

Create a folder named `apk-analysis` and place `apk_features.py` and your APK inside it. The commands below use `sample.apk` as an example; replace it with your actual filename.

Open Terminal or Command Prompt and navigate to the folder:

```bash
cd "path/to/apk-analysis"
```

Replace `path/to/apk-analysis` with the actual folder path.

## 2. Create and activate a virtual environment

### Windows — Command Prompt

```bat
python -m venv .venv
.venv\Scripts\activate.bat
```

If Windows recognizes `py` instead of `python`, use `py -m venv .venv` to create the environment.

### Windows — PowerShell

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

If PowerShell blocks activation, use Command Prompt with the commands above, or run the environment's Python directly as shown under Troubleshooting.

### macOS/Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
```

After activation, use `python` for the remaining commands. Activate the environment again whenever you open a new terminal session.

## 3. Install dependencies

```bash
python -m pip install --upgrade pip
python -m pip install androguard loguru
```

## 4. Run the script

Analyze one APK and save its results:

```bash
python apk_features.py sample.apk -o features.json
```

On success, the script prints:

```text
Saved: features.json
```

For a filename containing spaces, use quotes:

```bash
python apk_features.py "My Application.apk" -o features.json
```

You can also choose an output subfolder:

```bash
python apk_features.py sample.apk -o results/features.json
```

The script creates missing output folders. An existing output file is overwritten, so use a different filename to retain previous results.

To print JSON directly in the terminal without saving it:

```bash
python apk_features.py sample.apk
```

To display command-line help:

```bash
python apk_features.py --help
```

## 5. View the results

Open `features.json` in VS Code or any text editor. To display it in the terminal:

```bash
python -m json.tool features.json
```

The JSON includes:

| Field | Description |
| --- | --- |
| `file_name`, `sha256`, `size_bytes` | APK filename, SHA-256 hash, and size |
| `package_name`, `version_name`, `version_code` | Application package and version metadata |
| `min_sdk`, `target_sdk` | Manifest SDK declarations |
| `dex_count` | Number of analyzed DEX files |
| `permissions` | Declared permissions |
| `activities`, `services`, `receivers`, `providers` | Declared application components |
| `suspicious_method_counts` | Number of matching method entries for each rule |
| `suspicious_call_site_counts` | Number of static incoming call references for each rule |
| `suspicious_api_present` | `1` when at least one matching static call reference exists; otherwise `0` |

The rules cover `runtime_exec`, `dex_loader`, `reflection`, `send_sms`, and `installed_pkgs`. Matching preserves the original class-name and method-substring rules; for example, `send_sms` matches any method on `SmsManager` containing `send`.

These are static indicators, not a malware verdict or counts of runtime executions. A zero count does not prove an API is never used, particularly when behavior is hidden behind reflection, native code, or dynamically loaded code.

## Troubleshooting

| Problem | Action |
| --- | --- |
| `python` is not recognized | Verify that Python is installed and available in your terminal. On Windows, try `py` to create the environment; on macOS/Linux, use `python3`. |
| `No module named androguard` or `loguru` | Activate the environment and run `python -m pip install androguard loguru` again. |
| `APK file not found` | Check the APK filename and path. Quote paths containing spaces. |
| Python cannot open `apk_features.py` | Navigate to the folder containing the script, or supply its full path. |
| Invalid APK or parsing error | Confirm the input is a complete APK. Preserve the error message for diagnosis. |
| Output write fails | Choose a writable output folder and check available disk space. |

Activation is optional if you call the virtual environment's Python directly.

Windows:

```bat
.venv\Scripts\python.exe -m pip install androguard loguru
.venv\Scripts\python.exe apk_features.py sample.apk -o features.json
```

macOS/Linux:

```bash
.venv/bin/python -m pip install androguard loguru
.venv/bin/python apk_features.py sample.apk -o features.json
```

## 6. Exit the virtual environment

If you activated the environment, run:

```bash
deactivate
```

## Validation status

The supplied script passed Python syntax validation. End-to-end analysis has not been verified against a sample APK in this session.
