# Convert APK Features to a Schema Record and Flat Features

Convert the existing `features.json` produced by `apk_features.py` into:

- `record.json`: a structured record using the `apk-static-v1` schema.
- `flat_features.json`: a numeric feature dictionary with `perm::` and `api::` key prefixes.

This conversion reads the existing JSON. It does not analyze the APK again or recalculate its SHA-256 hash.

## Requirements

- Python 3.
- The `features.json` output from the previously supplied APK extraction script.
- The conversion script below, saved as `convert_features.py`.

The converter uses only Python's standard library (`json` and `pathlib`). No additional packages or Androguard installation are required for this step.

## 1. Save the conversion script

Save the following code in a file named `convert_features.py`:

```python
import json
from pathlib import Path


def convert_features(input_path):
    data = json.loads(
        Path(input_path).read_text(encoding="utf-8")
    )

    permissions = sorted(set(data["permissions"]))

    record = {
        "schema": "apk-static-v1",
        "sha256": data["sha256"],
        "package": data["package_name"],
        "min_sdk": data["min_sdk"],
        "target_sdk": data["target_sdk"],
        "permissions": permissions,
        "permission_count": len(permissions),
        "suspicious_api_counts": data["suspicious_method_counts"],
    }

    flat = {
        f"perm::{permission}": 1
        for permission in record["permissions"]
    }
    flat.update({
        f"api::{name}": count
        for name, count in record["suspicious_api_counts"].items()
    })

    return record, flat


if __name__ == "__main__":
    record, flat = convert_features("features.json")

    Path("record.json").write_text(
        json.dumps(record, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    Path("flat_features.json").write_text(
        json.dumps(flat, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    print("Saved: record.json")
    print("Saved: flat_features.json")
    print(json.dumps(flat, indent=2, sort_keys=True))
```

## 2. Prepare the input

Place `convert_features.py` and `features.json` in the same folder, for example `apk-analysis`.

The input must contain these keys:

```text
sha256
package_name
min_sdk
target_sdk
permissions
suspicious_method_counts
```

Use the original extractor's `features.json`, not a previously converted `record.json` or `flat_features.json`.

## 3. Run the converter

Open Terminal or Command Prompt and navigate to the folder containing both files:

```bash
cd "path/to/apk-analysis"
```

Replace the example path with your actual folder path.

### Windows

```bat
python convert_features.py
```

If Windows recognizes the Python launcher instead:

```bat
py convert_features.py
```

### macOS/Linux

```bash
python3 convert_features.py
```

If your existing virtual environment is active, you can also use `python convert_features.py`.

The script prints:

```text
Saved: record.json
Saved: flat_features.json
```

It then prints the flat feature dictionary. Both output files are written to your current working directory. Re-running the script overwrites them.

## 4. View the output

Open the files in VS Code or any text editor. Alternatively, use:

```bash
python -m json.tool record.json
python -m json.tool flat_features.json
```

Use `python3` instead of `python` on macOS/Linux if needed.

### Structured record mapping

| Output field | Source or calculation |
| --- | --- |
| `schema` | Constant value `apk-static-v1` |
| `sha256` | Copied from input `sha256` |
| `package` | Copied from input `package_name` |
| `min_sdk` | Copied from input `min_sdk` |
| `target_sdk` | Copied from input `target_sdk` |
| `permissions` | Sorted, deduplicated input permissions |
| `permission_count` | Number of unique permissions |
| `suspicious_api_counts` | Copied from input `suspicious_method_counts` by default |

SDK values retain the input representation, including strings or null values. Other extractor fields, such as components and file size, are not included in this schema.

### Flat feature example

The following values are illustrative, not results from your APK:

```json
{
  "api::dex_loader": 1,
  "api::installed_pkgs": 0,
  "api::reflection": 2,
  "api::runtime_exec": 1,
  "api::send_sms": 0,
  "perm::android.permission.ACCESS_NETWORK_STATE": 1,
  "perm::android.permission.INTERNET": 1
}
```

- `perm::<permission>` has value `1` when the permission is declared.
- `api::<feature>` holds the selected count, including zero values.
- Permissions absent from this APK are omitted from its dictionary.
- Package names, hashes, SDK values, and `permission_count` remain in `record.json`; they are not added to the flat dictionary by this script.

The flat output is ready for vectorization. It is a JSON dictionary, not yet a sparse matrix. A downstream vectorizer must establish consistent columns across APKs and treat missing permission features as zero.

## Choosing API count semantics

The default preserves the original extraction loop's meaning: the number of matching method entries.

```python
"suspicious_api_counts": data["suspicious_method_counts"],
```

To use static call-site counts from the extractor instead, replace that line with:

```python
"suspicious_api_counts": data["suspicious_call_site_counts"],
```

The alternate input field must exist. Use the same count definition for every APK in a dataset. Static call-site counts do not measure runtime execution frequency, and these features alone do not establish whether an APK is malicious.

## Using a different input filename

Change the call inside the main block:

```python
record, flat = convert_features("my_features.json")
```

This script does not accept command-line filename arguments. To retain outputs for multiple APKs, also change the two output filenames or run the converter in a separate folder for each APK.

## Troubleshooting

| Error or issue | Resolution |
| --- | --- |
| `FileNotFoundError` for `features.json` | Run from the folder containing the input, or change the input path in the main block. |
| Python cannot open `convert_features.py` | Check the script filename and current folder. Ensure it was not saved with a `.txt` extension. |
| `JSONDecodeError` | Ensure the input contains only valid JSON, without logs, Markdown fences, or incomplete content. |
| `KeyError` | Check that the input came from the original extractor and contains all required keys listed above. |
| `PermissionError` while saving | Run in a writable folder or change the output paths. |
| `python` is not recognized | Try `py` on Windows or `python3` on macOS/Linux, and verify Python is installed. |
