#!/usr/bin/env python3
"""Extract static APK metadata and API features; does not execute the APK."""

import argparse
import hashlib
import json
import sys
from pathlib import Path

from androguard.misc import AnalyzeAPK
from loguru import logger

SUSPICIOUS = {
    "runtime_exec": ("Ljava/lang/Runtime;", "exec"),
    "dex_loader": ("Ldalvik/system/DexClassLoader;", "<init>"),
    "reflection": ("Ljava/lang/reflect/Method;", "invoke"),
    "send_sms": ("Landroid/telephony/SmsManager;", "send"),
    "installed_pkgs": (
        "Landroid/content/pm/PackageManager;", "getInstalledPackages"
    ),
}


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def extract(apk_path):
    path = Path(apk_path).expanduser().resolve()
    if not path.is_file():
        raise FileNotFoundError(f"APK file not found: {path}")

    apk, dex_files, dx = AnalyzeAPK(str(path))
    if not apk.is_valid_APK():
        raise ValueError(f"Invalid APK manifest: {path}")

    # Preserve the original matching-method count.
    hits = {feature: 0 for feature in SUSPICIOUS}
    call_sites = {feature: 0 for feature in SUSPICIOUS}

    for method in dx.get_methods():
        m = method.get_method()
        owner, name = m.get_class_name(), m.get_name()
        for feature, (klass, token) in SUSPICIOUS.items():
            # Substring matching intentionally preserves the original rules.
            if owner == klass and token in name:
                hits[feature] += 1
                call_sites[feature] += len(method.get_xref_from())

    return {
        "file_name": path.name,
        "sha256": sha256(path),
        "size_bytes": path.stat().st_size,
        "package_name": apk.get_package(),
        "version_name": apk.get_androidversion_name(),
        "version_code": apk.get_androidversion_code(),
        "min_sdk": apk.get_min_sdk_version(),
        "target_sdk": apk.get_target_sdk_version(),
        "dex_count": len(dex_files),
        "permissions": sorted(set(apk.get_permissions())),
        "activities": sorted(set(apk.get_activities())),
        "services": sorted(set(apk.get_services())),
        "receivers": sorted(set(apk.get_receivers())),
        "providers": sorted(set(apk.get_providers())),
        "suspicious_method_counts": hits,
        "suspicious_call_site_counts": call_sites,
        "suspicious_api_present": {
            feature: int(count > 0) for feature, count in call_sites.items()
        },
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("apk", type=Path, help="Path to the APK")
    parser.add_argument("-o", "--output", type=Path, help="Save JSON to this file")
    args = parser.parse_args()

    # Keep Androguard's verbose logs out of the JSON output.
    logger.disable("androguard")

    try:
        if args.output and args.output.expanduser().resolve() == args.apk.expanduser().resolve():
            raise ValueError("Output must not overwrite the input APK")
        result = extract(args.apk)
        output = json.dumps(result, indent=2, ensure_ascii=False)
        if args.output:
            destination = args.output.expanduser()
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(output + "\n", encoding="utf-8")
            print(f"Saved: {destination}", file=sys.stderr)
        else:
            print(output)
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
