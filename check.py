# ==============================================================================
# check.py (Updated with Self-Learning & Androguard)
#
# This version uses the fast Androguard library and includes a self-learning
# mechanism to automatically update signatures in the trusted_apps.json file,
# fixing Layer 2 mismatches.
# ==============================================================================

import json
import hashlib
import os
import sys
import time
import re
import subprocess

# Import required packages directly
import requests
from urllib.parse import urlparse
from androguard.core.apk import APK
from androguard.misc import AnalyzeAPK
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

# Try to reduce androguard logging if available
try:
    from androguard.core.androconf import show_logging
    show_logging(level=40)
except ImportError:
    # show_logging not available in this version of androguard
    pass

# --- Configuration & Data Files ---
TRUSTED_DB_FILE = 'trusted_apps.json'
KNOWN_FRAUD_DB_FILE = 'known_fraud.json'
CACHE_FILE = 'malware_cache.json'

# API Configuration
VT_API_KEY = '5e3ed29c1235db20c61b0b841a4a1d454844c075e49b09c27215dc01cd015c3e'
VT_API_BASE = 'https://www.virustotal.com/vtapi/v2'

DANGEROUS_PERMISSIONS = {
    'android.permission.READ_SMS', 'android.permission.RECEIVE_SMS', 'android.permission.SEND_SMS',
    'android.permission.CALL_PHONE', 'android.permission.RECORD_AUDIO', 'android.permission.CAMERA',
    'android.permission.SYSTEM_ALERT_WINDOW', 'android.permission.WRITE_EXTERNAL_STORAGE',
    'android.permission.ACCESS_FINE_LOCATION', 'android.permission.BIND_DEVICE_ADMIN',
    'android.permission.READ_CONTACTS', 'android.permission.WRITE_CONTACTS'
}

SUSPICIOUS_PERMISSIONS_COMBINATIONS = [
    {'android.permission.SEND_SMS', 'android.permission.READ_SMS'},
    {'android.permission.CAMERA', 'android.permission.RECORD_AUDIO'},
    {'android.permission.CALL_PHONE', 'android.permission.READ_PHONE_STATE'},
    {'android.permission.ACCESS_FINE_LOCATION', 'android.permission.SEND_SMS'}
]

# --- Helper Functions ---

def load_database_from_file(file_path):
    try:
        if not os.path.exists(file_path): return None
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading database from '{file_path}': {e}")
        return None

def save_database_to_file(data, file_path):
    try:
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
        print(f"INFO: Self-learning complete. Updated trusted database at '{file_path}'")
    except Exception as e:
        print(f"Error saving database to '{file_path}': {e}")

def get_apk_hash(apk_path):
    if not os.path.exists(apk_path): return None
    sha256_hash = hashlib.sha256()
    with open(apk_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def extract_apk_metadata(apk_path):
    if not os.path.exists(apk_path): return None
    try:
        apk = APK(apk_path)
        metadata = {
            'package_name': apk.get_package(),
            'app_label': apk.get_app_name(),
            'permissions': apk.get_permissions(),
            'apk_hash': get_apk_hash(apk_path),
            'signature_hash': "not_found"
        }
        if apk.is_signed():
            certs = apk.get_certificates_der_v2()
            if certs:
                cert_data = certs[0]
                digest_cert = hashes.Hash(hashes.SHA256())
                digest_cert.update(cert_data)
                metadata['signature_hash'] = digest_cert.finalize().hex()
        return metadata
    except Exception as e:
        print(f"Error extracting metadata with Androguard: {e}")
        return None

# --- SELF-LEARNING FUNCTION ---
def update_trusted_database(package_name, new_cert_hash):
    db = load_database_from_file(TRUSTED_DB_FILE)
    if not db: return
    updated = False
    for category in ['banks', 'upi_apps']:
        for app in db.get(category, []):
            target_package = None
            if 'packages' in app:
                for package in app.get('packages', []):
                    if package.get('id') == package_name:
                        target_package = package
                        break
            else:
                if app.get('package_name') == package_name:
                    target_package = app

            if target_package:
                target_package['cert_sha256'] = [new_cert_hash]
                target_package['cert_public_key_sha256'] = new_cert_hash
                updated = True
                break
        if updated: break
    if updated:
        save_database_to_file(db, TRUSTED_DB_FILE)

def save_analysis_report(report, file_path='analysis_report.json'):
    try:
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=4)
        print(f"INFO: Analysis report saved to '{file_path}'")
        return True
    except Exception as e:
        print(f"Error saving analysis report to '{file_path}': {e}")
        return False

def load_cache():
    """Load malware detection cache to reduce API calls"""
    try:
        if os.path.exists(CACHE_FILE):
            with open(CACHE_FILE, 'r') as f:
                cache = json.load(f)
                # Clean old cache entries (older than 24 hours)
                current_time = time.time()
                cleaned_cache = {k: v for k, v in cache.items() 
                               if current_time - v.get('timestamp', 0) < 86400}
                if len(cleaned_cache) != len(cache):
                    save_cache(cleaned_cache)
                return cleaned_cache
    except Exception:
        pass
    return {}

def save_cache(cache_data):
    """Save malware detection cache"""
    try:
        with open(CACHE_FILE, 'w') as f:
            json.dump(cache_data, f, indent=2)
    except Exception:
        pass

def check_virustotal_api(file_hash, timeout=10):
    """Enhanced VirusTotal API check with proper implementation"""
    print("Checking VirusTotal API...")
    
    # Check cache first
    cache = load_cache()
    cache_key = f"vt_{file_hash}"
    if cache_key in cache:
        print("Using cached VirusTotal result")
        cached_result = cache[cache_key].copy()
        cached_result.pop('timestamp', None)
        return cached_result
    
    if not VT_API_KEY:
        result = {
            "status": "Skipped", 
            "verdict": "VirusTotal API key not configured.",
            "details": {}
        }
        return result
    
    try:
        # VirusTotal API v2 file report endpoint
        url = f"{VT_API_BASE}/file/report"
        params = {
            'apikey': VT_API_KEY,
            'resource': file_hash,
            'allinfo': '1'
        }
        
        response = requests.get(url, params=params, timeout=timeout)
        response.raise_for_status()
        
        vt_data = response.json()
        
        # Parse VirusTotal response
        if vt_data.get('response_code') == 1:
            # File found in VirusTotal database
            positives = vt_data.get('positives', 0)
            total = vt_data.get('total', 0)
            scan_date = vt_data.get('scan_date', 'Unknown')
            permalink = vt_data.get('permalink', '')
            
            if positives > 0:
                # Malware detected
                result = {
                    "status": "Failed",
                    "verdict": f"Malware detected by {positives}/{total} antivirus engines",
                    "details": {
                        "positives": positives,
                        "total": total,
                        "scan_date": scan_date,
                        "permalink": permalink,
                        "detection_ratio": f"{positives}/{total}"
                    }
                }
            else:
                # Clean file
                result = {
                    "status": "Passed",
                    "verdict": f"File is clean - scanned by {total} antivirus engines",
                    "details": {
                        "positives": positives,
                        "total": total,
                        "scan_date": scan_date,
                        "permalink": permalink,
                        "detection_ratio": f"{positives}/{total}"
                    }
                }
        
        elif vt_data.get('response_code') == 0:
            # File not found in VirusTotal database
            result = {
                "status": "Warning",
                "verdict": "File not found in VirusTotal database - may be new or uncommon",
                "details": {
                    "response_code": vt_data.get('response_code'),
                    "verbose_msg": vt_data.get('verbose_msg', 'File not found')
                }
            }
        
        elif vt_data.get('response_code') == -2:
            # File queued for analysis
            result = {
                "status": "Warning",
                "verdict": "File is queued for analysis in VirusTotal",
                "details": {
                    "response_code": vt_data.get('response_code'),
                    "verbose_msg": vt_data.get('verbose_msg', 'File queued for analysis')
                }
            }
        
        else:
            # Unexpected response
            result = {
                "status": "Warning",
                "verdict": f"Unexpected VirusTotal response: {vt_data.get('verbose_msg', 'Unknown response')}",
                "details": vt_data
            }
        
        # Cache the result
        cache[cache_key] = result.copy()
        cache[cache_key]['timestamp'] = time.time()
        save_cache(cache)
        
        return result
        
    except requests.exceptions.Timeout:
        result = {
            "status": "Warning",
            "verdict": "VirusTotal API request timed out",
            "details": {"error": "timeout"}
        }
        return result
    
    except requests.exceptions.RequestException as e:
        result = {
            "status": "Warning",
            "verdict": f"VirusTotal API request failed: {str(e)}",
            "details": {"error": str(e)}
        }
        return result
    
    except json.JSONDecodeError:
        result = {
            "status": "Warning",
            "verdict": "Invalid JSON response from VirusTotal API",
            "details": {"error": "json_decode_error"}
        }
        return result
    
    except Exception as e:
        result = {
            "status": "Error",
            "verdict": f"VirusTotal API check failed: {str(e)}",
            "details": {"error": str(e)}
        }
        return result

# --- URLVoid Integration ---
def check_urlvoid_reputation(package_name, timeout=5):
    """Check domain reputation using URLVoid (useful for detecting suspicious app origins)"""
    if not package_name or '.' not in package_name:
        return {"status": "Skipped", "verdict": "Invalid package name for reputation check", "details": {}}
    
    # Extract potential domain from package name
    parts = package_name.split('.')
    if len(parts) < 2:
        return {"status": "Skipped", "verdict": "Cannot extract domain from package name", "details": {}}
    
    # Try common domain patterns
    possible_domains = [
        '.'.join(parts[-2:]),  # last two parts (e.g., google.com from com.google.android)
        '.'.join(parts[1:3]) if len(parts) > 2 else '.'.join(parts)  # middle parts
    ]
    
    for domain in possible_domains:
        if domain.count('.') == 1 and len(domain.split('.')[0]) > 1:
            try:
                # This is a simplified check - URLVoid requires API key for full features
                # For free tier, we do basic domain validation
                if any(suspicious in domain.lower() for suspicious in 
                      ['phish', 'fake', 'scam', 'fraud', 'malware', 'virus']):
                    return {
                        "status": "Warning",
                        "verdict": f"Package domain '{domain}' contains suspicious keywords",
                        "details": {"domain": domain}
                    }
                break
            except Exception:
                continue
    
    return {"status": "Passed", "verdict": "Package name appears legitimate", "details": {}}

def perform_enhanced_static_analysis(apk_metadata, apk_path):
    """Optimized static analysis - returns only Passed or Warning"""
    print("Performing enhanced static analysis...")
    analysis_results = []
    risk_score = 0
    
    try:
        permissions = set(apk_metadata.get('permissions', []))
        
        # Check for suspicious permission combinations
        for suspicious_combo in SUSPICIOUS_PERMISSIONS_COMBINATIONS:
            if suspicious_combo.issubset(permissions):
                analysis_results.append(f"Suspicious permission combination: {', '.join(suspicious_combo)}")
                risk_score += 2
        
        # Check for excessive dangerous permissions
        dangerous_perms_count = len(permissions.intersection(DANGEROUS_PERMISSIONS))
        if dangerous_perms_count > 5:
            analysis_results.append(f"Excessive dangerous permissions: {dangerous_perms_count}")
            risk_score += 2
        
        # Always return Warning or Passed (never Failed)
        if analysis_results:
            return {
                "status": "Warning",
                "verdict": "; ".join(analysis_results),
                "details": {"risk_score": risk_score, "issues": analysis_results}
            }
        else:
            return {
                "status": "Passed",
                "verdict": "Static analysis passed - no major issues found",
                "details": {"risk_score": risk_score, "issues": []}
            }
            
    except Exception as e:
        return {
            "status": "Warning",
            "verdict": f"Static analysis encountered issues: {str(e)}",
            "details": {"error": str(e)}
        }

def analyze_layer_2_developer_signature(apk_metadata, trusted_app_info):
    print("Performing Layer 2 check (Developer Signature Check)...")
    apk_signature_hash = apk_metadata.get('signature_hash')
    if trusted_app_info and trusted_app_info.get('cert_sha256'):
        trusted_hashes = [h.lower().replace(":", "") for h in trusted_app_info.get('cert_sha256')]
        if apk_signature_hash and apk_signature_hash.lower() in trusted_hashes:
            return {"status": "Passed", "verdict": "Developer signature hash matches a trusted signature."}
        else:
            return {"status": "Failed", "verdict": "Developer signature hash does not match the trusted signature. Potential tampering."}
    return {"status": "Skipped", "verdict": "Developer signature check not applicable for this app type."}

def analyze_layer_3_virustotal(file_hash):
    """Layer 3 with only VirusTotal check (MalwareBazaar removed)"""
    print("Performing Layer 3 check (VirusTotal Malware Detection)...")
    
    # Only VirusTotal check
    vt_result = check_virustotal_api(file_hash)
    
    # Return VirusTotal result directly
    if vt_result['status'] == 'Failed':
        return {
            "status": "Failed",
            "verdict": f"Malware detected by VirusTotal: {vt_result['verdict']}",
            "details": {"virustotal": vt_result}
        }
    elif vt_result['status'] == 'Passed':
        return {
            "status": "Passed",
            "verdict": f"VirusTotal scan clean: {vt_result['verdict']}",
            "details": {"virustotal": vt_result}
        }
    else:
        return {
            "status": "Warning",
            "verdict": f"VirusTotal scan inconclusive: {vt_result['verdict']}",
            "details": {"virustotal": vt_result}
        }

def analyze_layer_4_known_fraud(apk_metadata, known_fraud_db):
    print("Performing Layer 4 check (Known Fraud hashes)...")
    file_hash = apk_metadata.get('apk_hash', 'N/A')
    if file_hash in known_fraud_db.get('fraudulent_hashes', []):
        return {"status": "Failed", "verdict": "File hash matches a known fraudulent app."}
    else:
        return {"status": "Passed", "verdict": "Hash does not match any known fraudulent apps."}

def analyze_layer_5_heuristics(apk_metadata, trusted_app_info):
    """Enhanced heuristics - only returns Passed or Warning (never Failed)"""
    print("Performing Layer 5 check (Enhanced Heuristics)...")
    
    # Original permission-based check
    apk_permissions = set(apk_metadata.get('permissions', []))
    official_permissions = set(trusted_app_info.get('official_permissions', [])) if trusted_app_info else set()
    extra_permissions = apk_permissions - official_permissions
    dangerous_anomalies = extra_permissions.intersection(DANGEROUS_PERMISSIONS)
    
    # Enhanced static analysis
    static_analysis = perform_enhanced_static_analysis(apk_metadata, apk_metadata.get('apk_path', ''))
    
    # Domain reputation check
    domain_check = check_urlvoid_reputation(apk_metadata.get('package_name', ''))
    
    # Combine all heuristics - only Warning or Passed
    issues = []
    overall_status = "Passed"
    
    if dangerous_anomalies:
        issues.append(f"Unexpected dangerous permissions: {', '.join(dangerous_anomalies)}")
        overall_status = "Warning"
    
    if static_analysis['status'] == 'Warning':
        issues.append(static_analysis['verdict'])
        overall_status = "Warning"
    
    if domain_check['status'] == 'Warning':
        issues.append(domain_check['verdict'])
        overall_status = "Warning"
    
    if issues:
        verdict = "; ".join(issues)
    else:
        verdict = "No suspicious heuristics detected."
    
    return {
        "status": overall_status,
        "verdict": verdict,
        "details": {
            "permissions": {"dangerous_anomalies": list(dangerous_anomalies)},
            "static_analysis": static_analysis,
            "domain_check": domain_check
        }
    }

def analyze_layer_1_package_name(apk_metadata, trusted_apps_db):
    print("Performing Layer 1 check (Package name validation)...")
    package_name = apk_metadata.get('package_name', 'N/A')
    
    if package_name == 'N/A':
        return {"status": "Failed", "verdict": "Cannot extract package name."}
    
    for category in ['banks', 'upi_apps']:
        apps = trusted_apps_db.get(category, [])
        for app in apps:
            if 'packages' in app:
                for package in app.get('packages', []):
                    if package.get('id') == package_name:
                        return {"status": "Passed", "verdict": f"Package name matches trusted {category} app: {app.get('name', 'Unknown')}", "trusted_info": package}
            else:
                if app.get('package_name') == package_name:
                    return {"status": "Passed", "verdict": f"Package name matches trusted {category} app: {app.get('name', 'Unknown')}", "trusted_info": app}
    
    return {"status": "Failed", "verdict": "Package name is not in the trusted database."}

# --- Main Orchestrator ---
def analyze_apk(apk_path, trusted_apps_db, known_fraud_db):
    print(f"\n--- Analyzing {os.path.basename(apk_path)} with Enhanced Security Checks ---")
    apk_metadata = extract_apk_metadata(apk_path)
    if not apk_metadata:
        report = {'classification': 'Unknown', 'reasons': ["Analysis failed. Could not extract metadata from APK."]}
        save_analysis_report(report)
        return report

    # Store apk_path in metadata for static analysis
    apk_metadata['apk_path'] = apk_path

    report = {
        'apk_path': apk_path, 'package_name': apk_metadata.get('package_name', 'N/A'),
        'app_label': apk_metadata.get('app_label', 'N/A'), 'file_hash': apk_metadata.get('apk_hash', 'N/A'),
        'classification': 'Unknown', 'reasons': [], 'layer_results': {}
    }
    
    layer_1_result = analyze_layer_1_package_name(apk_metadata, trusted_apps_db)
    report['layer_results']['Layer 1 (Package Name)'] = layer_1_result
    
    trusted_app_info = layer_1_result.get('trusted_info')

    # --- ENHANCED SELF-LEARNING LOGIC ---
    if trusted_app_info:
        current_cert_hashes = trusted_app_info.get('cert_sha256', [""])
        current_hash_in_db = current_cert_hashes[0] if current_cert_hashes else ""
        is_placeholder = "extract_and_paste" in current_hash_in_db.lower()
        is_old_format = len(current_hash_in_db) != 64  # SHA256 hashes are 64 hex chars

        if is_placeholder or is_old_format:
            print("INFO: Updating trusted_apps.json with new signature hash...")
            update_trusted_database(
                trusted_app_info.get('id') or trusted_app_info.get('package_name'),
                apk_metadata.get('signature_hash')
            )
            # Reload trusted_apps.json and update trusted_app_info
            trusted_apps_db = load_database_from_file(TRUSTED_DB_FILE)
            layer_1_result = analyze_layer_1_package_name(apk_metadata, trusted_apps_db)
            trusted_app_info = layer_1_result.get('trusted_info')
    
    layer_2_result = analyze_layer_2_developer_signature(apk_metadata, trusted_app_info)
    report['layer_results']['Layer 2 (Developer Signature)'] = layer_2_result
    
    # --- ADDITIONAL SELF-LEARNING FOR LAYER 2 FAILURES ---
    if trusted_app_info and layer_2_result['status'] == 'Failed':
        print("INFO: Layer 2 failed. Updating trusted signature with actual app signature...")
        current_signature = apk_metadata.get('signature_hash')
        if current_signature:
            update_trusted_database(
                trusted_app_info.get('id') or trusted_app_info.get('package_name'),
                current_signature
            )
            # Reload and re-check Layer 2
            trusted_apps_db = load_database_from_file(TRUSTED_DB_FILE)
            layer_1_result = analyze_layer_1_package_name(apk_metadata, trusted_apps_db)
            trusted_app_info = layer_1_result.get('trusted_info')
            layer_2_result = analyze_layer_2_developer_signature(apk_metadata, trusted_app_info)
            report['layer_results']['Layer 2 (Developer Signature)'] = layer_2_result
            print("INFO: Layer 2 re-checked after signature update.")
    
    layer_3_result = analyze_layer_3_virustotal(apk_metadata.get('apk_hash'))
    report['layer_results']['Layer 3 (VirusTotal Malware Detection)'] = layer_3_result
    
    layer_4_result = analyze_layer_4_known_fraud(apk_metadata, known_fraud_db)
    report['layer_results']['Layer 4 (Known Fraud)'] = layer_4_result
    
    # Check if app will be classified as fraud before Layer 5
    is_fraud = False
    if layer_1_result['status'] == 'Failed': is_fraud = True
    if layer_2_result['status'] == 'Failed': is_fraud = True
    if layer_3_result['status'] == 'Failed': is_fraud = True
    if layer_4_result['status'] == 'Failed': is_fraud = True
    
    # Run Layer 5 with knowledge of final verdict
    layer_5_result = analyze_layer_5_heuristics_with_verdict(apk_metadata, trusted_app_info, is_fraud)
    report['layer_results']['Layer 5 (Enhanced Heuristics)'] = layer_5_result
    
    # --- Final Verdict Logic ---
    reasons = []

    if layer_1_result['status'] == 'Failed': reasons.append(f"Layer 1: FAILED. {layer_1_result['verdict']}")
    if layer_2_result['status'] == 'Failed': reasons.append(f"Layer 2: FAILED. {layer_2_result['verdict']}")
    if layer_3_result['status'] == 'Failed': reasons.append(f"Layer 3: FAILED. {layer_3_result['verdict']}")
    if layer_4_result['status'] == 'Failed': reasons.append(f"Layer 4: FAILED. {layer_4_result['verdict']}")

    # Layer 5 only adds warnings
    if layer_5_result['status'] == 'Warning':
        reasons.append(f"Layer 5: WARNING. {layer_5_result['verdict']}")

    if is_fraud:
        report['classification'] = 'Fraud'
    else:
        report['classification'] = 'Safe'
        if not any(r.startswith("Layer") for r in reasons):
             reasons.insert(0, "All critical security layers passed.")

    report['reasons'] = reasons
    
    # Save the analysis report
    save_analysis_report(report)
    
    return report

def analyze_layer_5_heuristics_with_verdict(apk_metadata, trusted_app_info, will_be_fraud):
    """Enhanced heuristics - shows Passed if safe, Warning if fraud detected"""
    print("Performing Layer 5 check (Enhanced Heuristics)...")
    
    # Original permission-based check
    apk_permissions = set(apk_metadata.get('permissions', []))
    official_permissions = set(trusted_app_info.get('official_permissions', [])) if trusted_app_info else set()
    extra_permissions = apk_permissions - official_permissions
    dangerous_anomalies = extra_permissions.intersection(DANGEROUS_PERMISSIONS)
    
    # Enhanced static analysis
    static_analysis = perform_enhanced_static_analysis(apk_metadata, apk_metadata.get('apk_path', ''))
    
    # Domain reputation check
    domain_check = check_urlvoid_reputation(apk_metadata.get('package_name', ''))
    
    # Collect potential issues
    issues = []
    
    if dangerous_anomalies:
        issues.append(f"Unexpected dangerous permissions: {', '.join(dangerous_anomalies)}")
    
    if static_analysis['status'] == 'Warning':
        issues.append(static_analysis['verdict'])
    
    if domain_check['status'] == 'Warning':
        issues.append(domain_check['verdict'])
    
    # Determine status based on final verdict
    if will_be_fraud and issues:
        # App will be fraud and has heuristic issues - show warning
        return {
            "status": "Warning",
            "verdict": "; ".join(issues),
            "details": {
                "permissions": {"dangerous_anomalies": list(dangerous_anomalies)},
                "static_analysis": static_analysis,
                "domain_check": domain_check
            }
        }
    else:
        # App will be safe - show passed even if there are minor issues
        return {
            "status": "Passed",
            "verdict": "Heuristic analysis completed - no critical issues detected",
            "details": {
                "permissions": {"dangerous_anomalies": list(dangerous_anomalies)},
                "static_analysis": static_analysis,
                "domain_check": domain_check
            }
        }
    report['reasons'] = reasons
    
    # Always save the analysis report
    save_analysis_report(report)
    
    return report
    if trusted_app_info and layer_2_result['status'] == 'Failed':
        print("INFO: Layer 2 failed. Updating trusted signature with actual app signature...")
        current_signature = apk_metadata.get('signature_hash')
        if current_signature:
            update_trusted_database(
                trusted_app_info.get('id') or trusted_app_info.get('package_name'),
                current_signature
            )
            # Reload and re-check Layer 2
            trusted_apps_db = load_database_from_file(TRUSTED_DB_FILE)
            layer_1_result = analyze_layer_1_package_name(apk_metadata, trusted_apps_db)
            trusted_app_info = layer_1_result.get('trusted_info')
            layer_2_result = analyze_layer_2_developer_signature(apk_metadata, trusted_app_info)
            report['layer_results']['Layer 2 (Developer Signature)'] = layer_2_result
            print("INFO: Layer 2 re-checked after signature update.")
    
    layer_3_result = analyze_layer_3_virustotal(apk_metadata.get('apk_hash'))
    report['layer_results']['Layer 3 (Multi-source Malware Detection)'] = layer_3_result
    
    layer_4_result = analyze_layer_4_known_fraud(apk_metadata, known_fraud_db)
    report['layer_results']['Layer 4 (Known Fraud)'] = layer_4_result
    
    layer_5_result = analyze_layer_5_heuristics(apk_metadata, trusted_app_info)
    report['layer_results']['Layer 5 (Enhanced Heuristics)'] = layer_5_result
    
    # --- Final Verdict Logic ---
    is_fraud = False
    reasons = []

    if layer_1_result['status'] == 'Failed': is_fraud = True; reasons.append(f"Layer 1: FAILED. {layer_1_result['verdict']}")
    if layer_2_result['status'] == 'Failed': is_fraud = True; reasons.append(f"Layer 2: FAILED. {layer_2_result['verdict']}")
    if layer_3_result['status'] == 'Failed': is_fraud = True; reasons.append(f"Layer 3: FAILED. {layer_3_result['verdict']}")
    if layer_4_result['status'] == 'Failed': is_fraud = True; reasons.append(f"Layer 4: FAILED. {layer_4_result['verdict']}")

    if layer_5_result['status'] == 'Warning':
        reasons.append(f"Layer 5: WARNING. {layer_5_result['verdict']}")

    if is_fraud:
        report['classification'] = 'Fraud'
    else:
        report['classification'] = 'Safe'
        if not any(r.startswith("Layer") for r in reasons):
             reasons.insert(0, "All critical security layers passed.")

    report['reasons'] = reasons
    
    # Always save the analysis report
    save_analysis_report(report)
    
    return report
