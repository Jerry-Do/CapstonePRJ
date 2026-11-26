import hashlib
import numpy as np
import struct 
import json
import subprocess
import os
import re
from scipy.stats import entropy
PATTERNS = {
    'url':       r'https?://[^\s"\'<>]{4,}',
    'ipv4':      r'\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b',
    'domain':    r'\b(?:[a-z0-9-]{1,63}\.)+(?:com|net|org|ru|cn|info|xyz|top|io|biz|onion)\b',
    'email':     r'[\w.+-]+@[\w-]+\.[\w.-]+',
    'win_path':  r'(?<![A-Za-z0-9])[A-Za-z]:\\(?:[\w .$()-]+\\)*[\w .$()-]{2,}',
    'unc_path':  r'\\\\[\w.$-]+\\',
    'registry':  r'(?:HKEY_[A-Z_]+|HK(?:LM|CU|CR))\\',
    'run_key':   r'(?i)CurrentVersion\\Run',
    'pdb':       r'(?i)\.pdb\b',
    'cmdline':   r'(?i)\b(?:cmd(?:\.exe)?\s*/c|powershell|rundll32|regsvr32|schtasks|wscript|mshta)\b',
    'api_inject':r'\b(?:VirtualAlloc(?:Ex)?|WriteProcessMemory|CreateRemoteThread|NtUnmapViewOfSection|SetWindowsHookEx[AW]?)\b',
    'api_net':   r'\b(?:InternetOpen[AW]?|URLDownloadToFile[AW]?|WinHttp\w+|socket|connect|recv|send)\b',
    'api_antidbg':r'\b(?:IsDebuggerPresent|CheckRemoteDebuggerPresent|NtQueryInformationProcess)\b',
    'base64':    r'^(?:[A-Za-z0-9+/]{4}){6,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$',
    'guid':      r'\{[0-9A-Fa-f]{8}-(?:[0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}\}',
    'hash_hex':  r'\b(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})\b',
    'btc_onion': r'\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b|\.onion\b',
}

COMPILED = {k: re.compile(v) for k, v in PATTERNS.items()}
max_length = 150
def CapaExtract(file):
    package = {}
    package["ATT&CK Tactic"] = {}
    package["MBC"] = {}
    package["CAPA"] = {}
    with open("test.txt", "w") as f:
        subprocess.run(
        [
            os.path.join(
                os.path.dirname(__file__),
                "capa.exe"
            ),
            file
        ],
        stdout=f,
        text=True
    )
    with open("test.txt", "r", encoding="utf-8") as f:
        line_found = False
        curr_section = ""
        curr_t = ""
        for line in f:
            if "ATT&CK Tactic" in line or "MBC Objective" in line or  "Capability" in line or line_found:#Detect start of feature
                if "ATT&CK Tactic" in line:
                    curr_t = package["ATT&CK Tactic"]
                elif "MBC Objective" in line:
                    curr_t = package["MBC"]
                elif "Capability" in line:
                    curr_t = package["CAPA"] 
                if line_found == False:#Skip the next line
                    ditch_line = f.readline()
                    line_found = True
                next_line = line
                if "└───────" in next_line:#Stop at the last line
                    line_found = False
                    curr_section = ""
                    continue
                if "ATT&CK Tactic" in line or "MBC Objective" in line or  "Capability" in line:#Skip the label line
                    continue
                first_marker = next_line.find("│")
                second_marker = next_line.find(" ", first_marker + 2)
                section =  next_line[first_marker + 2 : second_marker]
                if section != "":
                    curr_section = section
                    curr_t[section] = []
                    third_marker = next_line.find("│", first_marker + 1)
                    fourth_marker = next_line.find("|", third_marker + 1)
                    section_content = next_line[third_marker + 1 : fourth_marker - 1].strip()
                    curr_t[section].append(section_content)
                else:
                    second_marker = next_line.find("│",first_marker + 1)
                    third_marker = next_line.find("|", second_marker + 1)
                    section_content = next_line[second_marker + 1 : third_marker - 1].strip()
                    curr_t[curr_section].append(section_content)
    #if os.path.exists("test.txt"):
        #os.remove("test.txt")
    
    for category in package:

        remove_keys = []

        for key, values in package[category].items():

            if not values:
                remove_keys.append(key)
                continue

            clean_values = [
                v.strip()
                for v in values
                if v.strip()
            ]

            if not clean_values:
                remove_keys.append(key)
            else:
                package[category][key] = clean_values

        for key in remove_keys:
            del package[category][key]

    return package

def ConvertIntToHex(value):
    return struct.pack("<I",value).hex().strip("00")

def HashCalc(file):
    with open(file, "rb") as f:
        hashes = {}
        for algo in ["sha256", "sha1", "md5"]:
            hashes[algo] = hashlib.file_digest(f, algo).hexdigest()
        return hashes

def EntropyCalc(file):
    data = np.fromfile(file, dtype=np.uint8)
    if data.size == 0:
        return 0.0
    counts = np.bincount(data, minlength=256)
    return float(entropy(counts, base=2))

def GetFileSize(file):
    size = os.path.getsize(file)
    return f"Size: {size} bytes"


def SaveToJSON(package):
    with open("result.json","w") as file:
        json.dump(package, file, indent=4)


def ExtractStrings(file):

    return_strings = []

    result = subprocess.run(
        [
            os.path.join(
                os.path.dirname(__file__),
                "floss.exe"
            ),
            "-j",
            file
        ],
        capture_output=True,
        text=True
    )

    try:

        data = json.loads(
            result.stdout
        )

    except Exception:

        return []

        static_strings =  data["strings"]["static_strings"]
        for entry in static_strings:
                string = entry["string"]
                for pattern in COMPILED:
                    if re.search(COMPILED[pattern], string) and len(string) < max_length:
                            return_strings.append(string)
    return return_strings