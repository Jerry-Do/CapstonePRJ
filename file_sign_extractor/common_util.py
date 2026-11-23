import hashlib
import numpy as np
import struct 
import json
import subprocess
import os
from scipy.stats import entropy


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