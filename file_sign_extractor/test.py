import lief
import pefile
import re
import json
#file_parse = lief.parse("D:\\Steam\\steamapps\\common\\CLANNAD\\SiglusEngine_Steam.exe")
#print(file_parse.dos_header)
#print(file_parse.header)
#print(file_parse.optional_header)
#print(file_parse.coff_string_table)
import argparse
import subprocess
import os

#Read line until ATT&CK Tactic 
#start while loop unti the line with 笏笏笏笏笏笏 are found
package = {}
package["ATT&CK Tactic"] = {}
package["MBC"] = {}
package["CAPA"] = {}


parser = argparse.ArgumentParser(description="Enter file: ")
parser.add_argument("-f", "--file", type=str, help="Enter path to file")
args = parser.parse_args()
cmd = ".\\capa.exe " + args.file 


#with open("test.txt", "w") as f:
    #subprocess.run(cmd, stdout=f, text=True)

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
            section =  next_line[first_marker + 1 : second_marker]
            if section != "":
                curr_section = section
                curr_t[section] = []
                third_marker = next_line.find("│", first_marker + 1)
                fourth_marker = next_line.find("  ", third_marker + 1)
                section_content = next_line[third_marker + 1 : fourth_marker]
                curr_t[section].append(section_content)
            else:
                second_marker = next_line.find("│",first_marker + 1)
                third_marker = next_line.find("  ", second_marker + 1)
                section_content = next_line[second_marker + 1 : third_marker - 2]
                curr_t[curr_section].append(section_content)
            
with open("result.json","w") as file:
    json.dump(package, file, indent=4)
print(package)

