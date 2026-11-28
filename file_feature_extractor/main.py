import argparse
import json
import lief
import struct
from pe_extractor import StartExtractingPE


if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        description="Extract malware features"
    )

    parser.add_argument(
        "-f",
        "--file",
        required=True,
        type=str,
        help="Path to executable file"
    )

    args = parser.parse_args()

    file = lief.parse(args.file)
    magic = ""

    try:
        magic = struct.pack("<I",file.dos_header.magic).hex().strip("00")
    except:
        print(json.dumps({"error":"Not PE file"}))
        exit()

    try:
        elf_magic = struct.pack("<I",file.header.magic).hex().strip("00")
    except:
        elf_magic = ""

    match magic:
        case "4d5a":
            try:
                result = StartExtractingPE(args.file)
                print(json.dumps(result))
            except Exception as ex:
                print(json.dumps({"error":str(ex)}))
        case _:
            print(json.dumps({"error":"Not supported file type"}))