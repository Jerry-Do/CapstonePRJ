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

    ##try:

        ##result = StartExtractingPE(
            ##args.file
        #)

        #print(
            #json.dumps(
                #result
            #)
        #)

    #except Exception as ex:

        #print(
            #json.dumps(
                #{
                    #"error": str(ex)
                #}
            #)
        #)

    file = lief.parse(args.file)
    magic = ""
    try:
        magic = struct.pack("<I",file.dos_header.magic).hex().strip("00")
    except:
        print("Not PE file")
    try:
        magic = struct.pack("<I",file.header.magic).hex().strip("00")
    except:
        print("Not ELF file")
    match magic:
        case "4d5a":
            result = StartExtractingPE(args.file)
        case _:
            print("Not supported file type")