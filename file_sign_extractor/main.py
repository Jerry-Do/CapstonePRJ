import argparse
import json

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

    try:

        result = StartExtractingPE(
            args.file
        )

        print(
            json.dumps(
                result
            )
        )

    except Exception as ex:

        print(
            json.dumps(
                {
                    "error": str(ex)
                }
            )
        )
