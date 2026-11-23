import os
import json
import subprocess

from mcp.server import MCPServer

ROOT_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

with open(
    os.path.join(ROOT_DIR, "config.json"),
    "r",
    encoding="utf-8"
) as f:
    config = json.load(f)

extractor_dir = os.path.abspath(
    os.path.join(
        ROOT_DIR,
        config["extractor_dir"]
    )
)

extractor_python = os.path.abspath(
    os.path.join(
        ROOT_DIR,
        config["extractor_python"]
    )
)

server = MCPServer(
    name="Project A Malware Server",
    description="Feature extraction and malware analysis support"
)


@server.tool()
def extract_features(
    file_path: str
):
    """
    Extract malware features from a PE file.

    This tool executes the Project A
    feature extraction pipeline and
    returns the extracted static-analysis
    features as a JSON object.
    """

    try:

        result = subprocess.run(
            [
                extractor_python,
                "main.py",
                "-f",
                file_path
            ],
            cwd=extractor_dir,
            capture_output=True,
            text=True,
            timeout=300
        )

        if result.returncode != 0:

            return {
                "error": result.stderr
            }

        stdout = result.stdout.strip()

        # CAPA sometimes prints progress
        # before the JSON object.
        json_start = stdout.find("{")

        if json_start == -1:

            return {
                "error":
                "No JSON found in extractor output",
                "raw_output":
                stdout
            }

        json_text = stdout[json_start:]

        try:

            return json.loads(
                json_text
            )

        except Exception as ex:

            return {
                "error":
                f"JSON parsing failed: {str(ex)}",
                "raw_output":
                stdout
            }

    except subprocess.TimeoutExpired:

        return {
            "error":
            "Feature extraction timed out"
        }

    except Exception as ex:

        return {
            "error": str(ex)
        }


@server.tool()
def lookup_reputation(
    sha256: str
):
    """
    Retrieve malware reputation information.
    """

    reputation_db = {

        "74a565819ad577d54612357f4c13d8e1b6c8ef42250b48d9d6e5c4b8f77c9d93":
        {
            "detection_ratio": "45/73",
            "family": "installcore",
            "confidence": 0.665
        }

    }

    return reputation_db.get(
        sha256,
        {
            "status": "unknown"
        }
    )


@server.tool()
def save_report(
    report: dict,
    output_file: str
):
    """
    Save analysis report as JSON.
    """

    try:

        with open(
            output_file,
            "w",
            encoding="utf-8"
        ) as f:

            json.dump(
                report,
                f,
                indent=4
            )

        return {
            "saved": True,
            "output_file": output_file
        }

    except Exception as ex:

        return {
            "saved": False,
            "error": str(ex)
        }


if __name__ == "__main__":
    server.run()