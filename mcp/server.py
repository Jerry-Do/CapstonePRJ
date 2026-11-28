import os
import json
import subprocess
import logging


from mcp.server import MCPServer

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler()
    ]
) 

logger = logging.getLogger("Project A Malware Server")

ROOT_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)
logger.info("Loading server configuration...")

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

logger.info("Configuration loaded successfully.")
logger.info("Extractor directory: %s", extractor_dir)
logger.info("Extractor Python: %s", extractor_python)

server = MCPServer(
    name="Project A Malware Server",
    description="Feature extraction and malware analysis support"
)


@server.tool()
def extract_features(file_path: str):
    """
    Extract malware features from a PE file.

    This tool executes the Project A
    feature extraction pipeline and
    returns the extracted static-analysis
    features as a JSON object.
    """
    logger.info("Feature extraction requested: %s", file_path)

    try:

        if not os.path.isfile(file_path):
            logger.error("File does not exist: %s", file_path)

            return {
                "error": "File does not exist"
            }

        logger.info("Starting feature extraction...")

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

            logger.error("No JSON found in extractor output.")
            return {
                "error":
                "No JSON found in extractor output",
                "raw_output":
                stdout
            }

        json_text = stdout[json_start:]

        try:

            features =  json.loads(json_text)

            logger.info("Feature extraction completed successfully.")

            return features

        except Exception as ex:

            logger.exception("JSON parsing failed.")
            return {
                "error":
                f"JSON parsing failed: {str(ex)}",
                "raw_output":
                stdout
            }

    except subprocess.TimeoutExpired:

        logger.error("Feature extraction timed out.")
        return {
            "error":
            "Feature extraction timed out"
        }

    except Exception as ex:

        logger.exception("Unexpected feature extraction error.")
        return {
            "error": str(ex)
        }


@server.tool()
def lookup_reputation(sha256: str):
    """
    Retrieve malware reputation information.
    """
    logger.info("Reputation lookup requested: %s", sha256)

    reputation_db = {

        "74a565819ad577d54612357f4c13d8e1b6c8ef42250b48d9d6e5c4b8f77c9d93":
        {
            "detection_ratio": "45/73",
            "family": "installcore",
            "confidence": 0.665
        }

    }

    result = reputation_db.get(
        sha256,
        {
            "status": "unknown"
        }
    )
    logger.info("Reputation lookup completed.")
    return result

@server.tool()
def save_report(
    report: dict,
    output_file: str
):
    """
    Save analysis report as a readable text report.
    """
    logger.info("Saving analysis report: %s", output_file)

    try:
        logger.info("Opening file")
        with open(
            output_file,
            "w",
            encoding="utf-8"
        ) as f:

            f.write(
                "=================================\n"
            )

            f.write(
                " MALWARE ANALYSIS REPORT\n"
            )

            f.write(
                "=================================\n\n"
            )

            f.write(
                f"Sample: {report.get('sample', 'Unknown')}\n\n"
            )

            f.write(
                f"Verdict: {report.get('verdict', 'Unknown')}\n\n"
            )

            f.write(
                "Evidence:\n"
            )

            evidence = report.get(
                "evidence",
                []
            )

            if evidence:

                for item in evidence:

                    f.write(
                        f"- {item}\n"
                    )

            else:

                f.write(
                    "- No evidence provided\n"
                )

            f.write(
                "\nExplanation:\n"
            )

            f.write(
                report.get(
                    "explanation",
                    "No explanation provided."
                )
            )

            f.write("\n")

        logger.info("Analysis report saved successfully.")
        return {
            "saved": True,
            "output_file": output_file
        }

    except Exception as ex:
        logger.exception("Failed to save analysis report.")
        return {
            "saved": False,
            "error": str(ex)
        }


if __name__ == "__main__":
    logger.info("==========================================")
    logger.info("Starting Project A Malware MCP Server")
    logger.info("==========================================")
    try:
        logger.info("Initializing MCP server...")
        server.run()
    except KeyboardInterrupt:

        logger.info("MCP server stopped by user.")

    except Exception:

        logger.exception("MCP server encountered a fatal error.")

    finally:

        logger.info("MCP server process terminated.")
