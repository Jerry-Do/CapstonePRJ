import os
import json
import asyncio

os.environ["TRANSFORMERS_VERBOSITY"] = "error"

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

MODEL_PATH = os.path.abspath(
    os.path.join(
        ROOT_DIR,
        config["model_dir"]
    )
)

from transformers.utils import logging
logging.set_verbosity_error()

from transformers import (
    AutoTokenizer,
    AutoModelForCausalLM
)

from mcp import ClientSession

from mcp.client.stdio import (
    stdio_client,
    StdioServerParameters,
)

server_params = StdioServerParameters(
    command=os.path.join(
        os.path.dirname(
            os.path.abspath(__file__)
        ),
        ".venv",
        "Scripts",
        "python.exe"
    ),
    args=[
        os.path.join(
            os.path.dirname(
                os.path.abspath(__file__)
            ),
            "server.py"
        )
    ]
)


def generate_response(
    model,
    tokenizer,
    prompt,
    max_tokens=1024
):
    messages = [
        {
            "role": "user",
            "content": prompt
        }
    ]

    text = tokenizer.apply_chat_template(
        messages,
        tokenize=False,
        add_generation_prompt=True
    )

    inputs = tokenizer(
        text,
        return_tensors="pt"
    )

    outputs = model.generate(
        **inputs,
        max_new_tokens=max_tokens
    )

    input_length = inputs["input_ids"].shape[1]

    generated_tokens = outputs[0][input_length:]

    return tokenizer.decode(
        generated_tokens,
        skip_special_tokens=True
    ).strip()


async def main():

    print("\nLoading model...")

    tokenizer = AutoTokenizer.from_pretrained(
        MODEL_PATH
    )

    model = AutoModelForCausalLM.from_pretrained(
        MODEL_PATH,
        device_map="cpu"
    )

    file_path = input(
        "\nPath to executable: "
    ).strip()

    async with stdio_client(
        server_params
    ) as (read, write):

        async with ClientSession(
            read,
            write
        ) as session:

            await session.initialize()

            print(
                "\nExtracting features..."
            )

            result = await session.call_tool(
                "extract_features",
                {
                    "file_path": file_path
                }
            )

            if not result.content:

                print(
                    "\nNo features returned."
                )

                return

            feature_text = "\n".join(
                getattr(
                    item,
                    "text",
                    str(item)
                )
                for item in result.content
            )

            print(
                "\n===== EXTRACTED FEATURES =====\n"
            )

            print(feature_text)

            analysis_prompt = f"""
            Classify the file as benign or malicious
            using only the supplied static-analysis evidence.

            Describe capabilities only as static indicators,
            not confirmed behavior.

            Do not infer a malware family unless the evidence
            explicitly supports it.

            If evidence is insufficient,
            return "uncertain".

            Return valid JSON with the following keys:

            {{
            "verdict": "benign | malicious | uncertain",
            "evidence": [
                "...",
                "..."
            ],
            "explanation": "..."
            }}

            Static-analysis evidence:

            {feature_text}
            """

            print(
                "\nRunning malware analysis..."
            )

            response = generate_response(
                model,
                tokenizer,
                analysis_prompt,
                max_tokens=1024
            )

            print(
                "\n===== MODEL ANALYSIS =====\n"
            )

            print(response)


if __name__ == "__main__":
    asyncio.run(main())