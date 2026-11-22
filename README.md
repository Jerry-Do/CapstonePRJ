# Project A - Malware Classification System

## Overview

Project A is a malware analysis platform that combines static feature extraction with AI-assisted malware classification.

The system extracts executable features such as PE metadata, imported APIs, CAPA capabilities, MBC behaviors, and ATT&CK techniques, then uses a fine-tuned language model to generate a malware assessment consisting of a verdict, supporting evidence, and an explanation.

Current architecture:

```text
EXE File
    ↓
Feature Extraction Pipeline
    ↓
Structured Feature Bundle
    ↓
Malware Analysis Model
    ↓
Verdict + Evidence + Explanation

The current repository contains the MCP integration layer, feature extraction pipeline, and model evaluation workflow used by the prototype.
```

---

## Repository Structure

```text
ProjectA/

├── mcp/
│   ├── server.py
│   └── test_classification.py
│
├── file_sign_extractor/
│   ├── main.py
│   ├── pe_extractor.py
│   ├── common_util.py
│   └── capa.exe
│
├── README.md
└── .gitignore
```

---

## Components

### MCP Layer

Location:

```text
mcp/
```

Responsibilities:

- Host MCP tools
- Connect extractor and model
- Execute malware analysis workflow
- Return final verdicts

Main MCP tool:

```python
extract_features(file_path)
```

---

### Feature Extraction Layer

Location:

```text
file_sign_extractor/
```

Responsibilities:

- PE parsing using LIEF
- Entropy calculation
- Import/API extraction
- CAPA capability extraction
- MBC mapping
- ATT&CK technique mapping

Returned features include:

```json
{
  "Entropy": "...",
  "Libraries and API": "...",
  "CAPA": "...",
  "MBC": "...",
  "ATT&CK": "..."
}
```

---

## Workflow

1. User supplies an executable file.
2. MCP calls `extract_features()`.
3. MCP launches the feature extractor.
4. Extractor returns feature JSON.
5. Feature JSON is passed to the model.
6. Model returns:

```json
{
  "verdict": "...",
  "evidence": [...],
  "explanation": "..."
}
```

---

## Model

Model files are not stored in Git due to size constraints.

Place the model directory inside:

```text
mcp/model/
```

The current prototype model is approximately 4.3 GB and is distributed separately through the team's shared storage.

---

## Environment Setup

### Feature Extractor

Install:

```bash
pip install lief pefile numpy scipy
```

---

### MCP Environment

Install required MCP and Hugging Face dependencies:

```bash
pip install mcp transformers torch accelerate
```

---

## Current Status

Implemented:

- MCP integration
- Feature extraction pipeline
- CAPA extraction
- MBC extraction
- ATT&CK mapping
- End-to-end malware classification testing

Planned Improvements:

- Improve model accuracy
- Clean CAPA parser artifacts
- Add threat intelligence lookups
- Evaluate on additional malware samples
