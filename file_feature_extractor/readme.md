# File Feature Extractor
File Feature Extractor is a set of python scripts used to extract the features of a file. As of right now, it only supports PE files.
## Extracted Features
These are the features that will get extracted from a PE file
 - Size
 - Entropy
 - COFF header
 - Optional header
 - Imported libraries and API calls
 - Strings
 - CAPA
 - MBC
 - ATT&CK techniques

 ## Tools Used
 There are three important tools that are used:
 - LIEF: a PE file python library used to extract the files' features
 - capa.exe: a tool used to extract CAPA, MBC and ATT&CK techniques
 - floss.exe: a tool used to extract strings out of files

## Extractor's Structure
```text
file_feature_extractor/
├── capa.exe
├── common_util.py
├── floss.exe
├── main.py
├── pe_extractor.py
└── README.md
```
### main.py
The entry point of the tool. A PE file's features can be extracted by using the commannd 
```text
py .\main.py -f *path to file*
```
main.py will extract the magic bytes of file to find what kind of file it is, i.e a PE, ELF, etc... And call the matching routine for extraction.

**Magic bytes**: is a series of bytes that indicates the type of file regardless of file extensions and it usually apears at the first couple of bytes in a binary. For example the first two bytes of a PE file will always be 4D 5A, which can be translated into MZ.

### common_util.py
This file contains all the functions can be used in different file types.

### pe_extractor.py
This file will extract all the features of a PE file like COFF headers, imported libraries, etc... and return a json object