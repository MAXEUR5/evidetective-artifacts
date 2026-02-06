# Artifact for “EVIDETECTIVE: Evidence-Driven Binary Vulnerability Discovery”

This repository contains the artifact corresponding to the paper:

> **EVIDETECTIVE: Evidence-Driven Binary Vulnerability Discovery**  

The artifact implements the evidence-driven workflow described in the paper: for each chain-centric lead, the system maintains an explicit proof state over four proof obligations (O1–O4) and incrementally gathers program-derived evidence to verify or refute vulnerability claims.

# Artifact Directory Layout

This repository is organized as follows:

```text
.
├── api_collect/
├── case_study/
├── EviD_master/
├── HypD_master/
├── ida_util/
├── mini_elf_feature_extract/
├── smoke_test/
├── apikey.txt
├── juliet_build_strip_flow.md
└── juliet_cwe121_cwe122_mislabel_report.md
```

## Directory Descriptions

- `api_collect/`  
  Scripts and data for collecting and organizing API-related information.

- `case_study/`  
  Data and supporting files for case-study programs.

- `EviD_master/`  
  Main implementation of the core system.

- `HypD_master/`  
  Implementation of the comparison / baseline system.

- `ida_util/`  
  Utility scripts related to binary analysis tooling.

- `mini_elf_feature_extract/`  
  Utilities for sampling and feature extraction on ELF binaries.

- `smoke_test/`  
  Small test set and scripts for quickly checking CWE-121 and CWE-122 samples.

- `apikey.txt`  
  Placeholder configuration file.

- `juliet_build_strip_flow.md`  
  Notes and steps for building and stripping Juliet binaries.

- `juliet_cwe121_cwe122_mislabel_report.md`  
  Notes and report related to CWE-121 and CWE-122 labeling.
