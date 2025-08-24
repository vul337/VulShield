# README

#### Overview

This README documents the scripts and data included as part of the artifacts submitted to demonstrate the usability and the coverage of vulnerability types by our proposed framework. These elements are integral to the contributions of our paper, specifically the manual analysis section.

#### Scripts

The `script` directory contains two analysis scripts:

- `count_listed_type_cve.py`: This script is used to count the number of vulnerabilities of the types listed in the pre-organized templates.
- `analysis_cve.py`: This script is used for counting and analyzing the number of vulnerabilities of other types supported by our framework.

#### Logs

The `log` directory stores two log files:

- `all_patch.log`: Contains the filenames of all the vulnerability patches analyzed.
- `cleaned_patch.log`: Contains the filenames of the vulnerability patches that have been manually verified to be supported by our framework with equivalent security capabilities.

### Note

- `cve_cwe_analysis.json` Contains all the cve and the corresponding cwe.

These artifacts are submitted as part of our effort to validate the practical application of our framework and its ability to adequately cover various vulnerability types.