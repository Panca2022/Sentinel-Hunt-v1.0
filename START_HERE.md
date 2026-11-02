# SentinelHunt source handover - Group 2

This is a local repository-ready package. It has not been published to GitHub and has not been rebuilt in this review environment.

## Layout
- SentinelHunt/: the frozen agent/MCP/interface source supplied by Win. Start with README.md and docs/REBUILD.md.
- SentinelHunt_ELK_Portable/: the team's isolated ELK kit. Start with README.md. Generate fresh local credentials; never upload runtime secrets.
- PACKAGE_SHA256.json: package file hashes, separate from the original recorded-run manifest.

Keep these two directories as siblings when following the source rebuild guide. Use the original handover's recorded evidence to compare a rebuild; review the report's limits and version distinctions.

## Before publishing a repository
1. Create a private GitHub/GitLab repository using your own account. Choose assessor access deliberately.
2. Upload the two source folders, this file and the package manifest.
3. Review all files for credentials and private data. Do not add .env, runtime/, private raw captures, private keys, report cover names/matriculation IDs or personal videos.
4. The v3 545-record dataset is NOT included here. Use the previously verified pseudonymized dataset ZIP; arrange assessor access separately. Its checksum is recorded in the report.
5. Copy the repository URL into the report and ensure the assessor can access it. Save a commit identifier after the final review.

No live containers, volumes or existing AppSec projects were modified while preparing this package.
