# Backups app: AGP's auto-generated keep rules cover the manifest-declared
# components (MainActivity, SuiteCapsProvider). Compose runtime keep rules
# come from the Compose plugin. BouncyCastle is reached via direct symbol
# from :common-security and :common-backup, kept by call-graph. No
# reflection-based code paths in this module.
