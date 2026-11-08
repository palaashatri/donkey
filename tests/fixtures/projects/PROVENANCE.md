# Project fixtures

## schema-v5.db

A project database written by the schema v5 build (before G12-T1 added the code and data
annotations), used to test the v5 to v6 migration in `tests/unit/project_test.cpp`
(`Project.MigratesSchemaV5AnnotationsToV6AndKeepsThem`).

- Made from `tests/fixtures/binaries/tiny-elf-x86_64`, the same image the other tests use. The
  repository has no separate provenance note for that binary. SHA-256 of the image recorded in
  the project: `cb2f08393b7c54eb793cf315f56fe51e974372d1e1c9dba2a04af2d9991bcb43`.
- Commands, run with the v5 `donkey-cli`:

  ```
  donkey-cli project save schema-v5.db tests/fixtures/binaries/tiny-elf-x86_64
  donkey-cli project rename schema-v5.db 1 0x400109 entry_main
  donkey-cli project comment schema-v5.db 1 0x400109 "reviewed in v5"
  donkey-cli project bookmark schema-v5.db 1 0x400109 "keep"
  ```

- Contents: `PRAGMA user_version` 5, one image (id 1), three annotations at 0x400109 (a rename,
  a comment and a bookmark). It is a generated file with no third-party content.
- The file is in WAL journal mode, as every project is; it was closed cleanly, so it has no
  `-wal` or `-shm` sidecar.
- Do not regenerate it with a newer build: the point of the fixture is to be a v5 file.
