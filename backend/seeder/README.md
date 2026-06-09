# Seeds

No users are seeded by default — create your first admin with:

```bash
shaapi auth init
```

To seed your own reference data, drop one JSON file per model in `json/` and run
the seeder inside the api container:

```bash
shaapi shell
python -m backend.seeder.run seed
```

Each file follows the [`sqlalchemyseed`](https://pypi.org/project/sqlalchemyseed/)
format, e.g. `json/role.json`:

```json
{
  "model": "backend.models.Role",
  "data": [
    { "name": "editor" }
  ]
}
```

> Never commit real credentials or password hashes here — seed files are part of
> the repository. Create privileged users with `shaapi auth init` instead.
