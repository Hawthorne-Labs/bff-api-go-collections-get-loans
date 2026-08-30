# Deploy / runtime

**Production ECS `bff-get-loans` runs this Go BFF** (cutover 2026-08-30).

- Do **not** deploy `mvp/bff-api-python-collections-get-loans` for normal releases.
- Catalog: `jenkins-ci/services.json` → `bff-get-loans` (`type=bff-go`, `blockedVariants: ["python"]`).
- Agent/operator registry: `docs/ai/bff-runtime-cutover.md`.

```bash
cd jenkins-ci/deploy-console
./deploy-console build-deploy -env prod -service bff-get-loans -branch main -release <slug>
```
