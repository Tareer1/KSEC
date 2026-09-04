# Contributing to KSEC

Thanks for contributing! KSEC is built directly against its master
specification in [`specs/`](specs/).

## Development setup

```bash
# No dependencies required — the core is pure Python stdlib.
export PYTHONPATH=src
python3 -m ksec init --username admin --password 'change-me'
make test        # 128 unit tests
```

## Definition of Done

Per the spec, a feature is complete only when it is:

**Implemented + Integrated + Tested + Error Handled + Documented +
Security Reviewed + Accessible + Recoverable**

Never mark a requirement `VERIFIED` without evidence. Never claim a
component is implemented when only a placeholder exists.

## Rules

1. Do not remove requirements silently.
2. Do not hardcode the Kali tool ecosystem.
3. Do not make AI/LLM services a dependency.
4. Do not bypass authorization or scope controls.
5. Do not silently ignore errors.
6. Write tests for implemented functionality.
7. Update documentation when behavior changes.

## Submitting changes

1. Keep changes focused; match existing conventions.
2. Add tests (stdlib `unittest`) covering the change.
3. Run `make test` before opening a pull request.
4. Reference the spec section your change implements.

## Code of conduct

Be professional. KSEC is security tooling for authorized work; keep it that
way.