# Contributing to Attestor

## Adding a New CIS Control

1. **Create a YAML rule file** in the appropriate `rules/<target>/` folder (e.g., `rules/ubuntu2204_desktop/1.1.1.1_cramfs.yaml`).
2. **Follow the rule schema** defined in `schema/rule_schema.json`. The validator will reject malformed files.
3. **Verify the control against a real system** before committing. A wrong control is worse than no control — see AGENTS.md Section 0.
4. **Run the rule validator**: `python tests/validate_rules.py` must pass.
5. **Commit with a descriptive message**: `feat(<target>): add <check_type> check + <control_id> <short description>`

## Build Discipline

Read [AGENTS.md](AGENTS.md) in full before contributing. It covers:
- Phase structure and dependencies
- Verification requirements
- Commit message standards
- Context preservation rules

Every control must be manually verified on a real VM before it is committed as working. No exceptions.
