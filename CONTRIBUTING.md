# Contributing to Kaguya

Thanks for helping! Bug reports, detection rules, docs and UI polish are all welcome.

## Set up

```bash
git clone https://github.com/Ordixian/Kaguya.git
cd Kaguya
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[recommended]" pytest
```

## Run it

```bash
kaguya run          # dashboard at http://127.0.0.1:8787
kaguya sweep        # one-shot, prints findings
```

## Run the tests

```bash
python3 -m pytest -q
```

CI runs the same tests on Python 3.9 to 3.13, so avoid syntax newer than 3.9.

## Add a detection rule

Rules live in `cybersentinel/detection/rules.py` and are run by `cybersentinel/detection/engine.py`.

1. Add a `rule_<name>(batch, ctx)` function in `cybersentinel/detection/rules.py`. Copy the shape of `rule_known_bad_port`: it receives the new events from the sweep and returns a list of `Alert(rule=..., title=..., severity=..., host=ctx.host, description=..., event_ids=[...], data=...)`. Read thresholds with `ctx.cfg("<name>", "<key>", default)`.
2. Append the function to `ALL_RULES` at the bottom of that file, and add its defaults to `cybersentinel/config.py` and `config/config.yaml`.
3. Add a plain-English explanation in `cybersentinel/explain.py` (the `rule -> function` table near line 300) so the dashboard's 💡 button works for your alert, and a MITRE ATT&CK tag in the `ssh_bruteforce: ["T1110", ...]` map in `cybersentinel/web/app.js`.
4. Add a test in `tests/test_detection.py` that feeds synthetic events and asserts the alert fires (and does not fire on benign input).
5. Document the rule in the README rules table.

## Pull requests

- Keep PRs focused; one change per PR.
- Add or update tests, and make sure `pytest` passes.
- Don't commit secrets, hostnames, personal paths or real log data.
- By contributing you agree your work is released under the MIT license.

Please follow our [Code of Conduct](CODE_OF_CONDUCT.md).
