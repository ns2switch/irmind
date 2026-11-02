# Synthetic custom-log episode

This fixture helps parser contributors test two synthetic authentication events.
The public input is `source/events.ndjson`, interpreted using
`docs/examples/parsers/nested-ndjson.toml`. The evaluator alone reads `private/`;
never ingest it or include it in model context. The episode follows HuntEval's
public-input/private-answer separation. These events were created for IRMind.
