# TRIAXIS v3.20 Context Materialization Protocol

| ID | Case | Required |
|---|---|---|
| CM01 | bytes changed after manifest | BLOCK |
| CM02 | tool request has artifact but no materialization receipt | DENY |
| CM03 | exact captured bytes | ALLOW |
| CM04 | request binds another receipt digest | DENY |
| CM05 | receipt observation is in the future | DENY |
