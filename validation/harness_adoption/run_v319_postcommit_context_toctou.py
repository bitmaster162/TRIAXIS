from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from triaxis.harness_v1 import CapabilityBroker, ToolSpec, assemble_context, resolve_harness_config, seal_tool_request
from triaxis.integrity import canonical_sha256, seal_mapping


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()

    authorized_bytes = b'approved content\n'
    substituted_bytes = b'substituted after manifest\n'
    expected = sha(authorized_bytes)
    observed = sha(substituted_bytes)
    cfg = resolve_harness_config([
        {'name': 'operator', 'values': {
            'capabilities': ['read'], 'tools': ['read_file'], 'targets': ['workspace:triaxis'],
            'data_classes': ['PUBLIC'], 'mcp_servers': [], 'max_context_bytes': 4096,
            'max_subagents': 0, 'max_workflow_fanout': 0, 'max_rounds': 1,
            'whole_repo_upload': False, 'plugin_digests': [], 'sandbox_profiles': []
        }}
    ])
    manifest = assemble_context({
        'session_id': 'session:toctou', 'purpose': 'read exact approved bytes',
        'items': [{
            'artifact_id': 'file:subject', 'logical_path': 'subject.txt', 'source_kind': 'FILE',
            'content_sha256': expected, 'size_bytes': len(authorized_bytes), 'data_class': 'PUBLIC',
            'explicit_grant': True
        }]
    }, cfg)
    broker = CapabilityBroker()
    broker.register(ToolSpec('read_file', 'read', False, ('workspace:triaxis',), 4096, ('PUBLIC',)))
    request = seal_tool_request({
        'tool_id': 'read_file', 'target': 'workspace:triaxis',
        'input_artifact_ids': ['file:subject'], 'payload_sha256': sha(b'read'), 'max_output_bytes': 4096
    })
    receipt = broker.dispatch(
        request,
        session_authority={
            'capabilities': ['read'], 'tools': ['read_file'], 'targets': ['workspace:triaxis'],
            'data_classes': ['PUBLIC'], 'mcp_servers': [], 'max_context_bytes': 4096,
            'max_subagents': 0, 'max_workflow_fanout': 0, 'max_rounds': 1
        },
        context_manifest=manifest,
        hook_receipt=None,
        evaluation_tick=1,
    )
    vulnerable = expected != observed and receipt['outcome'] == 'ALLOW'
    row = {
        'case_id': 'CTX_TOCTOU_01',
        'manifest_expected_sha256': expected,
        'materialized_observed_sha256': observed,
        'broker_outcome_without_materialization_receipt': receipt['outcome'],
        'vulnerability_reproduced': vulnerable,
        'required_fix': 'bind exact materialized bytes to manifest and tool request before dispatch'
    }
    result = {
        'contract_id': 'TRIAXIS_v3.19_POSTCOMMIT_CONTEXT_TOCTOU_v1',
        'exact_product_commit': '766c69044a6e10df14b88b3bebad46ce0f329e24',
        'status': 'FAIL_EXPECTED' if vulnerable else 'NOT_REPRODUCED',
        'rows': [row],
        'rows_sha256': canonical_sha256([row]),
        'result_sha256': ''
    }
    result = seal_mapping(result, 'result_sha256')
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if vulnerable else 1


if __name__ == '__main__':
    raise SystemExit(main())
