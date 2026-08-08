// TRIAXIS PI-001 Cedar Reference Policy
permit (
    principal == User::"alice@triaxis.dev",
    action == Action::"execute_capability",
    resource == Resource::"target_service_v1"
)
when {
    context.agent_instance_id == "agent_inst_001" &&
    context.delegation_grant_id == "grant_prod_001" &&
    context.task_id == "task_authorization_001"
};
