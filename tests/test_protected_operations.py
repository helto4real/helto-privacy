import asyncio

from helto_privacy import WorkflowRevealOperationContext, WorkflowRevealOperations


class Authorization:
    def __init__(self) -> None:
        self.calls = []

    def authorize_request(self, request, operation_id):
        self.calls.append(("reveal", request, operation_id))
        return "reveal-authorization"

    async def dispatch(self, request, scope_id, operation_id, operation):
        self.calls.append(("dispatch", request, scope_id, operation_id))
        return await operation("operation-authorization")


class Adapter:
    def invoke(self, payload, context):
        assert payload == {"protected": "CURRENT"}
        assert context == WorkflowRevealOperationContext(
            "operation-authorization",
            "reveal-authorization",
            "workflow-handle",
        )
        return {"status": "revealed"}


def test_workflow_reveal_operation_issues_narrow_authority_inside_dispatch():
    authorization = Authorization()
    operations = WorkflowRevealOperations(
        authorization,
        "workflow-handle",
        Adapter(),
        scope_id="display",
        operation_id="display.reveal",
    )

    result = asyncio.run(
        operations.dispatch("request", {"protected": "CURRENT"})
    )

    assert result == {"status": "revealed"}
    assert authorization.calls == [
        ("dispatch", "request", "display", "display.reveal"),
        ("reveal", "request", "snapshot.reveal"),
    ]
