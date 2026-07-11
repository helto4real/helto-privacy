"""Shared protected-operation lifecycle for authorized workflow reveals."""

from __future__ import annotations

import inspect
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class WorkflowRevealOperationContext:
    authorization: object
    reveal_authorization: object
    workflow: object


class WorkflowRevealOperations:
    """Dispatch one protected product operation with narrow reveal authority."""

    def __init__(
        self,
        authorization: object,
        workflow: object,
        adapter: object,
        *,
        scope_id: str,
        operation_id: str,
    ) -> None:
        if not scope_id or not operation_id:
            raise ValueError("Protected workflow operation identity is required.")
        self._authorization = authorization
        self._workflow = workflow
        self._adapter = adapter
        self._scope_id = scope_id
        self._operation_id = operation_id

    async def dispatch(self, request: object, payload: object) -> object:
        async def invoke(authorization: object) -> object:
            reveal_authorization = self._authorization.authorize_request(
                request,
                "snapshot.reveal",
            )
            result = self._adapter.invoke(
                payload,
                WorkflowRevealOperationContext(
                    authorization,
                    reveal_authorization,
                    self._workflow,
                ),
            )
            return await result if inspect.isawaitable(result) else result

        return await self._authorization.dispatch(
            request,
            self._scope_id,
            self._operation_id,
            invoke,
        )
