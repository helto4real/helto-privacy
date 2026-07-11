"""Bounded blocking adapter execution that remains responsive to cancellation."""

from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from threading import BoundedSemaphore


BLOCKING_ADAPTER_MAX_PENDING = 4

_EXECUTOR = ThreadPoolExecutor(
    max_workers=BLOCKING_ADAPTER_MAX_PENDING,
    thread_name_prefix="helto-privacy-adapter",
)
_ADMISSION = BoundedSemaphore(BLOCKING_ADAPTER_MAX_PENDING)


async def run_blocking_adapter(operation, *args):
    """Run one product adapter call on the bounded shared worker pool."""

    if not callable(operation):
        raise TypeError("A callable product adapter operation is required.")
    loop = asyncio.get_running_loop()
    while not _ADMISSION.acquire(blocking=False):
        await asyncio.sleep(0.01)
    release_admission = True
    try:
        concurrent = _EXECUTOR.submit(operation, *args)
        wrapped = asyncio.wrap_future(concurrent, loop=loop)
        try:
            while not wrapped.done():
                await asyncio.wait((wrapped,), timeout=0.01)
                if concurrent.done() and not wrapped.done():
                    wrapped.cancel()
                    return concurrent.result()
            return wrapped.result()
        except BaseException:
            wrapped.cancel()
            if not concurrent.done():
                release_admission = False
                concurrent.add_done_callback(lambda _future: _ADMISSION.release())
            raise
    finally:
        if release_admission:
            _ADMISSION.release()


def reset_blocking_adapter_runtime_for_tests() -> None:
    """Compatibility no-op; process-global admission has no loop-local state."""
