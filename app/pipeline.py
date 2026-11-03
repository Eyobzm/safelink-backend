import asyncio
import time

from .providers.base import EngineResult, Provider


async def run_scan(url: str, providers: list[Provider], redirect_resolver, deadline: float) -> dict:
    start = time.monotonic()
    tasks = {asyncio.create_task(p.lookup(url)): p.name for p in providers}
    redirect_task = asyncio.create_task(redirect_resolver.resolve(url))

    done, pending = await asyncio.wait(set(tasks) | {redirect_task}, timeout=deadline)
    for t in pending:  # FR-SCAN-03: late results ignored
        t.cancel()

    results: dict[str, EngineResult] = {}
    for t, name in tasks.items():
        if t in pending:
            results[name] = EngineResult(name, "timeout")
        elif t.exception() is not None:
            results[name] = EngineResult(name, "error")
        else:
            results[name] = t.result()

    hops = 0
    if redirect_task in done and redirect_task.exception() is None:
        hops = redirect_task.result().hops

    return {
        "results": results,
        "redirect_hops": hops,
        "latency_ms": int((time.monotonic() - start) * 1000),
    }
