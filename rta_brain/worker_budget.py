"""Cooperative CPU pacing for background repository work."""

from __future__ import annotations

import time


class WorkerBudget:
    def __init__(
        self, *, cpu_fraction=0.2, cancelled=lambda: False,
        wait=None, cpu_clock=time.thread_time, wall_clock=time.monotonic,
    ):
        if not 0 < cpu_fraction <= 1:
            raise ValueError("worker CPU fraction must be between zero and one")
        self.cpu_fraction = float(cpu_fraction)
        self.cancelled = cancelled
        self.wait = wait or (lambda seconds: time.sleep(seconds) or False)
        self.cpu_clock = cpu_clock
        self.wall_clock = wall_clock
        self.started_cpu = self.last_cpu = cpu_clock()
        self.started_wall = wall_clock()
        self.paused_seconds = 0.0

    def checkpoint(self):
        if self.cancelled():
            raise InterruptedError("repository refresh cancelled")
        cpu = self.cpu_clock()
        if cpu - self.last_cpu < 0.025:
            return
        # Natural I/O waits already satisfy the budget; charge only measured CPU.
        target_elapsed = (cpu - self.started_cpu) / self.cpu_fraction
        while True:
            delay = target_elapsed - (self.wall_clock() - self.started_wall)
            if delay <= 0:
                break
            pause = min(delay, 0.1)
            if self.wait(pause) or self.cancelled():
                raise InterruptedError("repository refresh cancelled")
            self.paused_seconds += pause
        self.last_cpu = cpu

    def sqlite_progress(self):
        try:
            self.checkpoint()
        except InterruptedError:
            return 1
        return 0

    def report(self):
        return {
            "cpu_budget_fraction": self.cpu_fraction,
            "last_cycle_cpu_seconds": round(self.cpu_clock() - self.started_cpu, 3),
            "last_cycle_wall_seconds": round(self.wall_clock() - self.started_wall, 3),
            "last_cycle_paused_seconds": round(self.paused_seconds, 3),
        }
