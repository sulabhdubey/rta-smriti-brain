"""Lifetime containment for the bridge's short-lived, trusted query worker."""

from __future__ import annotations

import os
import signal

_WORKER_JOB = None


def initialize_worker_containment():
    """A Windows worker owns a non-inherited kill-on-close job for its helpers."""
    global _WORKER_JOB
    if os.name != "nt" or _WORKER_JOB is not None:
        return
    import ctypes
    from ctypes import wintypes

    class BasicLimits(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_int64),
            ("PerJobUserTimeLimit", ctypes.c_int64),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class IoCounters(ctypes.Structure):
        _fields_ = [
            (name, ctypes.c_uint64)
            for name in (
                "ReadOperationCount",
                "WriteOperationCount",
                "OtherOperationCount",
                "ReadTransferCount",
                "WriteTransferCount",
                "OtherTransferCount",
            )
        ]

    class ExtendedLimits(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", BasicLimits),
            ("IoInfo", IoCounters),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    kernel.CreateJobObjectW.restype = wintypes.HANDLE
    kernel.SetInformationJobObject.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
    ]
    kernel.SetInformationJobObject.restype = wintypes.BOOL
    kernel.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    kernel.AssignProcessToJobObject.restype = wintypes.BOOL
    kernel.GetCurrentProcess.argtypes = []
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    handle = kernel.CreateJobObjectW(None, None)
    if not handle:
        raise OSError(ctypes.get_last_error(), "worker containment unavailable")
    limits = ExtendedLimits()
    limits.BasicLimitInformation.LimitFlags = (
        0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    )
    if not kernel.SetInformationJobObject(
        handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)
    ):
        error = ctypes.get_last_error()
        kernel.CloseHandle(handle)
        raise OSError(error, "worker containment unavailable")
    if not kernel.AssignProcessToJobObject(handle, kernel.GetCurrentProcess()):
        error = ctypes.get_last_error()
        kernel.CloseHandle(handle)
        raise OSError(error, "worker containment unavailable")
    # Keep the non-inherited handle until OS process teardown. Closing it here
    # would terminate this worker before its result has been flushed.
    _WORKER_JOB = handle


def kill_worker_tree(child):
    if os.name == "nt":
        child.kill()  # Process teardown closes its job and terminates its helpers.
    else:
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
