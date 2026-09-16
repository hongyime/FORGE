"""Windows Job containment for migration test processes, suspended until assigned."""
import ctypes as c
from ctypes import wintypes as w
import time


class Limits(c.Structure):
    _fields_ = [("process_time", c.c_int64), ("job_time", c.c_int64),
                ("flags", w.DWORD), ("min_working", c.c_size_t),
                ("max_working", c.c_size_t), ("active_limit", w.DWORD),
                ("affinity", c.c_size_t), ("priority", w.DWORD), ("scheduling", w.DWORD)]


class IO(c.Structure):
    _fields_ = [(name, c.c_uint64) for name in
                ("read_ops", "write_ops", "other_ops", "read_bytes", "write_bytes", "other_bytes")]


class Extended(c.Structure):
    _fields_ = [("basic", Limits), ("io", IO), ("process_memory", c.c_size_t),
                ("job_memory", c.c_size_t), ("peak_process", c.c_size_t), ("peak_job", c.c_size_t)]


class Accounting(c.Structure):
    _fields_ = [(name, c.c_int64) for name in ("user", "kernel", "period_user", "period_kernel")]
    _fields_ += [(name, w.DWORD) for name in ("faults", "total", "active", "terminated")]


class Job:
    def __init__(self):
        self.k = c.WinDLL("kernel32", use_last_error=True)
        signatures = {
            "CreateJobObjectW": ([c.c_void_p, w.LPCWSTR], w.HANDLE),
            "SetInformationJobObject": ([w.HANDLE, c.c_int, c.c_void_p, w.DWORD], w.BOOL),
            "AssignProcessToJobObject": ([w.HANDLE, w.HANDLE], w.BOOL),
            "TerminateJobObject": ([w.HANDLE, w.UINT], w.BOOL),
            "QueryInformationJobObject": ([w.HANDLE, c.c_int, c.c_void_p, w.DWORD, c.c_void_p], w.BOOL),
            "CloseHandle": ([w.HANDLE], w.BOOL),
        }
        for name, (args, result) in signatures.items():
            function = getattr(self.k, name)
            function.argtypes, function.restype = args, result
        self.handle = self.k.CreateJobObjectW(None, None)
        if not self.handle:
            raise OSError("job_create")
        limits = Extended()
        limits.basic.flags = 0x2000  # KILL_ON_JOB_CLOSE, no breakaway.
        if not self.k.SetInformationJobObject(self.handle, 9, c.byref(limits), c.sizeof(limits)):
            self.close()
            raise OSError("job_limits")

    def assign_resume(self, process):
        if not self.k.AssignProcessToJobObject(self.handle, int(process._handle)):
            raise OSError("job_assign")
        resume = c.WinDLL("ntdll").NtResumeProcess
        resume.argtypes, resume.restype = [w.HANDLE], c.c_long
        if resume(int(process._handle)) != 0:
            raise OSError("job_resume")

    def terminate(self):
        self.total_processes = 0
        self.active_after = None
        if not self.k.TerminateJobObject(self.handle, 125):
            return False
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            info = Accounting()
            if not self.k.QueryInformationJobObject(self.handle, 1, c.byref(info), c.sizeof(info), None):
                return False
            self.total_processes = info.total
            self.active_after = info.active
            if info.active == 0:
                return True
            time.sleep(0.02)
        return False

    def close(self):
        if self.handle:
            self.k.CloseHandle(self.handle)
            self.handle = None
