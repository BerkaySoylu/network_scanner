from dataclasses import dataclass
from time import time
from typing import Dict, List
import statistics

@dataclass
class ScanMetrics:
    start_time: float
    end_time: float
    total_ports: int
    successful_scans: int
    failed_scans: int
    response_times: List[float]

    @property
    def duration(self) -> float:
        return self.end_time - self.start_time

    @property
    def success_rate(self) -> float:
        return self.successful_scans / self.total_ports if self.total_ports > 0 else 0

    @property
    def avg_response_time(self) -> float:
        return statistics.mean(self.response_times) if self.response_times else 0

class PerformanceMonitor:
    def __init__(self):
        self.metrics: Dict[str, ScanMetrics] = {}

    def start_scan(self, scan_id: str, total_ports: int):
        self.metrics[scan_id] = ScanMetrics(
            start_time=time(),
            end_time=0,
            total_ports=total_ports,
            successful_scans=0,
            failed_scans=0,
            response_times=[]
        )

    def record_port_result(self, scan_id: str, response_time: float, success: bool):
        metrics = self.metrics[scan_id]
        metrics.response_times.append(response_time)
        if success:
            metrics.successful_scans += 1
        else:
            metrics.failed_scans += 1

    def end_scan(self, scan_id: str):
        self.metrics[scan_id].end_time = time() 