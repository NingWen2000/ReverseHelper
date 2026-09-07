"""Shared bounded-analysis profiles for competition workflows."""

from dataclasses import asdict, dataclass


@dataclass(frozen=True, slots=True)
class AnalysisBudget:
    mode: str
    max_code_bytes: int
    max_instructions: int
    max_scan_bytes: int
    function_instruction_limit: int
    dataflow_max_call_depth: int
    dataflow_max_functions: int
    dataflow_max_edges: int
    dataflow_max_instructions: int
    dataflow_max_sources: int
    max_algorithm_functions: int
    max_algorithm_instructions: int
    max_table_candidates: int
    max_cfg_functions: int
    max_cfg_blocks: int
    max_cfg_edges: int
    max_indirect_targets: int
    max_semantic_suggestions: int
    max_objects_per_function: int
    max_expression_groups: int
    soft_timeout_seconds: float
    hard_timeout_seconds: float

    @classmethod
    def quick(cls):
        return cls("quick", 256 * 1024, 32768, 10 * 1024 * 1024, 4096, 3, 48, 8000, 24000, 32,
                   96, 24000, 32, 96, 4096, 12000, 64, 20, 8, 8, 2.0, 8.0)

    @classmethod
    def deep(cls):
        return cls("deep", 1024 * 1024, 131072, 40 * 1024 * 1024, 8192, 5, 160, 30000, 96000, 96,
                   256, 96000, 96, 256, 16384, 48000, 256, 60, 16, 24, 8.0, 30.0)

    def to_dict(self):
        return asdict(self)
