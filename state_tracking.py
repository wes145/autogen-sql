from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional
from datetime import datetime

@dataclass
class ResponseAnalysis:
    length: int
    status_code: int
    contains_sql: bool
    debug_output: bool
    sql_snippet: Optional[str] = None
    error_messages: List[str] = field(default_factory=list)

@dataclass
class EndpointState:
    url: str
    method: str
    params: Dict[str, str]
    baseline_response: Optional[ResponseAnalysis] = None
    tests_run: List[Dict] = field(default_factory=list)
    promising: bool = False
    confirmed_vulnerable: bool = False

@dataclass
class FormAnalysis:
    action: str
    method: str
    fields: Dict[str, str]  # field_name -> field_type
    hidden_fields: Dict[str, str]  # field_name -> default_value

class PenTestState:
    def __init__(self):
        self.current_target: Optional[str] = None
        self.current_phase: str = "recon"  # recon -> crawl -> test -> exploit
        self.tested_endpoints: Set[str] = set()
        self.promising_endpoints: List[EndpointState] = []
        self.confirmed_vulns: List[EndpointState] = []
        self.forms_analyzed: Dict[str, FormAnalysis] = {}
        self.start_time = datetime.now()
        
    def add_form(self, url: str, form: FormAnalysis) -> None:
        self.forms_analyzed[url] = form
        
    def mark_endpoint_tested(self, url: str) -> None:
        self.tested_endpoints.add(url)
        
    def is_endpoint_tested(self, url: str) -> bool:
        return url in self.tested_endpoints

    # --------- persistence helpers ---------
    def to_dict(self):
        return {
            "current_target": self.current_target,
            "current_phase": self.current_phase,
            "tested_endpoints": list(self.tested_endpoints),
            "promising_endpoints": self.promising_endpoints,
            "confirmed_vulns": self.confirmed_vulns,
            "forms_analyzed": {k: v.__dict__ for k, v in self.forms_analyzed.items()},
            "start_time": self.start_time.isoformat(),
        }

    @staticmethod
    def from_dict(data):
        obj = PenTestState()
        obj.current_target = data.get("current_target")
        obj.current_phase = data.get("current_phase", "recon")
        obj.tested_endpoints = set(data.get("tested_endpoints", []))
        obj.promising_endpoints = data.get("promising_endpoints", [])
        obj.confirmed_vulns = data.get("confirmed_vulns", [])
        # forms_analyzed reconstruction minimal
        forms = data.get("forms_analyzed", {})
        for url, fa_dict in forms.items():
            obj.forms_analyzed[url] = FormAnalysis(**fa_dict)
        return obj

class SQLiTestState:
    SQL_ERROR_PATTERNS = [
        "mysql", "sqlite", "postgresql", "ora-", 
        "sql syntax", "sql error", "warning: mysql"
    ]
    
    DEBUG_PARAMS = ["debug", "test", "dev", "show_sql", "trace"]
    
    def __init__(self):
        self.baseline_lengths: Dict[str, int] = {}
        self.successful_payloads: Dict[str, str] = {}
        self.blocked_payloads: Set[str] = set()
        
    def analyze_response(self, content: str, status: int) -> ResponseAnalysis:
        return ResponseAnalysis(
            length=len(content),
            status_code=status,
            contains_sql=any(err in content.lower() for err in self.SQL_ERROR_PATTERNS),
            debug_output=any(debug in content.lower() for debug in self.DEBUG_PARAMS),
            sql_snippet=self._extract_sql_query(content)
        )
    
    def _extract_sql_query(self, content: str) -> Optional[str]:
        # Simple SQL query extraction - could be enhanced
        if "SELECT" in content and "FROM" in content:
            # Very basic extraction - would need improvement
            start = content.find("SELECT")
            end = content.find(";", start)
            if end == -1:
                end = content.find("\"", start)
            if end == -1:
                end = len(content)
            return content[start:end].strip()
        return None 