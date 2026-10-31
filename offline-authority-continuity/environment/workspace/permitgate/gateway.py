"""Conservative starting point, NOT a solution.

The service can read/write JSONL but intentionally cannot authenticate or apply
policy graphs, accept grants or execute operations. A correct contributor-owned
implementation should replace these stubs. No benchmark score is implied.
"""
class Gateway:
    def __init__(self, trust_path: str, state_path: str):
        self.trust_path = trust_path
        self.state_path = state_path

    def process(self, cmd: dict) -> dict:
        if not isinstance(cmd, dict):
            return {"status": "denied", "code": "malformed"}
        kind = cmd.get('kind')
        if kind == 'ingest':
            return {"status": "rejected", "code": "malformed"}
        if kind == 'checkpoint':
            return {"status": "rejected", "code": "malformed"}
        if kind == 'checkpoint_status':
            return {"status": "denied", "code": "unknown_site"}
        if kind == 'prepare':
            return {"status": "denied", "code": "unauthorized"}
        if kind == 'commit':
            return {"status": "denied", "code": "unknown_request"}
        return {"status": "denied", "code": "malformed"}
