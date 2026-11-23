from app.network.policy import Finding


class NetworkError(Exception):
    code = "network_error"


class NotFound(NetworkError):
    code = "network_not_found"


class RevisionConflict(NetworkError):
    code = "revision_conflict"


class CorruptSnapshot(NetworkError):
    code = "corrupt_snapshot"


class InvalidChange(NetworkError):
    code = "invalid_network_change"


class UnsupportedOperation(NetworkError):
    code = "unsupported_operation"


class PolicyBlocked(NetworkError):
    def __init__(self, findings: tuple[Finding, ...]) -> None:
        self.findings = findings
        self.code = (
            "policy_denied"
            if any(item.decision == "deny" for item in findings)
            else "policy_unknown"
        )
        super().__init__(self.code)
