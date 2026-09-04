import blackforge.core.types as types


class TestTypes:
    def test_mission_id_generation(self) -> None:
        mid = types.MissionID()
        assert mid.startswith("mission_")
        assert len(str(mid)) > 8

    def test_mission_id_custom(self) -> None:
        mid = types.MissionID("custom_id")
        assert mid == "custom_id"

    def test_task_id_generation(self) -> None:
        tid = types.TaskID()
        assert tid.startswith("task_")

    def test_evidence_id_generation(self) -> None:
        eid = types.EvidenceID()
        assert eid.startswith("ev_")

    def test_finding_id_generation(self) -> None:
        fid = types.FindingID()
        assert fid.startswith("find_")

    def test_capability_id_generation(self) -> None:
        cid = types.CapabilityID()
        assert cid.startswith("cap_")

    def test_asset_id_generation(self) -> None:
        aid = types.AssetID()
        assert aid.startswith("asset_")

    def test_unique_ids(self) -> None:
        ids = {types.MissionID() for _ in range(100)}
        assert len(ids) == 100

    def test_mission_status_values(self) -> None:
        assert types.MissionStatus.CREATED.value == "created"
        assert types.MissionStatus.RUNNING.value == "running"
        assert len(types.MissionStatus) == 7

    def test_task_status_values(self) -> None:
        assert types.TaskStatus.PENDING.value == "pending"
        assert len(types.TaskStatus) == 7

    def test_evidence_type_values(self) -> None:
        assert types.EvidenceType.OBSERVATION.value == "observation"
        assert len(types.EvidenceType) == 9

    def test_evidence_status_values(self) -> None:
        assert types.EvidenceStatus.OBSERVED.value == "observed"
        assert types.EvidenceStatus.VALIDATED.value == "validated"
        assert len(types.EvidenceStatus) == 4

    def test_confidence_values(self) -> None:
        assert types.Confidence.LOW.value == "low"
        assert types.Confidence.CONFIRMED.value == "confirmed"

    def test_risk_level_ordering(self) -> None:
        levels = [r.value for r in types.RiskLevel]
        assert "informational" in levels
        assert "critical" in levels

    def test_authorization_decision_values(self) -> None:
        assert types.AuthorizationDecision.AUTHORIZED.value == "authorized"
        assert types.AuthorizationDecision.DENIED.value == "denied"
        assert types.AuthorizationDecision.REQUIRES_APPROVAL.value == "requires_approval"
