from audithor import rules


class AccessRecordingDict(dict):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.accessed = set()

    def get(self, key, default=None):
        self.accessed.add(key)
        return super().get(key, default)

    def __getitem__(self, key):
        self.accessed.add(key)
        return super().__getitem__(key)

    def __contains__(self, key):
        self.accessed.add(key)
        return super().__contains__(key)


def test_rule_data_sources_match_static_access_contract():
    expected = {
        "ACM_001",
        *(f"DB_{number:03}" for number in range(1, 6)),
        *(f"INSPECTOR_{number:03}" for number in range(1, 6)),
        "ECR_004", "ECR_005", "CODEPIPELINE_003", "CODEPIPELINE_004",
    }
    declared = set()
    differences = {}
    for rule in rules.RULES_TO_CHECK:
        sources = rule.get("data_sources", [])
        if sources:
            declared.add(rule["rule_id"])
        data = AccessRecordingDict({
            "acm": {}, "inspector": {}, "databases": {}, "ecr": {}, "codepipeline": {},
        })
        try:
            rule["check_function"](data)
        except Exception:
            pass
        covered_accesses = data.accessed & set(rules.COVERAGE_SERVICES)
        differences[rule["rule_id"]] = {
            "undeclared": covered_accesses - set(sources),
            "unaccessed": set(sources) & set(rules.COVERAGE_SERVICES) - covered_accesses,
        }
    assert declared == expected
    assert {rule_id: diff for rule_id, diff in differences.items()
            if diff["undeclared"] or diff["unaccessed"]} == {}


def test_coverage_gap_scenario_matrix():
    rule = next(rule for rule in rules.RULES_TO_CHECK if rule["rule_id"] == "ACM_001")
    base = {"certificates": []}
    assert rules.coverage_gaps({"acm": {**base, "_collection": {
        "status": "complete", "coverageKnown": True}}}, rule["data_sources"]) == []
    assert rules.coverage_gaps({"acm": {**base, "_collection": {
        "status": "partial", "coverageKnown": True}}}, rule["data_sources"])[0]["status"] == "partial"
    for collection in ({"status": "complete", "coverageKnown": False}, {"status": "complete"}):
        assert rules.coverage_gaps({"acm": {**base, "_collection": collection}},
                                   rule["data_sources"])[0]["coverageKnown"] is False
    assert rules.coverage_gaps({"acm": {**base, "_collection": {
        "status": "not_applicable", "coverageKnown": True}}}, rule["data_sources"]) == []
    assert rules.coverage_gaps({"acm": base}, rule["data_sources"]) == []
    units = [{"operation": str(i), "region": "us-east-1", "category": "api", "status": "failed"}
             for i in range(12)]
    gap = rules.coverage_gaps({"acm": {**base, "_collection": {
        "status": "failed", "coverageKnown": False, "units": units}}}, rule["data_sources"])[0]
    assert len(gap["failedUnits"]) == 10


def test_acm_coverage_gaps_are_not_assessed_without_violations():
    rule = next(rule for rule in rules.RULES_TO_CHECK if rule["rule_id"] == "ACM_001")
    clean = {"acm": {"certificates": [], "_collection": {"status": "partial", "coverageKnown": True}}}
    assert rules.coverage_gaps(clean, rule["data_sources"])[0]["service"] == "acm"


def test_acm_violation_under_coverage_gap_keeps_red_flag_and_annotation():
    rule = next(rule for rule in rules.RULES_TO_CHECK if rule["rule_id"] == "ACM_001")
    gaps = rules.coverage_gaps({"acm": {"certificates": [{"Status": "EXPIRED"}],
        "_collection": {"status": "partial", "coverageKnown": True}}}, rule["data_sources"])
    assert gaps == [{"service": "acm", "status": "partial", "coverageKnown": True, "failedUnits": []}]


def test_dynamodb_table_unencrypted_only_reports_explicit_false():
    def check(encrypted):
        return rules.check_dynamodb_table_unencrypted({
            "databases": {"dynamodb_tables": [{"TableName": "example", "Region": "us-east-1", "Encrypted": encrypted}]}
        })

    assert check(False) == [{"resource": "example", "region": "us-east-1"}]
    assert check(True) == []
    assert check(None) == []
