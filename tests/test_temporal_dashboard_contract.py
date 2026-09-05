from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_temporal_truth_dashboard_is_wired_to_real_operator_api():
    source = (ROOT / "dashboard-src" / "src" / "main.jsx").read_text(
        encoding="utf-8"
    )
    styles = (ROOT / "dashboard-src" / "src" / "styles.css").read_text(
        encoding="utf-8"
    )
    assert "function TemporalTruthWorkspace" in source
    assert 'api(`/api/truth?' in source
    assert 'api("/api/truth"' in source
    assert "Truth Timeline" in source
    assert "Contradictions" in source
    assert "Validator Health" in source
    assert ".truthWorkspace" in styles
    assert ".truthTimeline" in styles


def test_trusted_lifecycle_health_is_visible_in_operator_settings():
    source = (ROOT / "dashboard-src" / "src" / "main.jsx").read_text(
        encoding="utf-8"
    )
    styles = (ROOT / "dashboard-src" / "src" / "styles.css").read_text(
        encoding="utf-8"
    )
    assert 'api(`/api/lifecycle?' in source
    assert "System lifecycle" in source
    assert "Database" in source
    assert "Project integrity" in source
    assert "Capture" in source
    assert "Continuation" in source
    assert "MCP" in source
    assert "Federation" in source
    assert "lifecycleHealthGrid" in styles


def test_trusted_lifecycle_dashboard_requires_preview_before_apply_or_repair():
    source = (ROOT / "dashboard-src" / "src" / "main.jsx").read_text(
        encoding="utf-8"
    )
    styles = (ROOT / "dashboard-src" / "src" / "styles.css").read_text(
        encoding="utf-8"
    )
    assert 'action: "plan"' in source
    assert 'action: "apply"' in source
    assert 'action: "verify"' in source
    assert 'action: "repair"' in source
    assert "Review lifecycle plan" in source
    assert "Apply approved plan" in source
    assert "LifecycleConflict" in source
    assert "lifecyclePlanSteps" in styles
    assert "lifecycleActions" in styles


def test_lifecycle_actions_do_not_install_an_old_projects_async_response():
    source = (ROOT / "dashboard-src" / "src" / "main.jsx").read_text(
        encoding="utf-8"
    )

    assert source.count("const requestProject = selectedProject;") >= 2
    assert source.count(
        "if (isCurrentProject(requestProject)) await loadProjectDetails(requestProject);"
    ) >= 2
