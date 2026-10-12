"""Run Project Passport with two fictional projects in an isolated local folder."""

import argparse
import json
import tempfile
import webbrowser
from contextlib import closing
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from . import db
from .console import create_dashboard_server


def prepare_demo(root: Path) -> Path:
    root = Path(root)
    if root.is_symlink():
        raise ValueError("demo directory must not be a symbolic link")
    root.mkdir(parents=True, exist_ok=True)
    marker = root / "passport-demo.json"
    database = root / "brains" / "passport-demo.sqlite"
    if marker.is_file() and marker.read_text(encoding="utf-8") == '{"fixture":"project-passport-v1"}\n' and database.is_file():
        return database
    if any(root.iterdir()):
        raise ValueError("choose an empty demo directory; existing files are never overwritten")
    for name, objective, decision, next_action in (
        ("atlas-studio", "Prepare the Atlas client launch", "Use a small pilot first because the client needs evidence before a wider launch.", "Review the pilot acceptance checklist with the client."),
        ("harbor-research", "Compare the Harbor research sources", "Keep observed facts separate from proposed explanations.", "Recheck the two open research questions."),
    ):
        folder = root / name
        folder.mkdir()
        (folder / "README.md").write_text(
            f"# {name}\n\nFictional Project Passport demonstration. No real client information.\n\n## Objective\n{objective}\n",
            encoding="utf-8",
        )
        (folder / "DECISIONS.md").write_text(f"# Decisions\n\n{decision}\n", encoding="utf-8")
        with closing(db.connect(database)) as conn:
            db.init_project(conn, name, str(folder.resolve()))
            db.ingest_repo(conn, folder, project=name)
            db.remember(conn, decision, project=name, memory_type="decision", pramana="sabda",
                        provenance={"verification_status": "unverified", "metadata": {"source": "fictional-demo"}})
            db.save_checkpoint(conn, name, objective, verified_evidence="A local brief and decision note were indexed.",
                               remaining_gaps="No customer validation has been performed.", next_action=next_action,
                               prohibited_repetition="Do not treat this fictional demo as customer evidence.")
    marker.write_text('{"fixture":"project-passport-v1"}\n', encoding="utf-8")
    return database


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path, help="An empty directory, or an existing Passport demo directory")
    parser.add_argument("--port", type=int, default=0, help="Loopback port; 0 selects a free port")
    parser.add_argument("--no-open", action="store_true")
    args = parser.parse_args(argv)
    root = args.data_dir or Path(tempfile.mkdtemp(prefix="rta-passport-demo-"))
    database = prepare_demo(root)
    server, _, url = create_dashboard_server(
        Path(__file__).resolve().parents[1], database.parent,
        default_db=database, default_project="atlas-studio", host="127.0.0.1", port=args.port,
        sessions_root=root / "empty-sessions", instance_id="passport-demo",
    )
    parts = urlsplit(url)
    query = dict(parse_qsl(parts.query))
    query["view"] = "passport"
    url = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment))
    print(json.dumps({"url": url, "data_dir": str(root.resolve()), "fixture": "fictional-only"}), flush=True)
    if not args.no_open:
        webbrowser.open(url)
    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
