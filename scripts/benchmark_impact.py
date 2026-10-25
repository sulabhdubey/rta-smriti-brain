"""Bounded synthetic impact comparison; not a real-world superiority benchmark."""

import argparse
import json
import statistics
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from rta_brain import db
from rta_brain.impact import impact_report, limit_impact_connection


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--nodes', type=int, default=1000)
    parser.add_argument('--queries', type=int, default=25)
    args = parser.parse_args()
    if not 10 <= args.nodes <= 10000 or not 5 <= args.queries <= 100:
        parser.error('nodes must be 10-10000 and queries 5-100')
    with tempfile.TemporaryDirectory(prefix='rta-impact-benchmark-') as directory:
        path = Path(directory) / 'fixture.sqlite'
        writer = db.connect(path)
        try:
            db.init_project(writer, 'fixture', directory)
            pid = writer.execute("SELECT id FROM projects WHERE name='fixture'").fetchone()[0]
            nodes = [db.ensure_entity(writer, pid, 'function', f'node_{i}') for i in range(args.nodes)]
            for i in range(1, args.nodes):
                sid = writer.execute('INSERT INTO sources(project_id,kind,path,title,hash,metadata_json,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)',
                    (pid, 'file', f'node_{i}.py', f'node_{i}.py', f'fixture-{i}', '{"privacy_class":"public"}', '2026-10-18', '2026-10-18')).lastrowid
                writer.execute('INSERT INTO chunks(source_id,ordinal,text,hash) VALUES(?,?,?,?)',
                    (sid, 0, f'node_{i} calls node_{(i-1)//2}', f'chunk-{i}'))
                db.add_edge(writer, pid, nodes[i], 'calls', nodes[(i-1)//2], source_id=sid, confidence=.8)
            writer.commit()
            started = time.perf_counter()
            baseline = db.graph_query(writer, project='fixture', target='node_0', query_type='dependents', depth=2, limit=60)
            baseline_ms = (time.perf_counter() - started) * 1000
            writer.commit()
            writer.execute('BEGIN IMMEDIATE')
            samples = []
            cpu_start = time.process_time()
            for _ in range(args.queries):
                start = time.perf_counter()
                reader = db.connect_readonly(path)
                try:
                    limit_impact_connection(reader)
                    value = impact_report(reader, project='fixture', target='node_0')
                    assert {n['name'] for n in value['nodes']} == {n['name'] for n in baseline['nodes']}
                    assert len(value['evidence']) == 6
                    assert all(n['path_edge_ids'] for n in value['nodes'] if n['distance'])
                finally:
                    reader.close()
                samples.append((time.perf_counter() - start) * 1000)
            cpu_seconds = time.process_time() - cpu_start
            writer.rollback()
            print(json.dumps({'fixture': 'synthetic binary dependency tree', 'nodes': args.nodes,
                'queries_under_reserved_writer': args.queries, 'successful_reads': len(samples),
                'failures': 0, 'matched_baseline_entity_set': True, 'candidate_paths_and_evidence': True,
                'candidate_including_connection_median_ms': round(statistics.median(samples), 3),
                'candidate_including_connection_p95_ms': round(sorted(samples)[int(.95 * (len(samples)-1))], 3),
                'candidate_process_cpu_seconds': round(cpu_seconds, 3),
                'baseline_single_query_existing_connection_ms': round(baseline_ms, 3),
                'limits': 'Different timing scopes; no speedup claim. Synthetic fixture only; no installed, cross-platform, RSS or thermal proof.'}, indent=2))
        finally:
            writer.close()


if __name__ == '__main__':
    main()
