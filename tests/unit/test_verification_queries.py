"""Representative SQL verification queries for OSIRIS Phase 1.

These queries are for verification only — they confirm that the Phase 1
schema supports the expected query patterns. They are NOT part of the
application code.

Run against a PostgreSQL database with Phase 1 schema and seed data loaded.
"""

VERIFICATION_QUERIES = {
    "list_hosts": """
        SELECT id, hostname, os_info, ip_address, created_at
        FROM hosts
        ORDER BY created_at;
    """,
    "list_linux_users_for_host": """
        SELECT lu.id, lu.uid, lu.username, lu.first_seen_at
        FROM linux_users lu
        JOIN hosts h ON lu.host_id = h.id
        WHERE h.hostname = 'osiris-dev-vm'
        ORDER BY lu.uid;
    """,
    "list_processes_for_host": """
        SELECT p.id, p.pid, p.ppid, p.command, p.executable,
               lu.username AS user, p.started_at, p.ended_at
        FROM processes p
        JOIN hosts h ON p.host_id = h.id
        LEFT JOIN linux_users lu ON p.linux_user_id = lu.id
        WHERE h.hostname = 'osiris-dev-vm'
        ORDER BY p.started_at;
    """,
    "list_files_for_host": """
        SELECT f.id, f.path, f.inode, f.file_type, f.first_seen_at
        FROM files f
        JOIN hosts h ON f.host_id = h.id
        WHERE h.hostname = 'osiris-dev-vm'
        ORDER BY f.path;
    """,
    "list_events_for_time_range": """
        SELECT e.id, e.timestamp, e.source, e.event_type, e.action,
               e.severity, e.pid, e.command
        FROM events e
        WHERE e.timestamp >= '2026-01-01T00:00:00Z'
          AND e.timestamp <  '2026-12-31T23:59:59Z'
        ORDER BY e.timestamp;
    """,
    "list_events_for_process": """
        SELECT e.id, e.timestamp, e.event_type, e.action, e.severity
        FROM events e
        JOIN processes p ON e.process_id = p.id
        WHERE p.pid = 1
        ORDER BY e.timestamp;
    """,
    "list_resource_snapshots_by_time": """
        SELECT rs.id, rs.timestamp, rs.cpu_percent,
               rs.memory_percent, rs.disk_usage_percent
        FROM resource_snapshots rs
        JOIN hosts h ON rs.host_id = h.id
        WHERE h.hostname = 'osiris-dev-vm'
        ORDER BY rs.timestamp;
    """,
    "join_events_with_processes": """
        SELECT e.id AS event_id, e.timestamp, e.event_type,
               p.pid, p.command, p.executable
        FROM events e
        JOIN processes p ON e.process_id = p.id
        ORDER BY e.timestamp;
    """,
    "join_processes_with_linux_users": """
        SELECT p.pid, p.command, lu.uid, lu.username
        FROM processes p
        JOIN linux_users lu ON p.linux_user_id = lu.id
        ORDER BY p.pid;
    """,
    "list_app_users": """
        SELECT id, username, display_name, role, is_active, created_at
        FROM app_users
        ORDER BY created_at;
    """,
    "list_audit_log_for_user": """
        SELECT al.id, al.action, al.target_type, al.details,
               al.ip_address, al.created_at
        FROM app_audit_log al
        JOIN app_users u ON al.user_id = u.id
        WHERE u.username = 'admin'
        ORDER BY al.created_at;
    """,
}

if __name__ == "__main__":
    print("=" * 72)
    print("OSIRIS Phase 1 — Representative Verification Queries")
    print("=" * 72)
    for name, query in VERIFICATION_QUERIES.items():
        print(f"\n--- {name} ---")
        print(query.strip())
    print()
