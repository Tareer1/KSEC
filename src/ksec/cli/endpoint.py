"""CLI: ``ksec endpoint`` — read-only local endpoint inventory (spec 08 #31)."""
from __future__ import annotations

from ksec.bootstrap import KsecContext
from ksec.cli.output import emit


def cmd_endpoint_inventory(ctx: KsecContext, args) -> int:
    host = ctx.endpoint.host_inventory()
    data = {
        "hostname": host.hostname,
        "os_name": host.os_name,
        "os_version": host.os_version,
        "kernel": host.kernel,
        "architecture": host.architecture,
        "uptime_seconds": round(host.uptime_seconds, 1),
        "cpu_count": host.cpu_count,
        "pid_count": host.pid_count,
        "memory_kb": host.memory_kb,
    }
    emit(data, args.json, args.quiet)
    return 0


def cmd_endpoint_processes(ctx: KsecContext, args) -> int:
    procs = ctx.endpoint.processes(limit=args.limit)
    data = [
        {"pid": p.pid, "name": p.name, "state": p.state, "ppid": p.ppid,
         "uid": p.uid, "cmdline": p.cmdline}
        for p in procs
    ]
    if args.json:
        emit(data, True, False)
    elif args.quiet:
        for p in procs:
            print(p.pid)
    else:
        for d in data:
            print(f"{d['pid']:>6} {d['name']:<20} {d['state']:<3} uid={d['uid']:<5} {d['cmdline'] or ''}")
    return 0


def cmd_endpoint_users(ctx: KsecContext, args) -> int:
    users = ctx.endpoint.users()
    data = [
        {"username": u.username, "uid": u.uid, "gid": u.gid, "home": u.home, "shell": u.shell}
        for u in users
    ]
    if args.json:
        emit(data, True, False)
    elif args.quiet:
        for u in users:
            print(u.username)
    else:
        for d in data:
            print(f"{d['username']:<16} uid={d['uid']:<5} gid={d['gid']:<5} shell={d['shell']}")
    return 0


def cmd_endpoint_ports(ctx: KsecContext, args) -> int:
    sockets = ctx.endpoint.listening_sockets()
    data = [
        {"protocol": s.protocol, "local": s.local, "state": s.state,
         "pid": s.pid, "process": s.process}
        for s in sockets
    ]
    if args.json:
        emit(data, True, False)
    elif args.quiet:
        for s in sockets:
            print(s.local)
    else:
        for d in data:
            print(f"{d['protocol']:<5} {d['local']:<28} {d['state']:<12} pid={d['pid']:<6} {d['process'] or ''}")
    return 0


def cmd_endpoint_check(ctx: KsecContext, args) -> int:
    """Passive checks; optionally create findings for notable observations."""
    data = ctx.endpoint.check(create_findings=args.create_findings, actor=args.user or "endpoint")
    if args.json:
        emit(data, True, False)
    elif args.quiet:
        print(f"observations={len(data['observations'])}")
    else:
        print(f"host: {data['host']['hostname']} ({data['host']['os']} {data['host']['os_version']})")
        if not data["observations"]:
            print("no notable observations")
        for obs in data["observations"]:
            print(f"  [review] {obs['check']}: {obs['detail']}")
    return 0