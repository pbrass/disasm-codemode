#!/usr/bin/env python3
"""gh-status — health check for the ghidra-headless-mcp connection.

Connects, performs the MCP handshake, calls health.ping + ghidra.info, and lists open sessions.
Exit 0 = healthy, 3 = server unreachable (use this to gate the integration tests)."""
import sys, os, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ghcm


def main():
    print("ghidra-headless-mcp @ %s:%d" % (ghcm.HOST, ghcm.PORT))
    client = ghcm.Client()        # exits 3 (EXIT_UNREACHABLE) with a clear message if down
    try:
        ping, _ = client.call_tool("health.ping", {}, timeout=30)
        print("  health.ping  : %s" % ghcm.scrub(json.dumps(ping))[:200])
        try:
            info, _ = client.call_tool("ghidra.info", {}, timeout=60)
            print("  ghidra.info  : %s" % ghcm.scrub(json.dumps(info))[:400])
        except Exception as e:
            print("  ghidra.info  : <unavailable: %s>" % e)
        opened, _ = client.call_tool("program.list_open", {}, timeout=30)
        recs = ghcm._session_records(opened)
        print("  open sessions: %d" % len(recs))
        for r in recs[:20]:
            print("     %-34s %s" % (r.get("session_id", "?"),
                                     ghcm.scrub(str(r.get("filename") or r.get("program_name") or "?"))))
    finally:
        client.close()
    print("OK")


if __name__ == "__main__":
    main()
