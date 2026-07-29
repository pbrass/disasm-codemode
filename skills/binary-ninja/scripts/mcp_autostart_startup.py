# disasm-codemode: auto-start the Code Mode MCP server when a binary is open.
#
# WHY: the MCP server (akrutsinger binja-codemode-mcp) is normally started by a GUI click
# (bottom-left status button / Plugins > Code Mode MCP > Start Server) — there is no CLI flag
# or auto-start setting. With this hook installed, an AGENT can bootstrap BN fully autonomously:
#     DISPLAY=:0 /path/to/binaryninja /abs/path/to/file   # launches GUI + loads file
# and the MCP comes up on 127.0.0.1:42069 with no human interaction.
#
# INSTALL (once): append this file to ~/.binaryninja/startup.py
#     cat mcp_autostart_startup.py >> ~/.binaryninja/startup.py
# (startup.py runs in BN's Python console at GUI launch). Verify with `bn-status` after a relaunch.
# Harmless if the plugin is missing or the server is already running (it no-ops).

from binaryninja import core_ui_enabled

if core_ui_enabled():
    import sys as _sys, threading as _th, binaryninja as _bn

    def _ds_find_bv():
        from binaryninjaui import UIContext
        for _c in UIContext.allContexts():
            try:
                for _v, _nm in _c.getAvailableBinaryViews():
                    return _v
            except Exception:
                pass
        return None

    def _ds_autostart():
        try:
            _inst = None
            for _n, _m in list(_sys.modules.items()):
                if _n.endswith("binja_codemode_mcp") and getattr(_m, "plugin_instance", None) is not None:
                    _inst = _m.plugin_instance
                    break
            if _inst is None or getattr(_inst, "_server", None) is not None:
                return  # plugin not loaded, or server already running
            _bv = _ds_find_bv()
            if _bv is not None:
                _inst.start_server(_bv)
                _bn.log_info("disasm-codemode: auto-started Code Mode MCP")
        except Exception as _e:
            _bn.log_warn("disasm-codemode autostart: %r" % _e)

    # Retry until a BV is ready (a large .bndb opened from the CLI can take minutes to load/analyze,
    # far past a fixed 15 s window) or the server is up. Re-schedules itself every few seconds up to a cap.
    _ds_state = {"tries": 0}
    def _ds_retry():
        _ds_state["tries"] += 1
        _bn.execute_on_main_thread(_ds_autostart)
        # stop once the server is running or after ~10 min (120 * 5 s)
        try:
            _up = any(_n.endswith("binja_codemode_mcp") and getattr(_m, "plugin_instance", None) is not None
                      and getattr(_m.plugin_instance, "_server", None) is not None
                      for _n, _m in list(_sys.modules.items()))
        except Exception:
            _up = False
        if not _up and _ds_state["tries"] < 120:
            _th.Timer(5.0, _ds_retry).start()
    for _d in (3.0, 6.0, 10.0):
        _th.Timer(_d, lambda: _bn.execute_on_main_thread(_ds_autostart)).start()
    _th.Timer(15.0, _ds_retry).start()
