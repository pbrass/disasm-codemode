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

    # Poll a few times after launch (a file opened from the CLI / Plugin Manager may still be loading).
    for _d in (3.0, 6.0, 10.0, 15.0):
        _th.Timer(_d, lambda: _bn.execute_on_main_thread(_ds_autostart)).start()
