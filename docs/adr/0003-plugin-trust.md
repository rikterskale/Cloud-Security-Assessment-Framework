# ADR 0003: allow-list external plugins

Third-party check modules are discovered only through registered entry points and are constrained by `CSAF_PLUGIN_ALLOWLIST`. Built-in modules win collisions. This keeps extension useful without letting an installed package silently add assessment behavior.
