"""Plugin subsystem (spec: PLUGIN AND ADAPTER ARCHITECTURE).

Plugins extend KSEC with new capabilities (adapters + parsers) without
touching the core engine. Every plugin ships a manifest declaring its
version, capabilities, permissions, dependencies and trust level; loading is
permission-controlled and untrusted plugins never execute.
"""