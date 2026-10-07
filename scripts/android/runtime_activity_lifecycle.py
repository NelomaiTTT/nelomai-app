#!/usr/bin/env python3
"""Add a per-Activity pre-admission opt-out to locked Wry/Tauri generated sources.

Android superclass calls and the normal native path stay intact. This is run by
both source generators and immediately before Kotlin compilation (including CLI
regeneration). Unexpected template changes fail the build for review.
"""
import argparse
from pathlib import Path
import re


def guard_source(name, source):
    if name == "WryActivity.kt":
        declaration = "abstract class WryActivity : AppCompatActivity() {"
        callbacks = ("onCreate(savedInstanceState)", "onWindowFocusChanged(hasFocus)",
                     "onSaveInstanceState(outState)", "onDestroy()", "onLowMemory()", "onNewIntent(intent)")
        indent, native, count = "        ", "Rust.", 7
    elif name == "TauriActivity.kt":
        declaration = "abstract class TauriActivity : WryActivity() {"
        callbacks = ("onCreate(savedInstanceState)", "onNewIntent(intent)", "onRestart()",
                     "onDestroy()", "onConfigurationChanged(newConfig)")
        indent, native, count = "    ", "PluginManager.", 5
    else:
        return source

    hook = "\n    protected open val runtimeLifecycleEnabled: Boolean = true\n"
    guard = "\n" + indent + "if (!runtimeLifecycleEnabled) return"
    # Normalize our own additions so rerunning after either generator is harmless.
    source = source.replace(declaration + hook, declaration).replace(guard, "")
    if source.count(declaration) != 1:
        raise ValueError(f"{name}: unexpected Activity declaration")
    prefix, body = source.split(declaration)
    if body.count(native) != count:
        raise ValueError(f"{name}: native callback surface changed; review lifecycle guards")
    guarded_calls = 0
    guarded_observers = 0
    for callback in callbacks:
        anchor = indent + "super." + callback
        if body.count(anchor + "\n") != 1:
            raise ValueError(f"{name}: unexpected superclass callback {callback}")
        method = callback.split('(')[0]
        region = re.search(r'override fun ' + method + r'\([^\n]*\) \{\n(.*?)\n'
                           + indent[:len(indent) // 2] + r'\}', body, re.DOTALL)
        if region is None or not region[1].startswith(anchor + '\n'):
            raise ValueError(f"{name}: {method} must call Android super before native work")
        guarded_calls += region[1].count(native)
        guarded_observers += region[1].count('.lifecycle.addObserver(')
        body = body.replace(anchor + "\n", anchor + guard + "\n")
    if guarded_calls != count or guarded_observers != body.count('.lifecycle.addObserver('):
        raise ValueError(f"{name}: native work outside guarded lifecycle callbacks")
    return prefix + declaration + (hook if name == "WryActivity.kt" else "") + body


def guard_directory(directory):
    outputs = {}
    for name in ("WryActivity.kt", "TauriActivity.kt"):
        path = directory / name
        source = path.read_text()
        guarded = guard_source(name, source)
        if guarded != source:
            outputs[path] = guarded
    for path, guarded in outputs.items():
        path.write_text(guarded)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    guard_directory(parser.parse_args().directory)
