"""Diagnostic common wrapper over the exact released Windows runtime. No signing/publishing."""
import base64
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("container", ROOT / "scripts/build-runtime-acceptance-container.py")
container = importlib.util.module_from_spec(spec)
spec.loader.exec_module(container)


def main():
    signed = (ROOT / "signed").resolve()
    output = (ROOT / "startup-diagnostic").resolve()
    if output.exists():
        raise ValueError("diagnostic output already exists")
    key = signed / "runtime-public-key.raw"
    if base64.b64encode(key.read_bytes()).decode() != os.environ["NELOMAI_RELEASE_MANIFEST_PUBLIC_KEY_B64"]:
        raise ValueError("retained artifact key differs from configured release pin")
    subprocess.run(["cargo", "build", "--locked", "-p", "nelomai-contracts", "--bin", "verify-runtime-manifest"],
                   cwd=ROOT, check=True)
    stage = output / "staged"
    container.stage_signed(signed,
        "e0820438778ace0d3a4dced771e19a06bbdbef66c236a140067f1b9866a0789f",
        stage, key, "windows", "x86_64", "cf257ed9f0a1ec7a45f5e36460129780c400e3e7", "shipping")
    package = container.package_desktop(stage, output / "work", key, "windows", "x86_64",
        features="custom-protocol,startup-diagnostics")
    delivery = output / "delivery"
    delivery.mkdir()
    destination = delivery / "nelomai-0.2.18-windows-startup-diagnostic.exe"
    shutil.copyfile(package, destination)
    (delivery / "SHA256SUMS.txt").write_text(container.verifier.digest(destination) + "  " + destination.name + "\n")
    (delivery / "README.txt").write_text(
        "Диагностическая сборка, не обычный релиз. Установить поверх 0.2.18, не удаляя данные.\n"
        "Сначала закройте Nelomai. После установки запустите обычным ярлыком.\n"
        "Отправьте %LOCALAPPDATA%\\Nelomai\\startup-diagnostics.log сразу после неудачного запуска.\n"
        "Журнал перезаписывается при каждом запуске. Он содержит этапы запуска и ошибки, не снимок учётных данных.\n"
        "Runtime и служба взяты без изменений из сборки 34267783952.\n", encoding="utf-8")


if __name__ == "__main__":
    main()
