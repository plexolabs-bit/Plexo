# StellarHub ZK reference · https://stellarhub.io
"""Proof generation wrappers (reference implementation).

Backends are invoked out-of-process to isolate CPU-heavy work (2-5s per
Groth16 proof) from the FastAPI event loop. Currently stubbed; production
integration will shell out to snarkjs/circom CLI or an arkworks-based
Rust binary.
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import shutil
import tempfile
from pathlib import Path
from typing import Any, Dict

from .types import Proof, ProofType

logger = logging.getLogger(__name__)


class ProofGenerationError(RuntimeError):
    """Raised when the underlying prover fails or is unavailable."""


def _resolve_build_dir() -> Path:
    """Locate the compiled-circuit build directory.

    Honours ``ZK_CIRCUITS_BUILD_DIR`` (env-configurable paths) first, then walks
    up for the repo root (the directory that holds ``circuits/`` + ``build/``) so
    no absolute path is hardcoded.
    """
    override = os.getenv("ZK_CIRCUITS_BUILD_DIR")
    if override:
        return Path(override)
    here = Path(__file__).resolve()
    for parent in here.parents:
        if (parent / "circuits").is_dir() and (parent / "build").is_dir():
            return parent / "build"
    # Last resort: the repo root relative to this reference file.
    return here.parents[1] / "build"


def _snarkjs_bin() -> list[str] | None:
    """Resolve a runnable snarkjs invocation, or None if unavailable.

    Prefers a ``snarkjs`` on PATH; falls back to ``npx snarkjs`` when Node is
    present. Returns None when neither exists so the caller can degrade to the
    scaffold 501 instead of raising an opaque subprocess error.
    """
    direct = shutil.which("snarkjs")
    if direct:
        return [direct]
    npx = shutil.which("npx")
    if npx:
        return [npx, "--no-install", "snarkjs"]
    return None


class ProofGenerator:
    """Async facade over external proving backends.

    All methods return fully-populated :class:`Proof` envelopes. Callers
    should treat the generator as stateless; backend processes are spawned
    per call.
    """

    def __init__(self, prover_bin: str | None = None, keys_dir: str | None = None) -> None:
        # TODO: wire prover_bin (snarkjs/arkworks) and keys_dir (proving keys).
        self._prover_bin = prover_bin
        self._keys_dir = keys_dir

    async def generate_groth16(
        self,
        circuit_path: str,
        inputs: Dict[str, Any],
        verification_key_id: str = "",
    ) -> Proof:
        """Generate a Groth16 proof (BLS12-381) via an out-of-process snarkjs call.

        Runs ``snarkjs groth16 fullprove`` against the compiled circuit artefacts
        (``<circuit>.wasm`` + ``<circuit>_final.zkey`` in the build dir). The
        subprocess keeps the 2-5s CPU-bound proving off the FastAPI event loop.

        Degrades to :class:`ProofGenerationError` (surfaced as 501 by the router)
        when snarkjs or the compiled artefacts are absent — i.e. before the
        toolchain is installed and ``build.sh`` has run. This preserves the
        scaffold behaviour on an un-provisioned host while becoming live the
        moment the artefacts exist.
        """
        circuit = Path(circuit_path).name  # tolerate a bare name or a path
        build_dir = _resolve_build_dir()
        wasm = build_dir / f"{circuit}.wasm"
        zkey = build_dir / f"{circuit}_final.zkey"

        bin_cmd = _snarkjs_bin()
        if bin_cmd is None:
            raise ProofGenerationError(
                "snarkjs not found (install via `npm i -g snarkjs` or provide npx). "
                "See docs/RUNBOOK.md."
            )
        if not wasm.is_file() or not zkey.is_file():
            raise ProofGenerationError(
                f"compiled circuit artefacts missing for '{circuit}' in {build_dir} "
                "(run scripts/build.sh first — it compiles + dev-setup in one pass)."
            )

        return await self._run_snarkjs_fullprove(
            bin_cmd, circuit, wasm, zkey, inputs, verification_key_id
        )

    async def _run_snarkjs_fullprove(
        self,
        bin_cmd: list[str],
        circuit: str,
        wasm: Path,
        zkey: Path,
        inputs: Dict[str, Any],
        verification_key_id: str,
    ) -> Proof:
        """Run snarkjs in a temp workspace and assemble the :class:`Proof` envelope."""
        with tempfile.TemporaryDirectory(prefix="zk-prove-") as tmp:
            tmpdir = Path(tmp)
            input_path = tmpdir / "input.json"
            proof_path = tmpdir / "proof.json"
            public_path = tmpdir / "public.json"
            input_path.write_text(json.dumps(inputs))

            cmd = [
                *bin_cmd, "groth16", "fullprove",
                str(input_path), str(wasm), str(zkey),
                str(proof_path), str(public_path),
            ]
            logger.info("zk.generate_groth16 circuit=%s (snarkjs)", circuit)

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                _, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)
            except asyncio.TimeoutError as exc:
                proc.kill()
                raise ProofGenerationError("snarkjs proving timed out (30s)") from exc

            if proc.returncode != 0:
                detail = (stderr or b"").decode(errors="replace")[:500]
                raise ProofGenerationError(f"snarkjs failed: {detail}")

            try:
                proof_json = json.loads(proof_path.read_text())
                public_signals = json.loads(public_path.read_text())
            except (OSError, json.JSONDecodeError) as exc:
                raise ProofGenerationError(f"snarkjs output unreadable: {exc}") from exc

        proof_b64 = base64.b64encode(
            json.dumps(proof_json).encode("utf-8")
        ).decode("ascii")
        public_inputs = [int(x) for x in public_signals]

        return Proof(
            proof_type=ProofType.GROTH16,
            proof_bytes=proof_b64,
            public_inputs=public_inputs,
            verification_key_id=verification_key_id or circuit,
            circuit_id=circuit,
        )

    async def generate_plonk(
        self,
        circuit_path: str,
        inputs: Dict[str, Any],
        verification_key_id: str = "",
    ) -> Proof:
        """Generate a PLONK proof (universal setup).

        TODO: subprocess wrapper over `snarkjs plonk prove`.
        """
        logger.info("zk.generate_plonk circuit=%s (stub)", circuit_path)
        raise ProofGenerationError(
            "PLONK backend not wired (reference scaffold)."
        )

    async def generate_stark(
        self,
        circuit_path: str,
        inputs: Dict[str, Any],
        verification_key_id: str = "",
    ) -> Proof:
        """Generate a STARK proof (no trusted setup).

        TODO: pending backend selection (winterfell / risc0 / Stone).
        """
        logger.info("zk.generate_stark circuit=%s (stub)", circuit_path)
        raise ProofGenerationError(
            "STARK backend not wired (reference scaffold)."
        )

    async def generate(
        self,
        proof_type: ProofType,
        circuit_path: str,
        inputs: Dict[str, Any],
        verification_key_id: str = "",
    ) -> Proof:
        """Dispatch to the appropriate backend based on `proof_type`."""
        if proof_type is ProofType.GROTH16:
            return await self.generate_groth16(circuit_path, inputs, verification_key_id)
        if proof_type is ProofType.PLONK:
            return await self.generate_plonk(circuit_path, inputs, verification_key_id)
        if proof_type is ProofType.STARK:
            return await self.generate_stark(circuit_path, inputs, verification_key_id)
        raise ProofGenerationError(f"Unknown proof_type: {proof_type}")
