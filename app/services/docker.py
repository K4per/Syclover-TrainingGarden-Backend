from __future__ import annotations

import asyncio
import ipaddress
import json
import posixpath
import random
import re
import subprocess
import tempfile
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

from app.services.assets import extract_patch_archive

IMAGE_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/:@-]{0,254}$")
CONTAINER_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
FLAG_PATTERN = re.compile(r"^[A-Za-z0-9_{}.\-]{1,480}$")
CONTAINER_LABEL = "syclover.training-garden=true"


class ContainerError(RuntimeError):
    pass


@dataclass(frozen=True)
class StartedContainer:
    container_id: str
    public_port: int


@dataclass(frozen=True)
class ContainerState:
    status: str
    running: bool
    restarting: bool
    exit_code: int | None
    oom_killed: bool
    error: str
    restart_count: int = 0

    @property
    def active(self) -> bool:
        """Whether Docker still considers the workload live or recoverable."""
        return self.running or self.status in {"created", "paused"}


def _validated_bind_address(value: str) -> str:
    """Accept only literal IP addresses so the published port cannot be redirected."""
    candidate = value.strip().strip("[]")
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError as exc:
        raise ContainerError(f"Invalid instance bind address: {value}") from exc


def _port_spec(bind: str, internal_port: int, host_port: int | None = None) -> str:
    """Publish ``internal_port`` on an explicit host port, or let Docker choose one.

    Docker picks from the host's ephemeral range (``net.ipv4.ip_local_port_range``)
    when no host port is given, which is why a configured range has to be applied
    here rather than validated after the fact.
    """
    host_bind = f"[{bind}]" if ":" in bind else bind
    if host_port is None:
        return f"{host_bind}::{internal_port}"
    return f"{host_bind}:{host_port}:{internal_port}"


def _candidate_ports(port_range: range) -> list[int]:
    """Ports to try, rotated so concurrent starts do not all fight over one port."""
    ports = list(port_range)
    if len(ports) > 1:
        offset = random.randrange(len(ports))
        ports = ports[offset:] + ports[:offset]
    return ports


def _is_port_conflict(error: Exception) -> bool:
    """Whether a failed start only lost a race for the host port."""
    message = str(error).lower()
    return "port is already allocated" in message or "address already in use" in message


class DockerService:
    def __init__(self, mode: str = "cli"):
        self.mode = mode
        self._buildx: bool | None = None
        self._mock_next_port = 30000

    def start(
        self,
        *,
        image: str,
        internal_port: int,
        name: str,
        user_id: str,
        challenge_id: str,
        bind_address: str = "127.0.0.1",
        port_range: range | None = None,
        flag: str | None = None,
    ) -> StartedContainer:
        if not IMAGE_PATTERN.fullmatch(image) or not CONTAINER_PATTERN.fullmatch(name):
            raise ContainerError("Unsafe container image or name")
        if flag is not None and not FLAG_PATTERN.fullmatch(flag):
            raise ContainerError("Unsafe instance flag value")
        if self.mode == "mock":
            public_port = self._mock_next_port
            self._mock_next_port += 1
            return StartedContainer(container_id=f"mock-{name}", public_port=public_port)
        bind = _validated_bind_address(bind_address)
        if port_range is None:
            # No configured window: let Docker pick, as it always has.
            return self._start_container(
                image=image,
                internal_port=internal_port,
                name=name,
                user_id=user_id,
                challenge_id=challenge_id,
                bind=bind,
                flag=flag,
                port_spec=_port_spec(bind, internal_port),
                port_range=None,
            )
        if len(port_range) == 0:
            raise ContainerError("The configured instance port range is empty")
        candidates = _candidate_ports(port_range)
        for index, host_port in enumerate(candidates):
            try:
                return self._start_container(
                    image=image,
                    internal_port=internal_port,
                    name=name,
                    user_id=user_id,
                    challenge_id=challenge_id,
                    bind=bind,
                    flag=flag,
                    port_spec=_port_spec(bind, internal_port, host_port),
                    port_range=port_range,
                )
            except ContainerError as exc:
                if not _is_port_conflict(exc):
                    raise
                # Someone took this port between picking it and binding it. Clean the
                # half-created container up so the retry can reuse the same name.
                self._discard_container(name)
                if index + 1 == len(candidates):
                    raise ContainerError(
                        "No free host port in the configured range "
                        f"{port_range.start}-{port_range.stop - 1}: all {len(candidates)} port(s) "
                        "are in use. Widen SYCL_INSTANCE_PORT_RANGE_START/END or wait for "
                        "instances to expire."
                    ) from exc
        raise ContainerError("No usable host port in the configured instance port range")

    def _start_container(
        self,
        *,
        image: str,
        internal_port: int,
        name: str,
        user_id: str,
        challenge_id: str,
        bind: str,
        flag: str | None,
        port_spec: str,
        port_range: range | None,
    ) -> StartedContainer:
        command = [
            "docker",
            "create" if flag else "run",
            *([] if flag else ["--detach"]),
            "--name",
            name,
            "--label",
            CONTAINER_LABEL,
            "--label",
            f"syclover.user={user_id}",
            "--label",
            f"syclover.challenge={challenge_id}",
            "--memory",
            "512m",
            "--cpus",
            "1.0",
            "--pids-limit",
            "256",
            "--security-opt",
            "no-new-privileges",
            "--restart",
            "unless-stopped",
            "--env",
            f"FLAG={flag}" if flag else "FLAG=",
            "-p",
            port_spec,
            image,
        ]
        container_id = self._run(command, timeout=90).strip()
        if flag:
            # A created container has its image filesystem but its service has not
            # started yet. Populate missing flag files before the program can read them.
            try:
                self._ensure_flag_files(container_id, flag)
                self._run(["docker", "start", container_id], timeout=45)
            except ContainerError:
                self._discard_container(container_id)
                raise
        public_port = self._await_published_port(container_id, internal_port)
        if public_port is None:
            logs = self.container_logs(container_id)
            state = self.container_state(container_id)
            self.stop(container_id)
            raise ContainerError(
                "The container did not stay up long enough to publish its port; check the "
                f"challenge command and port. {self.failure_message(state, logs)}"
            )
        state = self._await_stable_container(container_id)
        if state is None or not state.running or state.restart_count > 0:
            logs = self.container_logs(container_id)
            self.stop(container_id)
            raise ContainerError(
                "The container exited during startup. "
                f"{self.failure_message(state, logs)}"
            )
        if port_range is not None and public_port not in port_range:
            self.stop(container_id)
            raise ContainerError(
                f"Docker published port {public_port}, which is outside the configured range "
                f"{port_range.start}-{port_range.stop - 1}"
            )
        return StartedContainer(container_id=container_id, public_port=public_port)

    def _ensure_flag_files(self, container_id: str, flag: str) -> None:
        """Create conventional flag paths only when the image does not provide them."""
        workdir = self._run(
            ["docker", "inspect", "--format", "{{.Config.WorkingDir}}", container_id],
            timeout=15,
        ).strip()
        paths = {"/flag", "/flag.txt"}
        if workdir.startswith("/") and ":" not in workdir and "\n" not in workdir:
            paths.add(posixpath.join(posixpath.normpath(workdir), "flag"))
        with tempfile.TemporaryDirectory(prefix="syclover-flag-") as temporary:
            source = Path(temporary) / "flag"
            source.write_text(f"{flag}\n", encoding="utf-8")
            source.chmod(0o644)
            for index, path in enumerate(sorted(paths)):
                try:
                    self._run(
                        ["docker", "cp", f"{container_id}:{path}", str(Path(temporary) / f"probe-{index}")],
                        timeout=15,
                    )
                except ContainerError as exc:
                    message = str(exc).lower()
                    if "could not find the file" not in message and "no such file" not in message:
                        raise
                    self._run(["docker", "cp", str(source), f"{container_id}:{path}"], timeout=15)

    def _discard_container(self, name: str) -> None:
        """Best-effort removal of a container left behind by a failed start attempt."""
        if self.mode == "mock" or not CONTAINER_PATTERN.fullmatch(name):
            return
        try:
            self._run(["docker", "rm", "--force", "--volumes", name], timeout=20)
        except ContainerError:
            pass

    async def build(self, *, context: Path, image: str, on_output=None) -> str:
        """Build an image, forwarding each output chunk to ``on_output`` when given."""
        if not IMAGE_PATTERN.fullmatch(image):
            raise ContainerError("Unsafe image tag")
        if not (context / "Dockerfile").is_file():
            raise ContainerError("Dockerfile is missing from the build context")
        if self.mode == "mock":
            message = f"Mock mode: built {image} from {context.name}/Dockerfile."
            if on_output:
                on_output(message + "\n")
            return message
        command = ["docker", "build"]
        if await self._supports_buildx():
            # BuildKit needs --progress plain to emit line-oriented, streamable logs.
            command += ["--progress", "plain"]
        # Base images already present locally are reused: forcing --pull turns a registry
        # hiccup into a failed challenge build on an otherwise healthy host.
        command += ["--tag", image, str(context)]
        return await self._run_streaming(command, timeout=600, on_output=on_output)

    async def _supports_buildx(self) -> bool:
        """Detect the buildx plugin once; the legacy builder rejects ``--progress``."""
        if self._buildx is None:
            try:
                process = await asyncio.create_subprocess_exec(
                    "docker",
                    "buildx",
                    "version",
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                self._buildx = (await asyncio.wait_for(process.wait(), timeout=10)) == 0
            except (OSError, TimeoutError):
                self._buildx = False
        return self._buildx

    @staticmethod
    async def _run_streaming(command: list[str], timeout: int, on_output=None) -> str:
        """Run a command, emitting output as it arrives, and return the whole log."""
        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
        except FileNotFoundError as exc:
            raise ContainerError("Docker CLI is not installed") from exc
        collected: list[str] = []

        async def consume() -> None:
            assert process.stdout is not None
            while True:
                chunk = await process.stdout.read(4096)
                if not chunk:
                    break
                text = chunk.decode(errors="replace")
                collected.append(text)
                if on_output:
                    on_output(text)

        try:
            await asyncio.wait_for(consume(), timeout=timeout)
        except TimeoutError as exc:
            process.kill()
            await process.wait()
            raise ContainerError("Docker operation timed out") from exc
        await process.wait()
        output = "".join(collected).strip()
        if process.returncode != 0:
            raise ContainerError(output or f"Docker exited with code {process.returncode}")
        return output

    def stop(self, container_id: str) -> None:
        """Stop and remove one challenge container.

        ``--restart unless-stopped`` keeps patched containers alive across daemon
        restarts, so removing has to be explicit instead of relying on ``--rm``.
        """
        if not CONTAINER_PATTERN.fullmatch(container_id):
            raise ContainerError("Unsafe container identifier")
        if self.mode == "mock":
            return
        try:
            self._run(["docker", "rm", "--force", "--volumes", container_id], timeout=30)
        except ContainerError as remove_error:
            # Fall back to a plain stop so a removal race is not reported as a failure.
            try:
                self._run(["docker", "stop", "--time", "5", container_id], timeout=15)
            except ContainerError as stop_error:
                if "no such container" in str(stop_error).lower():
                    return
                raise remove_error from stop_error

    def list_managed_containers(self) -> list[dict[str, str]]:
        """Challenge containers carrying the platform label, as ``id``/``name`` pairs."""
        if self.mode == "mock":
            return []
        # ``--quiet`` would silently disable ``--format``, so request both columns directly.
        output = self._run(
            [
                "docker",
                "ps",
                "--all",
                "--no-trunc",
                "--filter",
                f"label={CONTAINER_LABEL}",
                "--format",
                "{{.ID}}\t{{.Names}}",
            ],
            timeout=15,
        )
        containers: list[dict[str, str]] = []
        for line in output.splitlines():
            parts = line.split("\t")
            if len(parts) != 2 or not parts[0].strip():
                continue
            containers.append({"id": parts[0].strip(), "name": parts[1].strip()})
        return containers

    def _await_published_port(
        self, container_id: str, internal_port: int, attempts: int = 5, delay: float = 0.6
    ) -> int | None:
        """Read the host port Docker published, tolerating a short start-up window."""
        for attempt in range(attempts):
            output = ""
            try:
                output = self._run(
                    ["docker", "port", container_id, f"{internal_port}/tcp"], timeout=10
                ).strip()
            except ContainerError:
                output = ""
            for line in output.splitlines():
                _, _, port = line.rpartition(":")
                if port.isdigit():
                    return int(port)
            if attempt + 1 < attempts:
                time.sleep(delay)
        return None

    def container_logs(self, container_id: str, tail: int = 5) -> str:
        """Best-effort tail of a container log, used to explain start failures."""
        if self.mode == "mock" or not CONTAINER_PATTERN.fullmatch(container_id):
            return ""
        try:
            return self._run(
                ["docker", "logs", "--tail", str(tail), container_id], timeout=10
            ).strip()[:500]
        except ContainerError:
            return ""

    def container_state(self, container_id: str) -> ContainerState | None:
        """Return Docker's runtime state, or ``None`` only when the container is absent.

        A daemon timeout or permission failure is deliberately propagated. Treating every
        inspect error as a missing container used to turn transient Docker failures into the
        misleading ``Container exited unexpectedly`` instance state.
        """
        if not CONTAINER_PATTERN.fullmatch(container_id):
            raise ContainerError("Unsafe container identifier")
        if self.mode == "mock":
            return ContainerState("running", True, False, 0, False, "")
        try:
            output = self._run(
                [
                    "docker",
                    "inspect",
                    "--format",
                    "{{json .State}}\t{{.RestartCount}}",
                    container_id,
                ],
                timeout=15,
            )
        except ContainerError as exc:
            detail = str(exc).lower()
            if "no such object" in detail or "no such container" in detail:
                return None
            raise
        state_output, separator, restart_output = output.rpartition("\t")
        if not separator:
            state_output = output
            restart_output = "0"
        try:
            raw = json.loads(state_output)
        except (TypeError, json.JSONDecodeError) as exc:
            raise ContainerError(f"Docker returned an invalid container state: {output[:200]}") from exc
        if not isinstance(raw, dict):
            raise ContainerError(f"Docker returned an invalid container state: {output[:200]}")
        exit_code = raw.get("ExitCode")
        try:
            restart_count = int(restart_output)
        except ValueError:
            restart_count = 0
        return ContainerState(
            status=str(raw.get("Status") or "unknown").lower(),
            running=bool(raw.get("Running")),
            restarting=bool(raw.get("Restarting")),
            exit_code=exit_code if isinstance(exit_code, int) else None,
            oom_killed=bool(raw.get("OOMKilled")),
            error=str(raw.get("Error") or "").strip(),
            restart_count=max(restart_count, 0),
        )

    def _await_stable_container(
        self,
        container_id: str,
        attempts: int = 5,
        delay: float = 0.6,
        stability_window: float = 5.0,
    ) -> ContainerState | None:
        """Reject an image that exits or enters a restart loop just after startup.

        Keeping the process alive across a short stability window also gives ordinary
        services time to bind their socket before the instance is advertised as running.
        """
        last_state: ContainerState | None = None
        for attempt in range(attempts):
            last_state = self.container_state(container_id)
            if last_state is None:
                return None
            if last_state.restart_count > 0:
                return last_state
            if last_state.running:
                # A second observation prevents a process that exits immediately after its
                # port mapping appears from being recorded as a healthy running instance.
                if attempt + 1 < attempts:
                    time.sleep(stability_window)
                    confirmed = self.container_state(container_id)
                    if (
                        confirmed is not None
                        and confirmed.running
                        and confirmed.restart_count == last_state.restart_count
                    ):
                        return confirmed
                    last_state = confirmed
                else:
                    return last_state
            if last_state is not None and last_state.status in {"exited", "dead", "removing"}:
                return last_state
            if attempt + 1 < attempts:
                time.sleep(delay)
        return last_state

    @staticmethod
    def failure_message(state: ContainerState | None, logs: str = "") -> str:
        """Build an actionable, bounded diagnostic for an unavailable container."""
        if state is None:
            message = "Container is missing; it may have been removed outside the platform."
        else:
            parts = [f"Docker status: {state.status}"]
            if state.exit_code is not None:
                parts.append(f"exit code: {state.exit_code}")
            if state.oom_killed:
                parts.append("killed by the memory limit (OOM)")
            if state.restart_count:
                parts.append(f"restart count: {state.restart_count}")
            if state.error:
                parts.append(f"runtime error: {state.error[:240]}")
            message = "; ".join(parts) + "."
        clean_logs = " ".join(logs.split())[:500]
        if clean_logs:
            message += f" Last output: {clean_logs}"
        return message

    def container_port(self, container_id: str, internal_port: int) -> int | None:
        """Current host port published for a container, or ``None`` when it is gone.

        Docker may hand out a different host port when a container is restarted outside
        the platform, so the stored mapping is refreshed from the daemon.
        """
        if not CONTAINER_PATTERN.fullmatch(container_id):
            raise ContainerError("Unsafe container identifier")
        if self.mode == "mock":
            return None
        try:
            output = self._run(
                ["docker", "port", container_id, f"{internal_port}/tcp"], timeout=10
            ).strip()
        except ContainerError:
            return None
        for line in output.splitlines():
            _, _, port = line.rpartition(":")
            if port.isdigit():
                return int(port)
        return None

    def restart(self, container_id: str, internal_port: int, timeout: int = 60) -> None:
        """Restart a challenge container and wait until it serves connections again.

        Patches change the challenge source, and challenge entry points rebuild from that
        source on start, so a restart is what makes a defence actually take effect. Docker
        may also publish a different host port after a restart, which the caller re-reads
        through :meth:`container_port`.
        """
        if not CONTAINER_PATTERN.fullmatch(container_id):
            raise ContainerError("Unsafe container identifier")
        if self.mode == "mock":
            return
        self._run(["docker", "restart", container_id], timeout=timeout)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            port = self.container_port(container_id, internal_port)
            if port is not None:
                return
            time.sleep(1)
        raise ContainerError("The patched instance did not become reachable after a restart")

    def remove_image(self, image: str) -> None:
        """Delete a challenge image; failures are reported, never raised."""
        if not IMAGE_PATTERN.fullmatch(image):
            raise ContainerError("Unsafe image tag")
        if self.mode == "mock":
            return
        try:
            self._run(["docker", "image", "rm", image], timeout=30)
        except ContainerError as exc:
            # An image still referenced by a container cannot be removed; that is fine.
            raise ContainerError(str(exc)) from exc

    def container_exists(self, container_id: str) -> bool:
        """Compatibility helper: whether the container object exists in Docker."""
        return self.container_state(container_id) is not None

    def apply_asset(
        self, container_id: str, path: Path, kind: str, *, category: str | None = None
    ) -> str:
        if not CONTAINER_PATTERN.fullmatch(container_id):
            raise ContainerError("Unsafe container identifier")
        if self.mode == "mock":
            return f"Mock mode: {kind} {path.name} accepted for {container_id}."
        if kind in {"check_script", "fix_script"}:
            target = f"/tmp/syclover-{path.name}"
            self._run(["docker", "cp", str(path), f"{container_id}:{target}"], timeout=20)
            # The interpreter is decided from the host-side file: the container path only
            # exists inside the challenge container.
            command = ["docker", "exec", container_id, *self._script_command(path, target)]
        elif kind == "patch":
            bundle_id = uuid.uuid4().hex
            with tempfile.TemporaryDirectory(prefix="syclover-patch-") as directory:
                try:
                    extract_patch_archive(path, Path(directory), category=category)
                except (ValueError, OSError) as exc:
                    raise ContainerError(str(exc)) from exc
                target = f"/tmp/syclover-patch-{bundle_id}"
                self._run(["docker", "cp", f"{directory}/.", f"{container_id}:{target}"], timeout=20)
                # docker cp creates the staging directory as root. Challenge images
                # commonly run as www-data, so make the copied tree accessible to
                # the container's default user before it copies files into /app.
                uid = self._run(["docker", "exec", container_id, "id", "-u"], timeout=10).strip()
                gid = self._run(["docker", "exec", container_id, "id", "-g"], timeout=10).strip()
                if not uid.isdecimal() or not gid.isdecimal():
                    raise ContainerError("Cannot determine the challenge container user")
                self._run(
                    ["docker", "exec", "--user", "0", container_id, "chown", "-R", f"{uid}:{gid}", target],
                    timeout=20,
                )
                command = [
                    "docker",
                    "exec",
                    container_id,
                    "/bin/sh",
                    "-c",
                    (
                        f"set -eu; trap 'rm -rf {target}' EXIT; "
                        f"cp -a {target}/. /app/; cd /app; /bin/sh /app/fix.sh"
                    ),
                ]
                return self._run(command, timeout=60)
        else:
            raise ContainerError("Only patches and fix scripts can be applied")
        return self._run(command, timeout=30)

    @staticmethod
    def _script_command(host_path: Path, container_target: str) -> list[str]:
        """Pick the interpreter from the shebang so Python checks work as well as shell ones."""
        try:
            first_line = host_path.read_text(encoding="utf-8", errors="replace").splitlines()[0]
        except (OSError, IndexError):
            first_line = ""
        if "python" in first_line:
            return ["python3", container_target]
        return ["/bin/sh", container_target]

    @staticmethod
    def _run(command: list[str], timeout: int) -> str:
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                check=False,
                text=True,
                timeout=timeout,
            )
        except FileNotFoundError as exc:
            raise ContainerError("Docker CLI is not installed") from exc
        except subprocess.TimeoutExpired as exc:
            raise ContainerError("Docker operation timed out") from exc
        output = (result.stdout + result.stderr).strip()
        if result.returncode != 0:
            raise ContainerError(output or f"Docker exited with code {result.returncode}")
        return output

    @staticmethod
    async def _run_async(command: list[str], timeout: int) -> str:
        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except FileNotFoundError as exc:
            raise ContainerError("Docker CLI is not installed") from exc
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
        except TimeoutError as exc:
            process.kill()
            await process.communicate()
            raise ContainerError("Docker operation timed out") from exc
        output = (stdout + stderr).decode(errors="replace").strip()
        if process.returncode != 0:
            raise ContainerError(output or f"Docker exited with code {process.returncode}")
        return output
