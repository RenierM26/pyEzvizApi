"""Optional real go2rtc REST contract; never a camera or account acquisition."""
import asyncio
import json
import os
from pathlib import Path
import socket

from aiohttp import ClientError, ClientSession
from custom_components.ezviz_native.relay import SharedRelay
import pytest


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.mark.parametrize("atomic_ownership", [False, True])
@pytest.mark.parametrize("raw_config", [False, True])
async def test_real_go2rtc_runtime_registration_and_removal(tmp_path, socket_enabled, raw_config, atomic_ownership):
    binary = os.environ.get("GO2RTC_TEST_BINARY")
    if not binary:
        pytest.skip("Set GO2RTC_TEST_BINARY for optional real-server contract")
    api_port, rtsp_port = free_port(), free_port()
    config = tmp_path / "go2rtc.yaml"
    initial = json.dumps({
        "api": {"listen": f"127.0.0.1:{api_port}"},
        "rtsp": {"listen": f"127.0.0.1:{rtsp_port}"},
        "webrtc": {"listen": ""},
        "streams": {"unrelated": "http://127.0.0.1:1/unrelated.ts"},
    })
    config.write_text(initial)
    process = await asyncio.create_subprocess_exec(
        str(Path(binary).resolve()), "-config", initial if raw_config else str(config),
        stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
    )
    try:
        async with ClientSession() as session:
            api = f"http://127.0.0.1:{api_port}/api/streams"
            async with asyncio.timeout(5):
                while True:
                    try:
                        async with session.get(api) as response:
                            if response.status == 200:
                                break
                    except ClientError:
                        pass
                    await asyncio.sleep(0.02)
            relay = SharedRelay(session, api_port, rtsp_port, atomic_ownership=atomic_ownership)
            await asyncio.gather(*(relay.source("http://127.0.0.1:1/native?auth=TEST_ONLY")
                                   for _ in range(8)))
            assert config.read_text() == initial  # No capability persisted.
            async with session.get(api) as response:
                streams = await response.json()
            assert set(streams) == {"unrelated", relay.name}
            # Unreachable source registration must remain lazy, not a failed dial.
            assert all("bytes_recv" not in p for p in streams[relay.name]["producers"])
            assert await relay.close()
            async with session.get(api) as response:
                streams = await response.json()
            assert set(streams) == {"unrelated"}
            assert "TEST_ONLY" not in config.read_text()
            assert "unrelated" in config.read_text()
    finally:
        if process.returncode is None:
            process.terminate()
        await asyncio.wait_for(process.wait(), 5)


@pytest.mark.parametrize("atomic_ownership", [False, True])
@pytest.mark.parametrize("reassigned", [False, True])
async def test_real_restart_does_not_delete_reassigned_name(tmp_path, socket_enabled, reassigned, atomic_ownership):
    binary = os.environ.get("GO2RTC_TEST_BINARY")
    if not binary:
        pytest.skip("Set GO2RTC_TEST_BINARY for optional real-server contract")
    api_port, rtsp_port = free_port(), free_port()
    config = tmp_path / "restart.json"
    config.write_text(json.dumps({
        "api": {"listen": f"127.0.0.1:{api_port}"},
        "rtsp": {"listen": f"127.0.0.1:{rtsp_port}"}, "webrtc": {"listen": ""},
        "streams": {"unrelated": "http://127.0.0.1:1/unrelated.ts"},
    }))
    process = None
    async with ClientSession() as session:
        api = f"http://127.0.0.1:{api_port}/api/streams"

        async def start():
            nonlocal process
            process = await asyncio.create_subprocess_exec(
                str(Path(binary).resolve()), "-config", str(config),
                stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
            )
            async with asyncio.timeout(5):
                while True:
                    try:
                        async with session.get(api) as response:
                            if response.status == 200:
                                return process
                    except ClientError:
                        pass
                    await asyncio.sleep(0.02)

        try:
            process = await start()
            relay = SharedRelay(session, api_port, rtsp_port, atomic_ownership=atomic_ownership)
            await relay.source("http://127.0.0.1:1/native?auth=TEST_ONLY")
            process.kill()
            await asyncio.wait_for(process.wait(), 5)
            assert not await relay.close()  # API is down; retain explicit recovery ownership.
            process = await start()
            foreign = "http://127.0.0.1:1/reassigned.ts"
            if reassigned:
                async with session.patch(api, params={"name": relay.name, "src": foreign}) as response:
                    assert response.status == 200
            assert await relay.close() is not reassigned
            async with session.get(api) as response:
                streams = await response.json()
            assert "unrelated" in streams
            if reassigned:
                assert streams[relay.name]["producers"][0]["url"] == foreign
                assert "bytes_recv" not in streams[relay.name]["producers"][0]
                # Test operator removes its own foreign registration, not adapter cleanup.
                async with session.delete(api, params={"src": relay.name}) as response:
                    assert response.status == 200
                assert await relay.close()
            else:
                assert set(streams) == {"unrelated"}
            assert "TEST_ONLY" not in config.read_text()
        finally:
            if process is not None and process.returncode is None:
                process.terminate()
                await asyncio.wait_for(process.wait(), 5)
