# Runtime hooks deliberately resolve through their legacy owner.
# ruff: noqa: SLF001

"""stream command handlers; legacy hooks resolve through cli.main."""
from __future__ import annotations

import pyezvizapi.cli.main as _owner


def _handle_stream(args: _owner.argparse.Namespace, client: _owner.EzvizClient) -> int:
    """Handle experimental stream helpers."""
    if args.stream_action not in {'trace', 'dump', 'proxy', 'local-sdk-dump', 'local-sdk-keys', 'h264-annexb-summary', 'hcnetsdk-command-dump-summary', 'hcnetsdk-command-plan-generate'}:
        _owner._LOGGER.error('Action not implemented, try running with -h switch for help')
        return 2
    if args.stream_action == 'hcnetsdk-command-dump-summary':
        return _owner._handle_hcnetsdk_command_dump_summary(args)
    if args.stream_action == 'hcnetsdk-command-plan-generate':
        return _owner._handle_hcnetsdk_command_plan_generate(args)
    if args.stream_action == 'h264-annexb-summary':
        return _owner._handle_h264_annexb_summary(args)
    if args.stream_action == 'local-sdk-keys':
        return _owner._handle_local_sdk_keys(args, client)
    if args.stream_action == 'local-sdk-dump':
        return _owner._handle_local_sdk_stream_dump(args, client)
    if args.stream_action == 'proxy':
        _owner._serve_stream_proxy(args, client)
        return 0
    if args.stream_action == 'dump' and args.decrypt_video and (not _owner.has_positive_finite_capture_bound(max_packets=args.max_packets, duration_seconds=args.duration)):
        raise _owner.PyEzvizError('--decrypt-video requires a positive finite --duration or --max-packets to bound memory use')
    media_key = _owner._cloud_cli_media_key(args, client) if args.stream_action == 'dump' and args.decrypt_video else None
    stream = _owner.open_cloud_stream(client, args.serial, channel=args.channel, client_type=args.client_type, token_index=args.token_index, refresh_vtm=not args.no_refresh_vtm, timeout=args.timeout)
    with _owner._closing_unconnected_cloud_stream(stream):
        if args.stream_action == 'dump':
            startup_deadline = _owner._start_cli_cloud_stream(stream, timeout=args.timeout, duration_seconds=args.duration)
            collected_packets: list[_owner.Any] | None = None
            if args.decrypt_video:
                collected_packets = _owner._collect_stream_packets(stream, max_packets=args.max_packets, duration_seconds=args.duration, first_packet_deadline=startup_deadline, allow_encrypted=args.allow_encrypted)
                transport = _owner._detect_stream_packets_transport(collected_packets)
                if transport == _owner.StreamTransport.RTP:
                    if args.format == 'mpegts' and _owner.cloud_rtp_packets_have_audio(collected_packets):
                        rtp_codec = _owner._detect_rtp_video_codec(collected_packets, media_key=media_key, decrypt_codec=args.decrypt_codec)
                        _owner._rtp_packets_to_annexb_units(collected_packets, codec=rtp_codec, first_slice_key=media_key, decrypt_codec=args.decrypt_codec)
                        assert media_key is not None

                        def _write_rtp_mpegts(selected_output: _owner.BinaryIO) -> None:
                            _owner.copy_decrypted_cloud_stream_packets_to_mpegts(collected_packets, selected_output, ffmpeg_path=args.ffmpeg_path, media_key=media_key, nalu_header_size=_owner._codec_nalu_header_size(args.decrypt_codec), transport=transport)
                        if args.output == '-':
                            _write_rtp_mpegts(_owner.sys.stdout.buffer)
                        else:
                            with _owner.Path(args.output).open('wb') as output:
                                _write_rtp_mpegts(output)
                        return 0
                    rtp_codec = _owner._detect_rtp_video_codec(collected_packets, media_key=media_key, decrypt_codec=args.decrypt_codec)
                    decrypt_codec = rtp_codec if args.decrypt_codec == 'auto' else args.decrypt_codec
                    rtp_units = _owner._rtp_packets_to_annexb_units(collected_packets, codec=rtp_codec, first_slice_key=media_key, decrypt_codec=decrypt_codec)
                    payload = b''.join(rtp_units) if _owner._codec_nalu_header_size(decrypt_codec) == 0 else _owner._decrypt_rtp_annexb_units(client, args.serial, rtp_units, detected_codec=rtp_codec, decrypt_codec=decrypt_codec, media_key=media_key)
                    if args.output == '-':
                        if args.format == 'raw':
                            _owner.sys.stdout.buffer.write(payload)
                            _owner.sys.stdout.buffer.flush()
                        else:
                            _owner._remux_elementary_video_bytes_to_mpegts(payload, _owner.sys.stdout.buffer, ffmpeg_path=args.ffmpeg_path, codec=rtp_codec)
                    else:
                        with _owner.Path(args.output).open('wb') as output:
                            if args.format == 'raw':
                                output.write(payload)
                                output.flush()
                            else:
                                _owner._remux_elementary_video_bytes_to_mpegts(payload, output, ffmpeg_path=args.ffmpeg_path, codec=rtp_codec)
                    return 0
            if args.output == '-':
                if args.decrypt_video:
                    payload = b''.join(packet.body for packet in collected_packets or [])
                    payload = _owner._decrypt_stream_payload_bytes(client, args.serial, payload, codec=args.decrypt_codec, media_key=media_key)
                    if args.format == 'raw':
                        _owner.sys.stdout.buffer.write(payload)
                        _owner.sys.stdout.buffer.flush()
                    else:
                        _owner._remux_mpegps_bytes_to_mpegts(payload, _owner.sys.stdout.buffer, ffmpeg_path=args.ffmpeg_path)
                elif args.format == 'raw':
                    _owner._write_stream_payloads(stream, _owner.sys.stdout.buffer, max_packets=args.max_packets, duration_seconds=args.duration, first_packet_deadline=startup_deadline, allow_encrypted=args.allow_encrypted)
                else:
                    _owner._remux_stream_payloads_to_mpegts(stream, _owner.sys.stdout.buffer, ffmpeg_path=args.ffmpeg_path, max_packets=args.max_packets, duration_seconds=args.duration, first_packet_deadline=startup_deadline, allow_encrypted=args.allow_encrypted)
            else:
                with _owner.Path(args.output).open('wb') as output:
                    if args.decrypt_video:
                        payload = b''.join(packet.body for packet in collected_packets or [])
                        payload = _owner._decrypt_stream_payload_bytes(client, args.serial, payload, codec=args.decrypt_codec, media_key=media_key)
                        if args.format == 'raw':
                            output.write(payload)
                            output.flush()
                        else:
                            _owner._remux_mpegps_bytes_to_mpegts(payload, output, ffmpeg_path=args.ffmpeg_path)
                    elif args.format == 'raw':
                        _owner._write_stream_payloads(stream, output, max_packets=args.max_packets, duration_seconds=args.duration, first_packet_deadline=startup_deadline, allow_encrypted=args.allow_encrypted)
                    else:
                        _owner._remux_stream_payloads_to_mpegts(stream, output, ffmpeg_path=args.ffmpeg_path, max_packets=args.max_packets, duration_seconds=args.duration, first_packet_deadline=startup_deadline, allow_encrypted=args.allow_encrypted)
            return 0
        events = [event.as_dict() for event in stream.trace_packets(max_packets=args.max_packets)]
    if args.json_lines:
        for event in events:
            _owner.sys.stdout.write(_owner.json.dumps(event, sort_keys=True) + '\n')
    else:
        _owner._write_json(events)
    return 0
