#!/usr/bin/env python

import lief
import asyncio
import enum
import struct
import os
import numpy as np
from electricunicorn import trace_register_hws
import matplotlib.pyplot as plt


class EUException(Exception):
    pass


class EUClientMessageType(enum.Enum):
    CLIENT_HELLO = 0
    UNKNOWN = -1


class EUClientState:
    CLIENT_HELLO = 0


class EUClientMessage:
    def __init__(self, message_type, payload):
        self.message_type = EUClientMessageType(message_type)
        self.payload = payload

    @classmethod
    def from_bytes(cls, raw_bytes):
        message_type = struct.unpack("B", raw_bytes[0])[0]
        length = struct.unpack(">H", raw_bytes[1:3])[0]
        payload = raw_bytes[3:]

        if len(payload) != length:
            raise EUException("Malformed EUClientMessage")

        return EUClientMessage(message_type, payload)

    def __repr__(self):
        return "%s: %s" % (self.message_type, str(self.payload))


class EUClientHandler:
    def __init__(self):
        self.state = EUClientState.CLIENT_HELLO

    def handle(self, message):
        if self.state == EUClientState.CLIENT_HELLO:
            if message.message_type != EUClientMessageType.CLIENT_HELLO:
                raise EUException("Expected CLIENT_HELLO message, but got %s" % message.message_type.name)


class Elf:
    def __init__(self, meta, memory):
        self.meta = meta
        self.memory = memory
        self.sp = None
        self._create_stack()
        self.pmk = next(s for s in meta.symbols if s.name == 'fake_pmk').value
        self.ptk = next(s for s in meta.symbols if s.name == 'fake_ptk').value
        self.stop_addr = next(s for s in meta.symbols if s.name == 'stop').value

    def _create_stack(self):
        self.memory.extend(bytearray(1024*1024))
        self.sp = len(self.memory)
        self.memory.extend(bytearray(1024*1024))


class ElectricUnicorn:
    def __init__(self, elf_path):
        self.event_loop = asyncio.get_event_loop()  # Construct or get current event loop
        self.server = None
        self.elf_path = os.path.abspath(elf_path)

    async def _stream_get_packet(self, reader):
        message_type = struct.unpack("B", await reader.readexactly(1))[0]
        length = struct.unpack(">H", await reader.readexactly(2))[0]
        payload = await reader.readexactly(length)

        return EUClientMessage(message_type, payload)

    async def handle_new_stream(self, reader, writer):
        done = False
        handler = EUClientHandler()

        while not done:
            try:
                # Get message
                message = await self._stream_get_packet(reader)
                addr = writer.get_extra_info('peername')
                print("Received %r from %r" % (message, addr))

                # Handle message
                response = handler.handle(message)

                # Send response
                if response is not None:
                    writer.write(bytes(response))
                    await writer.drain()
            except (asyncio.streams.IncompleteReadError, ConnectionResetError):
                print("Client disconnected.")
                writer.close()
                done = True

    def analyze_elf(self, elf_path):
        elf = lief.parse(elf_path)

        begin_addrs = [s.virtual_address for s in elf.segments]
        end_addrs = [s.virtual_address + len(s.content) for s in elf.segments]
        end_addr = max(end_addrs)
        buffer = bytearray(end_addr)

        for s in elf.segments:
            begin = s.virtual_address
            end = s.virtual_address + len(s.content)
            buffer[begin:end] = s.content
            print("[%d:%d] -> %s" % (begin, end, str(s.content)))

        return Elf(elf, buffer)

    def start(self):
        elf = self.analyze_elf(self.elf_path)
        max_mem_bytes = 1024*1024*1024
        results = np.zeros(int(max_mem_bytes / np.ushort().nbytes), dtype=np.ushort)
        trace_register_hws(results, elf.memory, len(elf.memory), elf.meta.entrypoint, elf.sp, elf.pmk, elf.ptk, elf.stop_addr)
        plt.plot(results)
        plt.show()

        """
        # Accept results from unicorns
        server_coroutine = asyncio.start_server(self.handle_new_stream, '127.0.0.1', 3884)
        self.server = self.event_loop.run_until_complete(server_coroutine)
        print('Serving on {}'.format(self.server.sockets[0].getsockname()))

        # Keep listening for events
        try:
            self.event_loop.run_forever()
        except KeyboardInterrupt:
            pass
        finally:
            self.server.close()
            self.event_loop.run_until_complete(self.server.wait_closed())
            self.event_loop.close()
        """


if __name__ == "__main__":
    e = ElectricUnicorn("./hmac-sha1")
    e.start()
