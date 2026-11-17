"""No Docker, provider, credentials or production dependency required."""
import socket
import subprocess
import sys
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import port_forward


class RelayTests(unittest.TestCase):
    def test_command_has_a_fixed_destination_and_no_shell(self):
        self.assertEqual(port_forward.COMMAND[-6:], ['es', '/usr/bin/nc', '-i', '60', '127.0.0.1', '9200'])
        self.assertEqual(port_forward.COMMAND[:2], ['docker', 'compose'])

    def test_binary_bytes_survive_and_child_exits_when_client_disconnects(self):
        listener = socket.socket()
        listener.bind(('127.0.0.1', 0))
        listener.listen(1)
        client = socket.create_connection(listener.getsockname())
        connection, _ = listener.accept()
        listener.close()
        program = 'import os; data=os.read(0,65536); os.write(1,data)'
        with subprocess.Popen([sys.executable, '-c', program], stdin=subprocess.PIPE, stdout=subprocess.PIPE) as child:
            worker = threading.Thread(target=port_forward.relay, args=(connection, child, 5))
            worker.start()
            payload = b'\x16\x03\x01\x00\x04\x00\xff\x00\n'
            client.sendall(payload)
            client.settimeout(5)
            received = bytearray()
            while len(received) < len(payload):
                part = client.recv(len(payload) - len(received))
                if not part:
                    break
                received.extend(part)
            self.assertEqual(received, payload)
            client.close()
            worker.join(5)
            self.assertFalse(worker.is_alive())
            self.assertIsNotNone(child.poll())
        connection.close()


if __name__ == '__main__':
    unittest.main()
