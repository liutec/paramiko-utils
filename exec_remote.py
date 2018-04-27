#!/usr/bin/env python

import sys
import getpass
import logging

from io import StringIO
from queue import Queue, Empty as QueueEmpty
from threading import Thread
from socket import timeout as socket_timeout, gaierror as socket_gaierror
from paramiko import Agent, SSHClient, AutoAddPolicy
from paramiko.agent import AgentRequestHandler
from paramiko.ssh_exception import NoValidConnectionsError, SSHException
from time import sleep, time


class Result(object):
    __slots__ = [
        'host',
        'username',
        'command',
        'exit_status',
        'stdout',
        'stderr'
    ]

    def __init__(self, host, username, command):
        super(Result, self).__init__()
        self.host = host
        self.username = username
        self.command = command
        self.exit_status = -1
        self.stdout = StringIO()
        self.stderr = StringIO()

    def error(self, err, exit_status=None):
        self.stderr.write(str(err) + '\n')
        if exit_status is not None:
            self.exit_status = exit_status
        return self

    def write(self, stream):
        stream.write('%s (%s)$ %s\n' % (self.host, self.username, self.command))
        value = self.stdout.getvalue()
        stream.write('stdout (%d bytes):\n%s\n' % (len(value), value))
        value = self.stderr.getvalue()
        stream.write('stderr (%d bytes):\n%s\n' % (len(value), value))
        stream.write('exit: %d\n' % self.exit_status)
        stream.flush()


class ReaderThread(Thread):
    DEFAULT_POISON_PILL = (None, None)

    def __init__(self, read_fn, message_queue, tag, poison_pill=DEFAULT_POISON_PILL):
        self.read_fn = read_fn
        self.buff_size = 2048
        self.message_queue = message_queue
        self.tag = tag
        self.poison_pill = poison_pill

        super(ReaderThread, self).__init__()
        self.setDaemon(True)

    def send_line(self, line):
        backspace = chr(8)
        if backspace in line:
            parsed = []
            for part in line.split(backspace):
                parsed.append(part[:-1])
            line = ''.join(parsed)
        self.message_queue.put((line, self.tag))

    def run(self):
        logged_cr = False
        line = []
        while True:
            try:
                byte_list = self.read_fn(self.buff_size)
            except socket_timeout:
                sleep(0.01)
                continue
            # EOS
            if byte_list == b'':
                str_line = (''.join(line)).strip()
                if str_line:
                    self.send_line(str_line)
                break
            parsed_bytes = byte_list
            if parsed_bytes[-1] == b'\r':
                logged_cr = True
            if parsed_bytes[0] == b'\n' and logged_cr:
                parsed_bytes = parsed_bytes[1:]
                logged_cr = False
            while parsed_bytes != b'':
                k = parsed_bytes.find(b'\r\n')
                if k == -1:
                    k = parsed_bytes.find(b'\r')
                if k == -1:
                    k = parsed_bytes.find(b'\n')
                if k == -1:
                    break
                eol = parsed_bytes[:k]
                parsed_bytes = parsed_bytes[k + 1:]
                if (b'\r' in eol) or (b'\n' in eol):
                    eol = ''
                self.send_line(''.join(line) + eol.decode('utf-8'))
                line = []
            line += [parsed_bytes.decode('utf-8')]
        if len(line) > 0:
            self.send_line(''.join(line))
        self.message_queue.put(self.poison_pill)


def check_forward_agent_available():
    logger = logging.getLogger()
    forward_agent = None
    forwarded_keys = ()
    try:
        forward_agent = Agent()
        forwarded_keys = forward_agent.get_keys()
    except SSHException as e:
        logger.error(str(e))
        exit(1)
    finally:
        if forward_agent:
            forward_agent.close()
    if not forwarded_keys:
        if sys.platform == 'win32':
            logger.error('Unable to communicate with forward-agent. Make sure Pageant is running.')
        else:
            logger.error('Unable to communicate with forward-agent.')
        exit(1)
    logger.debug('Found %d key(s) available in forward-agent.' % len(forwarded_keys))


def ssh(username, host, cmd=None, password=None, port=None, timeout=None, max_attempts=None, retry_interval=None,
        max_time_wo_output=None, max_wait_exit_status=None):
    cmd = cmd or 'w'
    port = port or 22
    timeout = timeout or 5
    max_attempts = max_attempts or 25
    retry_interval = retry_interval or 5
    max_time_wo_output = max_time_wo_output or 5
    max_wait_exit_status = max_wait_exit_status or 5

    logger = logging.getLogger()
    result = Result(host, username, cmd)

    attempt = 1
    channel = None
    while attempt <= max_attempts:
        try:
            client = SSHClient()
            client.set_missing_host_key_policy(AutoAddPolicy())
            client.connect(
                username=username,
                password=password,
                hostname=host,
                port=port,
                timeout=timeout,
                allow_agent=True
            )
            transport = client.get_transport()
            channel = transport.open_session()
            AgentRequestHandler(channel)
            break
        except socket_gaierror as e:
            return result.error(e, -2)
        except (socket_timeout, NoValidConnectionsError, SSHException) as e:
            if "Authentication failed" in str(e):
                return result.error(e, -3)
            logger.debug("ssh %s@%s: %s (attempt %d of %d)" % (username, host, str(e), attempt, max_attempts))
            sleep(retry_interval)
            attempt += 1
            continue

    if not channel:
        result.exit_status = -4
        return result

    try:
        try:
            logger.debug("ssh %s@%s$ %s" % (username, host, cmd))
            channel.exec_command(command=cmd)
        except SSHException as e:
            return result.error(e, -5)
        except TypeError as e:
            return result.error("Forward agent problem: %s. " % str(e), -6)

        output_queue = Queue()
        readers = {
            0: (ReaderThread(channel.recv, output_queue, 0), result.stdout),
            1: (ReaderThread(channel.recv_stderr, output_queue, 1), result.stderr)
        }

        for _, (reader, _) in readers.items():
            reader.start()

        start_time = time()
        last_output_time = start_time

        num_pills_received = 0
        num_pills_total = len(readers)
        while True:
            try:
                message_line, message_tag = output_queue.get(True, 0.1)
                last_output_time = time()
                if (message_line, message_tag) == ReaderThread.DEFAULT_POISON_PILL:
                    num_pills_received += 1
                    if num_pills_received < num_pills_total:
                        continue
                    break
                readers[message_tag][1].write(message_line + '\n')
            except QueueEmpty:
                if max_time_wo_output and ((time() - last_output_time) > max_time_wo_output):
                    try:
                        channel.sendall('\x003')
                    except SSHException:
                        pass
                    result.error("Max time without output reached (%.2f sec).\n" % float(max_time_wo_output), -6)
                    break

        if result.exit_status == -1:
            result.exit_status = -7
            while True:
                if channel.exit_status_ready():
                    result.exit_status = channel.recv_exit_status()
                    break
                if time() - last_output_time > max_wait_exit_status:
                    result.error("Timeout waiting for exit status (%.2f sec).\n" % float(max_wait_exit_status), -8)
                    break
                sleep(0.1)
    finally:
        channel.close()

    return result


def main():
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    ch.setFormatter(logging.Formatter('%(asctime)s|%(levelname)s|%(message)s'))
    logging.getLogger().addHandler(ch)

    check_forward_agent_available()
    result = ssh(getpass.getuser(), '192.169.44.134', 'who -a')
    result.write(sys.stdout)


if __name__ == '__main__':
    main()
