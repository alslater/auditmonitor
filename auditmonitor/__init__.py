#!/usr/bin/env python

import os
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import threading
from queue import Queue
import subprocess
import logging
import signal
import platform
from xml.sax.handler import ContentHandler
from xml.sax import make_parser
import traceback
from datetime import datetime
import json
import re
from auditmonitor.daemon import Daemon
from pathlib import Path
import socket

hostname = ''
watchdir = '/var/audit'
taskQueue = Queue()
logQueue = Queue()
daemonized = False;

current_files = set()


def start_daemon():
    global daemonized
    daemonized = True
    our_daemon = AuditmonDaemon("/var/run/auditmon")
    our_daemon.start()
    exit()


def stop_daemon():
    our_daemon = AuditmonDaemon("/var/run/auditmon")
    our_daemon.stop()
    exit()


def restart_daemon():
    global daemonized
    daemonized = True
    our_daemon = AuditmonDaemon("/var/run/auditmon")
    our_daemon.restart()
    exit()


def block_signals(sigset={signal.SIGINT}):
    mask = signal.pthread_sigmask(signal.SIG_BLOCK, {})
    signal.pthread_sigmask(signal.SIG_BLOCK, sigset)
    return mask


def restore_signals(mask):
    signal.pthread_sigmask(signal.SIG_SETMASK, mask)


class FileProcessor(FileSystemEventHandler):
    def on_created(self, event):
        if event.is_directory:
            # Not interested in folders?
            pass
        else:
            logging.info(f'New file event: {event.src_path}')
            # Only looking for new audit files
            if event.src_path.find('not_terminated') > -1:
                taskQueue.put(os.path.join(event.src_path))

    def on_deleted(self, event):
        global current_files
        if event.src_path in current_files:
            # File that we were currently processing has been deleted
            # The thread should notice and finish, but we need a new one
            logging.warning(f"Current file {event.src_path} has been deleted, rotating audit files")
            subprocess.run(["/usr/sbin/audit", "-n"])

    def on_moved(self, event):
        if event.src_path in current_files:
            logging.info(f'Removing rotated audit log {event.dest_path} : {event.src_path in current_files}')
            os.remove(event.dest_path)

            # Look for replacement
            time.sleep(1)
            found_new = False
            for filename in os.listdir(watchdir):
                if filename.find("not_terminated") > -1:
                    found_new = True

            if not found_new:
                logging.warning(f"No new file round after rotation.  Possible renaming shenanigans?  Forcing rotation")
                subprocess.run(["/usr/sbin/audit", "-n"])


# noinspection PyPep8
'''
<record version="2" event="execve(2)" host="aslate.brighton.scluk.com" iso8601="2019-03-20 10:16:00.248 +00:00">
  <path>/usr/bin/rm</path>
  <attribute mode="100555" uid="root" gid="bin" fsid="65538" nodeid="540444" device="18446744073709551615"/>
  <exec_args>
    <arg>rm</arg>
    <arg>/tmp/httpd_monitor.sh.lock</arg>
  </exec_args>
  <subject audit-uid="aslate" uid="aslate" gid="technical" ruid="aslate" rgid="technical" pid="13572" sid="3911594195" tid="283 7 aslate.brighton.scluk.com"/>
  <return errval="success" retval="0"/>
  <zone name="global"/>
</record>
'''

## Need to log
# Logins and Logouts
# Actions by root or administrators

to_audit = {
    "execve(2)": ".*-local",
    "cron-invoke": ".*-local",
    "login": ".*",
    "logout": ".*",
    "sudo(1m)": ".*",
    "ssh": ".*",
    "zlogin": ".*",
    "role login": ".*",
    "role_logout": ".*",
    "mount": ".*",
    "mount(2)": ".*",
    "umount2(2)": ".*",
    "su": ".*"
}

# noinspection PyAttributeOutsideIn it
class AuditRecord:
    def __init__(self, event, date):
        global hostname
        global tz_re

        self.hostname = hostname

        evs = event.split(' ')
        self.event = evs[0]

        # Solaris audit format includes a : in the TZ, we need to remove it
        # to parse it with strptime
        lastcolon = date.rfind(':')
        fixed_date = date[:lastcolon] + date[lastcolon+1:]

        self.timestamp = datetime.strptime(fixed_date, '%Y-%m-%d %H:%M:%S.%f %z').timestamp()

        if event.find('pfexec') > -1:
            self.elevated = True
        else:
            self.elevated = False
        self.args = []
        self.remote = ""

    def set_path(self, path):
        self.path = path

    def add_arg(self, arg):
        self.args.append(arg)

    def add_subject(self, auid, uid, gid, ruid, rgid, pid, sid, tid):
        self.auid = auid
        self.uid = uid
        self.gid = gid
        self.ruid = ruid
        self.rgid = rgid
        self.pid = pid
        self.sid = sid

        tidl = tid.split(' ')

        if tidl[0] == 0 and tidl[1] == 0:
            self.remote = "CONSOLE"
        else:
            try:
                ip = socket.gethostbyaddr(tidl[2])
                self.remote = ip[2][0]
            except Exception:
                self.remote = tidl[2]

        if self.uid == 'root' and self.auid != self.uid:
            self.elevated = True

    def add_zone(self, zone):
        if zone != 'global':
            self.hostname = zone

    def add_retval(self, result, retval):
        self.result = result
        self.retval = retval

    def set_cron(self):
        self.cron = True

    def to_dict(self):
        message = f"auditmon : {self.hostname} : {self.auid} as {self.uid}:{self.gid} : {self.event} : {self.result}"

        if self.event == "execve(2)":
            if self.retval == "0":
                message = message + f" : {' '.join(self.args)}"
                if len(self.args) > 0 and self.path != self.args[0] and os.path.isdir(self.path):

                    message = message + f" : pwd({self.path})"
            else:
                message = message + f" : {self.path}"

        if self.remote != hostname:
            message = message + f" : remote({self.remote})"


        self.message = message
        return self.__dict__


class RecordHandler(ContentHandler):
    def __init__(self):
        super().__init__()
        self.stack = []
        self.audit_record = None
        self.current_element = None
        self.current_value = ''
        self.cron_sids = []

        self.rexp = {}

        for event in to_audit:
            logging.debug(f'Compiling regexp "{to_audit[event]}" for event {event}')
            self.rexp[event] = re.compile(to_audit[event])

    def startDocument(self):
        pass

    def startElement(self, name, attrs):
        self.stack.append(name)
        self.current_element = name

        if name == "record":
            self.audit_record = AuditRecord(attrs["event"], attrs["iso8601"])

        if name == "subject":
            self.audit_record.add_subject(
                attrs['audit-uid'],
                attrs['uid'],
                attrs['gid'],
                attrs['ruid'],
                attrs['rgid'],
                attrs['pid'],
                attrs['sid'],
                attrs['tid']
            )

        if name == "zone":
            self.audit_record.add_zone(attrs['name'])

        if name == "return":
            self.audit_record.add_retval(
                attrs['errval'],
                attrs['retval']
            )

    def endElement(self, name):
        if name == "record":
            if self.audit_record.event == "cron-invoke":
                self.cron_sids.append(self.audit_record.sid)

            if self.audit_record.event in to_audit:
                if self.audit_record.event == "execve(2)" and self.audit_record.sid in self.cron_sids:
                    self.audit_record.set_cron()

                if self.audit_record.auid == "root" or \
                     self.audit_record.uid == "root" or \
                     self.audit_record.ruid == "root" or \
                     self.rexp[self.audit_record.event].match(self.audit_record.auid) is not None:
                    logQueue.put(json.dumps(self.audit_record.to_dict()))
            self.audit_record = None

        if name == "path":
            self.audit_record.set_path(self.current_value)

        if name == "arg":
            self.audit_record.add_arg(self.current_value)

        self.current_element = self.stack.pop()
        self.current_value = ''

    def characters(self, chars):
        self.current_value += chars.strip()


class AuditReadWorker(threading.Thread):
    def __init__(self):
        super(AuditReadWorker, self).__init__()

    def run(self):
        global hostname
        global current_files
        try:
            while True:
                file = taskQueue.get()
                logging.info(f'{self} Processing file {file}')
                current_files.add(file)

                mask = block_signals()

                # Open command pipeline
                p1 = subprocess.Popen(['/usr/gnu/bin/tail', '-n', '0', '--follow=name', file], stdout=subprocess.PIPE,
                                      stdin=subprocess.DEVNULL, stderr=subprocess.DEVNULL, bufsize=128000)

                time.sleep(1)
                if p1.poll() is not None:
                    logging.error(f'Tail failed on {file}')
                    taskQueue.task_done()
                    continue

                p2 = subprocess.Popen(['/usr/sbin/praudit', '-x'], stdin=p1.stdout, stdout=subprocess.PIPE,
                                      stderr=subprocess.DEVNULL, bufsize=128000)

                restore_signals(mask)

                parser = make_parser()
                handler = RecordHandler()
                parser.setContentHandler(handler)

                # Incrementally process the xml output from praudit
                for line in iter(p2.stdout.readline, b''):
                    # logging.info(line)
                    try:
                        parser.feed(line)
                    except Exception:
                        print(traceback.format_exc())
                        raise

                r1 = p1.poll()
                p2.poll()

                current_files.remove(file)

                # In the normal case, the file would have been renamed by the audit rotation.
                #  That will cause the tail to exit, and that will cause the praudit to exit.

                if r1 is None:
                    # The tail is still running.  Either praudit went bang or it has been deliberately
                    # closed down.  Either way, kill the tail and requeue the current file
                    p1.kill()
                    p1.wait()
                    logging.info(f'{self} Abnormal praudit exit on {file}, requeuing')
                    taskQueue.put(file)
                else:
                    # Check if the file still exists.
                    check = Path(file)
                    if check.is_file():
                        #  Still here, so the tail went bang or was deliberately closed down.
                        logging.info(f'{self} Abnormal tail exit on {file}, requeuing')
                        taskQueue.put(file)
                    else:
                        logging.info(f'{self} Finished Processing file {file}')

                # Signal that we have finished processing the file
                taskQueue.task_done()

        except Exception as e:  # Catch all
            logging.error(f'Task thread exiting because of exception : {e}')
            taskQueue.task_done()  # Just in case


class LogWriteWorker(threading.Thread):
    def __init__(self):
        super(LogWriteWorker, self).__init__()
        self.logfile = None
        self.open_logfile()

    def open_logfile(self):
        fd = os.open('/var/log/audit.json', os.O_CREAT | os.O_WRONLY | os.O_APPEND, 0o640)
        self.logfile = open(fd, 'a')

    def close_logfile(self):
        if self.logfile:
            self.logfile.close()
            self.logfile = None

    def run(self):
        try:
            while True:
                item = logQueue.get()
                if item == "ROTATE":
                    self.close_logfile()
                    self.open_logfile()
                    logQueue.task_done()
                elif item == "STOP":
                    self.close_logfile()
                    logQueue.task_done()
                    break
                else:
                    if not self.logfile:
                        self.open_logfile()

                    self.logfile.write(f'{item}\n')
                    self.logfile.flush()
                    logQueue.task_done()

        except Exception as e:  # Catch all
            logging.error(f'logging task thread exiting because of exception : {e}')
            logQueue.task_done()  # Just in case


class InterruptHandler(object):

    def __init__(self, sig=signal.SIGINT):
        self.sig = sig
        self.released = False

    def __enter__(self):
        self.interrupted = False
        self.released = False

        self.original_handler = signal.getsignal(self.sig)

        # noinspection PyUnusedLocal
        def handler(signum, frame):
            self.release()
            self.interrupted = True

        signal.signal(self.sig, handler)

        return self

    def __exit__(self, _type, value, tb):
        self.release()

    def release(self):
        if self.released:
            return False

        signal.signal(self.sig, self.original_handler)

        self.released = True


class AuditmonDaemon(Daemon):
    """ Manages running the app as a daemon
    """

    def __init__(self, pidfile):
        super(AuditmonDaemon, self).__init__(pidfile)

    def run(self):
        """ Overridden run method which calls runs the application

        :return: None
        """
        run()

def run():
    global hostname
    global watchdir
    global taskQueue
    global logQueue
    global terminating

    try:
        hostname = socket.gethostbyaddr(platform.node())[2][0]
    except Exception:
        hostname = platform.node()

    logformat = '%(asctime)s %(levelname)s : %(message)s'

    logconfig = {
        'format': logformat,
        'level': logging.INFO
    }

    logging.basicConfig(**logconfig)

    logging.info('Starting file processing threads...')

    # Start the file processing threads
    num_worker_threads = 2  # configurable???

    for i in range(num_worker_threads):
        t = AuditReadWorker()
        t.daemon = True
        t.start()

    logging.info('Starting logger...')
    logworker = LogWriteWorker()
    logworker.start()

    logging.info('Starting watchdog...')
    # Start the watchdog observer
    observer = Observer()


    # Add the watch
    try:
        logging.info('Adding watch on %s...' % watchdir)
        observer.schedule(FileProcessor(), watchdir)
    except Exception as e:
        logging.error(f'Cannot watch %s : no permission? : {e}' % watchdir)
        exit(1)

    observer.start()

    # Find any existing audit files and queue them for monitoring
    for filename in os.listdir(watchdir):
        if filename.find("not_terminated") > -1:
            taskQueue.put(os.path.join(watchdir, filename))
        else:
            logging.info(f'Removing terminated log file {os.path.join(watchdir, filename)}')
            os.remove(os.path.join(watchdir, filename))

    try:
        with InterruptHandler() as sigint_handler:
            terminating = False
            while not terminating:
                with InterruptHandler(signal.SIGHUP) as sighup_handler:
                    while True:  # loop forever, we'll break when we get ctrl-c or SIGINT
                        time.sleep(0.5)
                        if sigint_handler.interrupted:
                            logging.info('Termination requested')
                            terminating = True
                            break
                        if sighup_handler.interrupted:
                            logQueue.put("ROTATE")
                            logging.info('Caught SIGHUP, rotating log file')
                            break # To reset the SIGHUP handler

    except KeyboardInterrupt:
        logging.info('Termination requested, waiting for jobs to complete...')
    except Exception as e:
        logging.info(f'Caught unexpected exception {e}, waiting for jobs to complete...')

    logging.info('Stopping the logger thread')
    logQueue.put("STOP")
    logQueue.join()
    logworker.join()

    logging.info('Stopping the observer')
    observer.stop()
    if daemonized:
        taskQueue.join()
    logging.info('Terminating')
