#!/usr/bin/env python

import os
import sys

# Add our path if necessary
if os.path.dirname(__file__) not in sys.path:
    sys.path.append(os.path.dirname(os.path.abspath(__file__)))

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
from daemon import Daemon
from pathlib import Path

hostname = ''
watchdir = '/var/audit'
taskQueue = Queue()
logQueue = Queue()

current_files = set()

def start_daemon():
    our_daemon = auditmonDaemon("/var/run/auditmon")
    our_daemon.start()
    exit()

def stop_daemon():
    our_daemon = auditmonDaemon("/var/run/auditmon")
    our_daemon.stop()
    exit()

def restart_daemon():
    our_daemon = auditmonDaemon("/var/run/auditmon")
    our_daemon.restart()
    exit()

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

to_audit =["execve(2)", "login", "logout","sudo(1m)","ssh"]

# noinspection PyAttributeOutsideInit
class auditRecord:
    def __init__(self, event, date):
        global hostname
        self.hostname = hostname

        evs = event.split(' ')
        self.event = evs[0]
        fixed_date = date.replace(' +00:00', ' +0000')
        self.timestamp = datetime.strptime(fixed_date, '%Y-%m-%d %H:%M:%S.%f %z' ).timestamp()

        if event.find('pfexec') > -1:
            self.elevated = True
        else:
            self.elevated = False
        self.args = []

    def set_path(self, path):
        self.path = path

    def add_arg(self, arg):
        self.args.append(arg)

    def add_subject(self, auid, uid, gid, ruid, rgid, pid, tid):
        self.auid = auid
        self.uid = uid
        self.gid = gid
        self.ruid = ruid
        self.rgid = rgid
        self.pid = pid

        tidl = tid.split(' ')
        self.remote = tidl[2]

        if self.uid == 'root' and self.auid != self.uid:
            self.elevated = True

    def add_zone(self, zone):
        self.zone = zone

    def add_retval(self, result, retval):
        self.result = result
        self.retval = retval

    def to_dict(self):
        #self.message = f"{self.uid}:{self.gid} : {self.event}"

        return self.__dict__

class recordHandler(ContentHandler):
    def __init__(self):
        super().__init__()
        self.stack = []
        self.audit_record = None
        self.current_element = None
        self.current_value = ''
        self.user_re = re.compile('.*-local')

    def startDocument(self):
        pass

    def startElement(self, name, attrs):
        self.stack.append(name)
        self.current_element = name

        if name == "record":
            self.audit_record = auditRecord(attrs["event"], attrs["iso8601"])

        if name == "subject":
            self.audit_record.add_subject(
                attrs['audit-uid'],
                attrs['uid'],
                attrs['gid'],
                attrs['ruid'],
                attrs['rgid'],
                attrs['pid'],
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
            if self.audit_record.event in to_audit:
                #and (
                #    self.audit_record.auid == 'root' or
                #    self.user_re.match(self.audit_record.auid) is not None):
                #logging.info(f'{json.dumps(self.audit_record.to_dict())}')
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


class taskWorker(threading.Thread):
    def __init__(self):
        super(taskWorker, self).__init__()

    def run(self):
        global hostname
        global current_files
        try:
            while True:
                file = taskQueue.get()
                logging.info(f'{self} Processing file {file}')
                current_files.add(file)

                # Open command pipeline
                p1 = subprocess.Popen(['tail', '-n', '0', '--follow=name', file], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0)

                time.sleep(1)
                if p1.poll() is not None:
                    logging.error(f'Tail failed on {file}')
                    taskQueue.task_done()
                    continue

                p2 = subprocess.Popen(['praudit', '-x'], stdin=p1.stdout, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0)

                parser = make_parser()
                handler = recordHandler()
                parser.setContentHandler(handler)

                # Incrementally process the xml output from praudit
                for line in p2.stdout:
                    #logging.info(line)
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


class logWorker(threading.Thread):
    def __init__(self):
        super(logWorker, self).__init__()
        self.logfile = None
        self.open_logfile()

    def open_logfile(self):
        self.logfile = open('/var/log/audit.json', 'a')

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

    def __enter__(self):
        self.interrupted = False
        self.released = False

        self.original_handler = signal.getsignal(self.sig)

        def handler(signum, frame):
            self.release()
            self.interrupted = True

        signal.signal(self.sig, handler)

        return self

    def __exit__(self, type, value, tb):
        self.release()

    def release(self):
        if self.released:
            return False

        signal.signal(self.sig, self.original_handler)

        self.released = True


class auditmonDaemon(Daemon):
    """ Manages running the app as a daemon
    """

    def __init__(self, pidfile):
        super(auditmonDaemon, self).__init__(pidfile)

    def run(self):
        """ Overridden run method which calls runs the application

        :return: None
        """
        run()

def run():
    global hostname

    hostname = platform.node()

    logformat = '%(asctime)s %(levelname)s : %(message)s'

    logconfig = {
        'format': logformat,
        'level': logging.INFO
    }

    # if logfile:
    #    logconfig['filename'] = logfile

    logging.basicConfig(**logconfig)

    logging.info('Starting file processing threads...')

    # Start the file processing threads
    num_worker_threads = 2  # configurable???

    for i in range(num_worker_threads):
        t = taskWorker()
        t.daemon = True
        t.start()

    logging.info('Starting logger...')
    logworker = logWorker()
    logworker.start()

    logging.info('Starting watchdog...')
    # Start the watchdog observer
    observer = Observer()

    # Add the watch
    watchdir = '/var/audit'
    try:
        logging.info('Adding watch on %s...' % watchdir)
        observer.schedule(FileProcessor(), watchdir)
    except Exception:
        logging.error('Cannot watch %s : no permission?' % watchdir)
        exit(1)

    observer.start()

    # Find any existing audit files and queue them for monitoring
    for filename in os.listdir(watchdir):
        if filename.find("not_terminated") > -1:
            taskQueue.put(os.path.join(watchdir, filename))

    while True:  # loop forever, we'll break when we get ctrl-c or SIGINT
        try:
            with InterruptHandler() as sigint_handler:
                with InterruptHandler(signal.SIGHUP) as sighup_handler:
                    if sigint_handler.interrupted:
                        logging.info('Termination requested, waiting for jobs to complete...')
                        break
                    if sighup_handler.interrupted:
                        logging.info('Caught SIGHUP, rotating log file')
                        continue

        except KeyboardInterrupt:
            logging.info('Termination requested, waiting for jobs to complete...')
            break
        except Exception:
            logging.info('Unknown exception, waiting for jobs to complete...')
            break

    # Signal
    logQueue.put("STOP")
    logworker.join()

    observer.stop()
    taskQueue.join()
    logging.info('Terminating')


