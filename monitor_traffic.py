#!/usr/bin/env python3

import json
import queue
import socket
import threading
import time
from datetime import datetime


HOST = "127.0.0.1"
PORT = 14580

LOGIN = (
    "user DXLMON pass -1 "
    "vers DxlAprsManager LiveMonitor\r\n"
)


class TrafficMonitor:

    def __init__(self):

        self.listeners = set()
        self.listeners_lock = threading.Lock()

        self.worker = None
        self.worker_lock = threading.Lock()

        self.running = False
        self.connected = False

        self.last_error = ""
        self.reconnects = 0


    # ========================================================
    # LISTENER
    # ========================================================

    def subscribe(self):

        q = queue.Queue(
            maxsize=1000
        )

        with self.listeners_lock:
            self.listeners.add(q)

        self.start()

        return q


    def unsubscribe(self, q):

        with self.listeners_lock:
            self.listeners.discard(q)


    # ========================================================
    # START THREAD
    # ========================================================

    def start(self):

        with self.worker_lock:

            if (
                self.worker
                and self.worker.is_alive()
            ):
                return

            self.running = True

            self.worker = threading.Thread(
                target=self._run,
                name="dxlaprs-live-traffic",
                daemon=True
            )

            self.worker.start()


    # ========================================================
    # BROADCAST
    # ========================================================

    def _broadcast(self, message):

        dead = []

        with self.listeners_lock:

            for q in self.listeners:

                try:

                    q.put_nowait(
                        message
                    )

                except queue.Full:

                    # Se un browser è troppo lento,
                    # scartiamo la riga più vecchia.
                    try:
                        q.get_nowait()
                    except queue.Empty:
                        pass

                    try:
                        q.put_nowait(
                            message
                        )
                    except queue.Full:
                        dead.append(q)

            for q in dead:
                self.listeners.discard(q)


    def _status(self, connected, error=""):

        self.connected = connected
        self.last_error = error

        self._broadcast({
            "type": "status",
            "connected": connected,
            "error": error,
            "reconnects": self.reconnects
        })


    # ========================================================
    # TCP UDPGATE4
    # ========================================================

    def _run(self):

        while self.running:

            sock = None

            try:

                sock = socket.create_connection(
                    (HOST, PORT),
                    timeout=8
                )

                sock.settimeout(
                    None
                )

                sock.sendall(
                    LOGIN.encode(
                        "ascii",
                        errors="ignore"
                    )
                )

                self._status(
                    True
                )

                fileobj = sock.makefile(
                    "r",
                    encoding="utf-8",
                    errors="replace",
                    newline=""
                )


                for raw in fileobj:

                    line = raw.rstrip(
                        "\r\n"
                    )

                    if not line:
                        continue

                    self._broadcast({
                        "type": "frame",

                        "timestamp":
                            datetime.now().strftime(
                                "%H:%M:%S.%f"
                            )[:-3],

                        "data": line
                    })


                raise ConnectionError(
                    "connessione chiusa da udpgate4"
                )


            except Exception as exc:

                self.reconnects += 1

                self._status(
                    False,
                    str(exc)
                )

                time.sleep(
                    2
                )


            finally:

                if sock:

                    try:
                        sock.close()
                    except Exception:
                        pass


traffic_monitor = TrafficMonitor()


def traffic_subscribe():
    return traffic_monitor.subscribe()


def traffic_unsubscribe(q):
    traffic_monitor.unsubscribe(q)


def traffic_status():

    return {
        "connected":
            traffic_monitor.connected,

        "error":
            traffic_monitor.last_error,

        "reconnects":
            traffic_monitor.reconnects
    }


def sse_encode(data):

    return (
        "data: "
        + json.dumps(
            data,
            ensure_ascii=False
        )
        + "\n\n"
    )
