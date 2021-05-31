"""
Similar to the OpenCTIConnectorHelper, this ThreatBusConnectorHelper facilitates
registration, subscriptions, and message passing to and from Threat Bus via Zero
MQ.
"""

import asyncio
from threading import Event, Thread
from typing import Callable, List
import zmq
import time


def send_manage_message(endpoint: str, action: dict, timeout: int = 1):
    """
    Sends a 'management' message, following the threatbus-zmq-app protocol to
    either subscribe or unsubscribe this application to/from Threat Bus.
    @param endpoint A host:port string to connect to via ZeroMQ
    @param action The message to send as JSON
    @param timeout The period after which the connection attempt is aborted
    """
    context = zmq.Context()
    socket = context.socket(zmq.REQ)
    socket.setsockopt(zmq.LINGER, 0)
    socket.connect(f"tcp://{endpoint}")
    socket.send_json(action)
    poller = zmq.Poller()
    poller.register(socket, zmq.POLLIN)

    reply = None
    if poller.poll(timeout * 1000):
        reply = socket.recv_json()
    socket.close()
    context.term()
    return reply


def reply_is_success(reply: dict):
    """
    Predicate to check if `reply` is a dict and contains the key-value pair
    "status" = "success".
    @param reply A python dict
    @return True if the dict contains "status" = "success"
    """
    return (
        reply
        and type(reply) is dict
        and reply.get("status", None)
        and reply["status"] == "success"
    )


def subscribe(endpoint: str, topic: str, snapshot: int):
    """
    Subscribes this app to Threat Bus for the given topic.
    @param endpoint The ZMQ management endpoint of Threat Bus ('host:port')
    @param topic The topic to subscribe to
    """
    action = {"action": "subscribe", "topic": topic, "snapshot": snapshot}
    return send_manage_message(endpoint, action, timeout=5)


def unsubscribe(endpoint: str, topic: str):
    """
    Unsubscribes this app from Threat Bus for the given topic.
    @param endpoint The ZMQ management endpoint of Threat Bus
    @param topic The topic to unsubscribe from
    """
    action = {"action": "unsubscribe", "topic": topic}
    return send_manage_message(endpoint, action)


class ThreatBusConnectorHelper(Thread):
    def __init__(
        self,
        zmq_endpoint: str,
        message_callback: Callable[[str], None],
        log_info_callback: Callable[[str], None],
        log_error_callback: Callable[[str], None],
        subscribe_topics: List[str] = None,
        publish_topic: str = None,
        snapshot: int = 0,
    ):
        super(ThreatBusConnectorHelper, self).__init__()
        self._stop_event = Event()
        self.zmq_manage_ep = zmq_endpoint
        self.message_callback = message_callback
        self.log_error = log_error_callback
        self.log_info = log_info_callback
        self.subscribe_topics = subscribe_topics
        self.publish_topic = publish_topic
        self.snapshot = snapshot

        self.event_loop = None

        # These fields will be populated upon successful registration
        self.publish_socket = None
        self.receive_socket = None
        self.poller = None
        self.p2p_topic = None

    def _running(self):
        """Private predicate to test if this Thread should keep on running"""
        return not self._stop_event.is_set()

    def _unsubscribe(self) -> dict:
        reply = unsubscribe(self.zmq_manage_ep, self.p2p_topic)
        if not reply_is_success(reply):
            self.log_error(
                f"Error unsubscribing from Threat Bus p2p_topic '{self.p2p_topic}'."
            )
        self.p2p_topic = None

    def stop(self):
        """Stops the current Thread"""
        self._stop_event.set()
        self._unsubscribe()

    def send(self, msg: str):
        """
        Sends a JSON message to Threat Bus.
        @param msg The JSON message to send
        """
        self.publish_socket.send_string(f"{self.publish_topic} {msg}")

    def run(self):
        """
        Starts a zmq subscriber and listens for new messages from Threat Bus.
        Invokes the given callback for every received message.
        @param callback A callable function to invoke for received messages.
        """
        while not self.receive_socket:
            try:
                self._register_to_threatbus()
            except Exception as e:
                self.log_error(e)
                time.sleep(5)

        # create new event loop for the current thread
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        def exception_handler(loop, context):
            self.log_error(f"Error: {context}")

        loop.set_exception_handler(exception_handler)
        loop.run_until_complete(asyncio.wait([self._heartbeat(), self._receive()]))
        loop.close()

    async def _receive(self):
        while self._running():
            socks = dict(
                self.poller.poll(timeout=1000)
            )  # smaller timeouts may increase CPU load
            if (
                self.receive_socket in socks
                and socks[self.receive_socket] == zmq.POLLIN
            ):
                try:
                    topic, msg = self.receive_socket.recv().decode().split(" ", 1)
                    asyncio.get_event_loop().call_soon_threadsafe(
                        self.message_callback, msg
                    )
                except Exception:
                    continue
            await asyncio.sleep(0.01)

    async def _heartbeat(self):
        """
        Sends a one-time heartbeat message to the management endpoint of Threat
        Bus. Initiates reconnection in case the connection is lost (heartbeat is
        not answered.)
        """
        while self._running():
            action = {"action": "heartbeat", "topic": self.p2p_topic}
            reply = send_manage_message(self.zmq_manage_ep, action)
            if not reply_is_success(reply):
                self.log_error("Lost connection to Threat Bus.")
                try:
                    self._register_to_threatbus()
                except Exception as e:
                    self.log_error(f"Error: {e}")
            await asyncio.sleep(5)  # heartbeat every 5 secs

    def _register_to_threatbus(self):
        """
        Registers this connector at the configured Threat Bus endpoint.
        Populates the registration details to this connector instance.
        @return True for successful subscription, False otherwise
        """
        reply = subscribe(self.zmq_manage_ep, self.subscribe_topics, self.snapshot)
        if not reply_is_success(reply):
            raise RuntimeError(
                f"Threat Bus subscription with topics {self.subscribe_topics} failed. Is the endpoint reachable?"
            )
        pub_endpoint = reply.get("pub_endpoint", None)
        sub_endpoint = reply.get("sub_endpoint", None)
        p2p_topic = reply.get("topic", None)
        if not pub_endpoint or not sub_endpoint or not p2p_topic:
            raise RuntimeError(
                "Threat Bus subscription failed with an incomplete reply."
            )

        # Registration successful, create ZMQ sockets
        if self.p2p_topic:
            # p2p_topic is already set, so we might be recovering from a
            # connection loss. Unsubscribe the old topic before re-subscribing.
            self._unsubscribe()
        self.p2p_topic = p2p_topic
        self.publish_socket = zmq.Context().socket(zmq.PUB)
        self.publish_socket.connect(f"tcp://{sub_endpoint}")
        self.receive_socket = zmq.Context().socket(zmq.SUB)
        self.receive_socket.connect(f"tcp://{pub_endpoint}")
        self.receive_socket.setsockopt(zmq.SUBSCRIBE, self.p2p_topic.encode())
        self.log_info(f"Subscribed to Threat Bus using p2p_topic '{self.p2p_topic}'.")
        self.poller = zmq.Poller()
        self.poller.register(self.receive_socket, zmq.POLLIN)

        # unset the snapshot interval, so it is not re-requested in case the
        # connector and Threat Bus lose connection and reconnect.
        self.snapshot = 0
