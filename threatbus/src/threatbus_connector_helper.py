"""
Similar to the OpenCTIConnectorHelper, this ThreatBusConnectorHelper facilitates
registration, subscriptions, and message passing to and from Threat Bus via Zero
MQ.
"""

from threading import Event, Thread
from typing import Callable
import zmq


def send_manage_message(endpoint: str, action: dict, timeout: int = 5):
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


def subscribe(endpoint: str, topic: str):
    """
    Subscribes this app to Threat Bus for the given topic.
    @param endpoint The ZMQ management endpoint of Threat Bus ('host:port')
    @param topic The topic to subscribe to
    """
    action = {"action": "subscribe", "topic": topic}
    return send_manage_message(endpoint, action)


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
        subscribe_topic: str = None,
        publish_topic: str = None,
    ):
        super(ThreatBusConnectorHelper, self).__init__()
        self._stop_event = Event()
        self.zmq_manage_ep = zmq_endpoint
        self.message_callback = message_callback
        self.subscribe_topic = subscribe_topic
        self.publish_topic = publish_topic

        # These fields will be populated upon successful registration
        self.publish_socket = None
        self.receive_socket = None
        self.p2p_topic = None

        self._register_to_threatbus()

    def _running(self):
        """Private predicate to test if this Thread should keep on running"""
        return not self._stop_event.is_set()

    def stop(self):
        """Stops the current Thread"""
        self._stop_event.set()
        reply = unsubscribe(self.zmq_manage_ep, self.p2p_topic)
        if not reply_is_success(reply):
            raise RuntimeError("Error unsubscribing from Threat Bus.")

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
        self.receive_socket.setsockopt(zmq.SUBSCRIBE, self.p2p_topic.encode())
        poller = zmq.Poller()
        poller.register(self.receive_socket, zmq.POLLIN)
        while self._running():
            socks = dict(
                poller.poll(timeout=100)
            )  # smaller timeouts may increase CPU load
            if (
                self.receive_socket in socks
                and socks[self.receive_socket] == zmq.POLLIN
            ):
                try:
                    topic, msg = self.receive_socket.recv().decode().split(" ", 1)
                    self.message_callback(msg)
                except Exception:
                    continue

    def _register_to_threatbus(self) -> bool:
        """
        Registers this connector at the configured Threat Bus endpoint.
        Populates the registration details to this connector instance.
        @return True for successful subscription, False otherwise
        """
        reply = subscribe(self.zmq_manage_ep, self.subscribe_topic)
        if not reply_is_success(reply):
            raise RuntimeError("Threat Bus subscription failed.")
        pub_endpoint = reply.get("pub_endpoint", None)
        sub_endpoint = reply.get("sub_endpoint", None)
        topic = reply.get("topic", None)
        if not pub_endpoint or not sub_endpoint or not topic:
            raise RuntimeError(
                "Threat Bus subscription failed with an incomplete reply."
            )

        # Registration successful, create ZMQ sockets
        self.p2p_topic = topic
        self.publish_socket = zmq.Context().socket(zmq.PUB)
        self.publish_socket.connect(f"tcp://{sub_endpoint}")
        self.receive_socket = zmq.Context().socket(zmq.SUB)
        self.receive_socket.connect(f"tcp://{pub_endpoint}")
