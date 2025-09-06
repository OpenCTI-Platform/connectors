from pymisp import PyMISP


class MISPClient:
    """
    """

    def __init__(self, misp_url, misp_api_key, ssl_verify=True):
        """
        """
        self.pymisp = PyMISP(
            url=misp_url, key=misp_api_key, ssl=ssl_verify, debug=True)

    def add_event(self, event):
        """
        :param event:
        :return:
        """
        event = self.pymisp.add_event(event)
        return event.get("Event").get("id")

    def publish_event(self, event_id):
        """
        :param event_id:
        :return:
        """
        # Publish the event
        publish_response = self.pymisp.publish(event_id)
        if publish_response.get('message'):
            print(f"Publication status: {publish_response['message']}")
        else:
            print("Event published successfully!")

    def update_event(self, event_id, event):
        """
        :param event_id:
        :param event:
        :return:
        """
        self.pymisp.update_event(event, event_id)

