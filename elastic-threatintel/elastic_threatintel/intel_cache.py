###############
# INTEL CACHE #
###############

from pycti import OpenCTIConnectorHelper


class IntelCache:
    def __init__(self, helper: OpenCTIConnectorHelper):
        self.helper: OpenCTIConnectorHelper = helper

    def get(self, type: str, opencti_entity_id: str):
        current_state: dict = self.helper.get_state()
        if current_state is not None:
            if type in current_state:
                if opencti_entity_id in current_state[type]:
                    return current_state[type][opencti_entity_id]
        return None

    def set(self, type: str, opencti_entity_id: str, elastic_threatintel_id: str):
        current_state: dict = self.helper.get_state()
        if current_state is not None:
            if type in current_state:
                current_state[type][opencti_entity_id] = elastic_threatintel_id
            else:
                current_state[type] = {}
                current_state[type][opencti_entity_id] = elastic_threatintel_id
        else:
            current_state = {}
            current_state[opencti_entity_id] = elastic_threatintel_id
            self.helper.set_state(current_state)
        self.helper.set_state(current_state)
        return elastic_threatintel_id

    def delete(self, type: str, opencti_entity_id: str):
        current_state: dict = self.helper.get_state()
        if current_state is None:
            return
        if current_state is not None:
            if type in current_state and opencti_entity_id in current_state[type]:
                del current_state[type][opencti_entity_id]
                self.helper.set_state(current_state)
        return
