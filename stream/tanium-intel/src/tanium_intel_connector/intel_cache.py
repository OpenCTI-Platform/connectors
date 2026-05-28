class IntelCache:
    def __init__(self, helper):
        self.helper = helper

    def get(self, tanium_entity_type, opencti_entity_id) -> str | None:
        """
        Get Tanium entity ID from connector's state.
        :param tanium_entity_type: Type of Tanium entity (intel or reputation)
        :param opencti_entity_id: OpenCTI entity ID
        :return: Tanium entity ID if found in connector's state, otherwise None
        """
        current_state = self.helper.get_state()
        if current_state is None:
            return None

        if tanium_entity_type in current_state:
            if opencti_entity_id in current_state[tanium_entity_type]:
                return current_state[tanium_entity_type][opencti_entity_id]

    def set(self, tanium_entity_type, opencti_entity_id, tanium_intel_id):
        """
        Set Tanium entity ID in connector's state.
        :param tanium_entity_type: Type of Tanium entity (intel or reputation)
        :param opencti_entity_id: OpenCTI entity ID
        :param tanium_intel_id:
        """
        current_state = self.helper.get_state()
        if current_state is None:
            current_state = {opencti_entity_id: tanium_intel_id}
        else:
            if tanium_entity_type in current_state:
                current_state[tanium_entity_type][opencti_entity_id] = tanium_intel_id
            else:
                current_state[tanium_entity_type] = {}
                current_state[tanium_entity_type][opencti_entity_id] = tanium_intel_id
        self.helper.set_state(current_state)

    def delete(self, tanium_entity_type, opencti_entity_id):
        """
        Delete Tanium entity ID from connector's state.
        :param tanium_entity_type: Type of Tanium entity (intel or reputation)
        :param opencti_entity_id: OpenCTI entity ID
        """
        current_state = self.helper.get_state()
        if current_state is None:
            return None

        if (
            tanium_entity_type in current_state
            and opencti_entity_id in current_state[tanium_entity_type]
        ):
            del current_state[tanium_entity_type][opencti_entity_id]
            self.helper.set_state(current_state)
