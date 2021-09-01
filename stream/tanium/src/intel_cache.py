###############
# INTEL CACHE #
###############


class IntelCache:
    def __init__(self, helper):
        self.helper = helper

    def get(self, type, opencti_entity_id):
        current_state = self.helper.get_state()
        if current_state is not None:
            if type in current_state:
                if opencti_entity_id in current_state[type]:
                    return current_state[type][opencti_entity_id]
        return None

    def set(self, type, opencti_entity_id, tanium_intel_id):
        current_state = self.helper.get_state()
        if current_state is not None:
            if type in current_state:
                current_state[type][opencti_entity_id] = tanium_intel_id
            else:
                current_state[type] = {}
                current_state[type][opencti_entity_id] = tanium_intel_id
        else:
            current_state = {}
            current_state[opencti_entity_id] = tanium_intel_id
        self.helper.set_state(current_state)
        return tanium_intel_id

    def delete(self, type, opencti_entity_id):
        current_state = self.helper.get_state()
        if current_state is None:
            return
        if current_state is not None:
            if type in current_state and opencti_entity_id in current_state[type]:
                del current_state[type][opencti_entity_id]
                self.helper.set_state(current_state)
        return
