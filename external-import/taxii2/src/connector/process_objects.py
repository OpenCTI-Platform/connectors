import re

from pycti import StixCyberObservableTypes


class ProcessObjects:
    """
    Functions that are used to mofify the stix objects before sending
    """

    def __init__(self, helper, config, converter_to_stix):
        self.helper = helper
        self.config = config
        self.converter_to_stix = converter_to_stix

    def indicator_observable_generation(self, stix_objects: list) -> list:
        """
        Used to generate indicators or observables.
        :return: List of STIX objects
        """
        for obj in stix_objects:
            object_type = obj["type"]
            if object_type == "indicator":
                obj["x_opencti_create_observables"] = self.config.create_observables
            elif StixCyberObservableTypes.has_value(object_type):
                obj["x_opencti_create_indicators"] = self.config.create_indicators
        return stix_objects

    def add_custom_label(self, stix_objects: list) -> list:
        """
        Used to add label to object e.g. intel feed source
        :return: List of STIX objects
        """
        for obj in stix_objects:
            if "labels" in obj:
                new_labels = obj["labels"]
                new_labels.append(self.config.custom_label)
                obj["labels"] = new_labels
        return stix_objects

    def add_custom_property_label(self, stix_objects: list) -> list:
        """
        Used to copy data from a custom property and make it a label
        e.g. x_category: "phishing" has the label phishing added to object
        :return: List of STIX objects
        """
        for obj in stix_objects:
            if self.config.stix_custom_property in obj and "labels" in obj:
                new_labels = obj["labels"]
                new_labels.append(obj[self.config.stix_custom_property])
                obj["labels"] = new_labels
        return stix_objects

    def add_main_observable_type(self, stix_objects: list) -> list:
        """
        Used to add the main observable type to an indicator
        :return: List of STIX objects
        """
        # Define a mapping of observable types to x_opencti_main_observable_type
        observable_type_mapping = {
            "ipv4-addr": "IPv4-Addr",
            "ipv6-addr": "IPv6-Addr",
            "file": "StixFile",
            "domain-name": "Domain-Name",
            "url": "Url",
            "email-addr": "Email-Addr",
        }
        for obj in stix_objects:
            if obj["type"] == "indicator":
                # Perform regex search to extract the observable type
                match = re.search(r"\[(.*?):.*'(.*?)\'\]", obj["pattern"])
                if match is not None:
                    # Get the observable type from the regex match and set the corresponding value
                    observable_type = match[1]
                    if observable_type in observable_type_mapping:
                        obj["x_opencti_main_observable_type"] = observable_type_mapping[
                            observable_type
                        ]
        return stix_objects

    def taxii20_add_pattern_type(self, stix_objects: list) -> list:
        """
        Used to add pattern_type to a taxii 2.0 object if missing
        :return: List of STIX objects
        """
        for obj in stix_objects:
            if "pattern_type" not in obj and obj["type"] == "indicator":
                obj["pattern_type"] = "stix"
        return stix_objects

    def force_pattern_as_name(self, stix_objects: list) -> list:
        """
        Forces name of indicator to be extracted from pattern
        If indicator contains multiple observables (AND/OR in pattern),
        the name specified in the config is used.
        :return: List of STIX objects
        """
        for obj in stix_objects:
            if obj["type"] == "indicator":
                # Perform regex search to extract the pattern
                match = re.search(r"\[(.*?):.*'(.*?)\'\]", obj["pattern"])
                # If multiple observables (AND/OR), use the config name
                if match is not None and (
                    " AND " in obj["pattern"] or " OR " in obj["pattern"]
                ):
                    obj["name"] = self.config.force_multiple_pattern_name
                # Otherwise, use the extracted part from the pattern
                elif match != None:
                    obj["name"] = match[2]
        return stix_objects

    def determine_x_opencti_score_by_label(self, stix_objects: list) -> list:
        """
        Lets you define custom scores of an indicator based on the label
        :return: List of STIX objects
        """
        for obj in stix_objects:
            if "labels" in obj:
                obj_labels_set = {label.lower() for label in obj["labels"]}
                # High score labels
                for high_label in self.config.indicator_high_score_labels:
                    if high_label.lower() in obj_labels_set:
                        obj["x_opencti_score"] = self.config.indicator_high_score
                        break
                # Medium score labels (if high score not already assigned)
                if "x_opencti_score" not in obj:
                    for med_label in self.config.indicator_medium_score_labels:
                        if med_label.lower() in obj_labels_set:
                            obj["x_opencti_score"] = self.config.indicator_medium_score
                            break
                # Low score labels (if neither high nor medium score assigned)
                if "x_opencti_score" not in obj:
                    for low_label in self.config.indicator_low_score_labels:
                        if low_label.lower() in obj_labels_set:
                            obj["x_opencti_score"] = self.config.indicator_low_score
                            break
                # Default score if no match found
                if "x_opencti_score" not in obj:
                    obj["x_opencti_score"] = self.config.default_x_opencti_score
        return stix_objects

    def set_indicator_as_detection(self, stix_objects: list) -> list:
        """
        Sets Detection flag for an indicator
        :return: List of STIX objects
        """
        for obj in stix_objects:
            if obj["type"] == "indicator":
                obj["x_opencti_detection"] = True
        return stix_objects

    def create_author(self, stix_objects: list) -> list:
        """
        Creates author for object
        :return: List of STIX objects
        """
        for obj in stix_objects:
            obj["created_by_ref"] = self.converter_to_stix.author.get("id")
        stix_objects.append(self.converter_to_stix.author)
        return stix_objects

    def exclude_specific_labels(self, stix_objects: list) -> list:
        """
        Lets you define labels to ignore
        :return: List of STIX objects
        """
        for obj in stix_objects:
            if "labels" in obj:
                new_labels = []
                for label in obj["labels"]:
                    exclude = any(
                        re.search(regex, label)
                        for regex in self.config.labels_to_exclude
                    )
                    # If no match, add label to new_labels
                    if not exclude:
                        new_labels.append(label)

                # Assign new_labels
                obj["labels"] = new_labels
        return stix_objects

    def replace_characters_in_label(self, stix_objects: list) -> list:
        """
        Lets you replace characters in a labels
        :return: List of STIX objects
        """
        # Parse the characters_to_replace_in_label string into a list of (find, replace) tuples
        replacement_rules = [
            tuple(pair.split(":"))
            for pair in self.config.characters_to_replace_in_label
        ]

        for obj in stix_objects:
            if "labels" in obj:
                new_labels = []
                for label in obj["labels"]:
                    # Apply each replacement rule
                    for find, replace in replacement_rules:
                        label = label.replace(find, replace)
                    new_labels.append(label)

                # Assign new_labels
                obj["labels"] = new_labels
        return stix_objects

    def ignore_pattern_types(self, stix_objects: list) -> list:
        """
        Lets you ignore certain pattern types
        :return: List of STIX objects
        """
        # Copy obj to new_stix_objects if not in ignored pattern types
        new_stix_objects = []
        for obj in stix_objects:
            if obj["type"] == "indicator":
                if (
                    "pattern_type" in obj
                    and obj["pattern_type"] not in self.config.pattern_types_to_ignore
                ):
                    new_stix_objects.append(obj)
            else:
                # Still add other types
                new_stix_objects.append(obj)
        return new_stix_objects

    def ignore_object_types(self, stix_objects: list) -> list:
        """
        Lets you ignore certain object types
        :return: List of STIX objects
        """
        return [
            obj
            for obj in stix_objects
            if "type" in obj and obj["type"] not in self.config.object_types_to_ignore
        ]

    def ignore_specific_patterns(self, stix_objects: list) -> list:
        """
        Lets you ignore certain patterns
        :return: List of STIX objects
        """
        # Copy obj to new_stix_objects if not in ignored patterns
        new_stix_objects = []
        for obj in stix_objects:
            if obj["type"] == "indicator":
                if "pattern" in obj and all(
                    pattern not in obj["pattern"]
                    for pattern in self.config.patterns_to_ignore
                ):
                    new_stix_objects.append(obj)
            else:
                # Still add other types
                new_stix_objects.append(obj)
        return new_stix_objects

    def ignore_specific_notes(self, stix_objects: list) -> list:
        """
        Lets you ignore certain notes
        :return: List of STIX objects
        """
        # Copy obj to new_stix_objects if not in ignored patterns
        new_stix_objects = []
        for obj in stix_objects:
            if obj["type"] == "note":
                if "content" in obj and all(
                    content not in obj["content"]
                    for content in self.config.notes_to_ignore
                ):
                    new_stix_objects.append(obj)
            else:
                # Still add other types
                new_stix_objects.append(obj)
        return new_stix_objects

    def save_original_indicator_id_to_note(self, stix_objects: list) -> list:
        """
        Lets you save the original indicator id as a note
        :return: List of STIX objects
        """
        for obj in stix_objects:
            if obj["type"] == "indicator":
                note = self.converter_to_stix.create_note(
                    abstract=self.config.save_original_indicator_id_abstract,
                    content=obj["id"],
                    object_refs=[obj["id"]],
                )
                stix_objects.append(note)
        return stix_objects

    def change_report_status(self, stix_objects: list) -> list:
        """
        Lets you change the status of the report on ingestion
        :return: List of STIX objects
        """
        for obj in stix_objects:
            if obj["type"] == "report":
                obj["x_opencti_workflow_id"] = (
                    self.config.change_report_status_x_opencti_workflow_id
                )
        return stix_objects

    def objects(self, stix_objects: list) -> list:
        """
        Used to process stix_objects and make modifications
        :return: List of STIX objects
        """
        stix_objects = self.add_main_observable_type(stix_objects)

        if not self.config.taxii2v21:
            stix_objects = self.taxii20_add_pattern_type(stix_objects)

        if self.config.ignore_pattern_types:
            stix_objects = self.ignore_pattern_types(stix_objects)

        if self.config.ignore_object_types:
            stix_objects = self.ignore_object_types(stix_objects)

        if self.config.ignore_specific_patterns:
            stix_objects = self.ignore_specific_patterns(stix_objects)

        if self.config.ignore_specific_notes:
            stix_objects = self.ignore_specific_notes(stix_objects)

        if self.config.create_observables or self.config.create_indicators:
            stix_objects = self.indicator_observable_generation(stix_objects)

        if self.config.add_custom_label:
            stix_objects = self.add_custom_label(stix_objects)

        if self.config.stix_custom_property_to_label:
            stix_objects = self.add_custom_property_label(stix_objects)

        if self.config.force_pattern_as_name:
            stix_objects = self.force_pattern_as_name(stix_objects)

        if self.config.determine_x_opencti_score_by_label:
            stix_objects = self.determine_x_opencti_score_by_label(stix_objects)

        if self.config.set_indicator_as_detection:
            stix_objects = self.set_indicator_as_detection(stix_objects)

        if self.config.create_author:
            stix_objects = self.create_author(stix_objects)

        if self.config.exclude_specific_labels:
            stix_objects = self.exclude_specific_labels(stix_objects)

        if self.config.replace_characters_in_label:
            stix_objects = self.replace_characters_in_label(stix_objects)

        if self.config.save_original_indicator_id_to_note:
            stix_objects = self.save_original_indicator_id_to_note(stix_objects)

        if self.config.change_report_status:
            stix_objects = self.change_report_status(stix_objects)

        return stix_objects
