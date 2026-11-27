"""A note whose id depends on the observable it describes."""

from connectors_sdk.models import Note
from connectors_sdk.models.note import NoteStix
from pycti import Note as PyctiNote


class ObservableNote(Note):
    """Note about one observable, with an id of its own for each observable.

    The id of a connectors-sdk `Note` is built from its abstract and its content. The
    summary note does not hold the indicator, so two observables with the same OTX
    summary would get the same id and OpenCTI would merge them into one shared note.
    The id of the observable is added to what the id is built from. The content, the
    `created` date (never set) and every other property are those of a plain `Note`.

    The note must be attached to exactly one object: the observable.
    """

    def to_stix2_object(self) -> NoteStix:
        """Make the STIX note, with an id built from its content and its observable.

        Returns:
            The STIX note of a plain `Note`, except for its id.

        Raises:
            ValueError: If the note is not attached to exactly one object.
        """
        if not self.objects or len(self.objects) != 1:
            raise ValueError(
                "An ObservableNote must be attached to exactly one object."
            )
        properties = dict(super().to_stix2_object())
        # The id is not in the content sent: it only tells the notes apart
        properties.pop("id")
        return NoteStix(
            id=PyctiNote.generate_id(
                content=f"{self.content}\n{self.objects[0].id}",
                created=self.created,
                abstract=self.abstract,
            ),
            allow_custom=True,
            **properties,
        )
