"""Constants for the ShadowTrackr connector"""

# Score steps for the ShadowTrackr connector.
# The first value is the threshold, the second value is the decrement.
SCORE_STEPS: list[tuple[int, int]] = [
    (99, 60),
    (89, 40),
    (69, 20),
    (50, 10),
]
