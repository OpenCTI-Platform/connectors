# Copyright (C) 2020-2022 Hatching B.V.
# All rights reserved.

def prompt_select_options(options, key, f=None):
    print("\nMake your selection by entering the numbers as listed below "
    "separated by spaces and finish with enter.\n")

    i = 0
    for option in options:
        em = " "
        if option.get("selected"):
            em = ">"
        print(em, i, option[key])
        i += 1

    selection = []
    choices = input("> ")
    for choice in choices.split(" "):
        if choice.strip() == "":
            continue

        try:
            choice = int(choice)
        except ValueError:
            print("Bad input ", choice)
            continue

        if choice < 0 or len(options) <= choice:
            print("Out of range ", choice)
            continue

        if choice in selection:
            continue

        selection.append(choice)

    if f:
        if not f(selection):
            return prompt_select_options(options, key,  f)

    if len(selection) > 0:
        print("You selected:")
    for choice in selection:
        print(" ", options[choice][key])
    return selection
