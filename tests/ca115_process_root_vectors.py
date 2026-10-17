from pathlib import Path

PREFIX_CASES = ("inside", "case", "mixed-separators", "normalized", "sibling-prefix")


def prefix_vector(image: Path, case: str):
    root = str(image.parents[3])
    value = str(image)
    if case == "case":
        value = value.upper()
        root = root.lower() + "\\"
    elif case == "mixed-separators":
        value = value.replace("\\", "/")
        root = root.replace("\\", "/") + "/"
    elif case == "normalized":
        root += "\\unused\\.."
        value = str(image.parent) + "\\..\\runtime\\" + image.name
    elif case == "sibling-prefix":
        value = root + "x" + value[len(root):]
    return root, value, case != "sibling-prefix"
