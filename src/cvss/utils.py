import enum


def get_enum_first_char(enum_entry: enum):
    return str(enum_entry).split('.')[1][0]
