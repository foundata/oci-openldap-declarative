"""Entry UUID values shared by parser, schema and image contract tests."""

ENTRY_UUID_CASES = [
    ("7f38d690-8427-1ca2-98b4-bd5ee71ac31f", True),
    ("7f38d690-8427-2ca2-98b4-bd5ee71ac31f", True),
    ("7f38d690-8427-3ca2-98b4-bd5ee71ac31f", True),
    ("7f38d690-8427-4ca2-98b4-bd5ee71ac31f", True),
    ("7f38d690-8427-5ca2-98b4-bd5ee71ac31f", True),
    ("7f38d690-8427-6ca2-98b4-bd5ee71ac31f", True),
    ("7f38d690-8427-7ca2-98b4-bd5ee71ac31f", True),
    ("7f38d690-8427-8ca2-98b4-bd5ee71ac31f", True),
    ("7F38D690-8427-4CA2-98B4-BD5EE71AC31F", False),
    ("00000000-0000-0000-0000-000000000000", False),
    ("7f38d690-8427-9ca2-98b4-bd5ee71ac31f", False),
    ("7f38d690-8427-5ca2-78b4-bd5ee71ac31f", False),
    ("7f38d69084275ca298b4bd5ee71ac31f", False),
    ("{7f38d690-8427-5ca2-98b4-bd5ee71ac31f}", False),
    ("7f38d690-8427-5ca2-98b4-bd5ee71ac31f\n", False),
]
