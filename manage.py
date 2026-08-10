#!/usr/bin/env -S uv run
"""Django's command-line utility for administrative tasks.

The `uv run` shebang syncs the environment from uv.lock before executing, so
`./manage.py <command>` always runs against the locked dependencies without a
venv to activate first. Deployment is unaffected: the zai-ops role invokes
`<venv>/bin/python manage.py ...`, which never consults this line.
"""
import os
import sys


def main():
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "corliss.settings")
    try:
        from django.core.management import execute_from_command_line
    except ImportError as exc:
        raise ImportError(
            "Couldn't import Django. Are you sure it's installed and available "
            "on your PYTHONPATH? Did you forget to activate a virtual "
            "environment?"
        ) from exc
    execute_from_command_line(sys.argv)


if __name__ == "__main__":
    main()
