#!/usr/bin/env bash
# Render build command for the Genius Mirage Django backend.
set -o errexit

pip install -r requirements.txt
python manage.py collectstatic --noinput
python manage.py migrate
