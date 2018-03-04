#!/usr/bin/env bash
python setup-db.py
gunicorn -k flask_sockets.worker -w 8 -b 0.0.0.0:8913 -t 100 run:app
