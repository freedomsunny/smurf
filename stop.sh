#!/usr/bin/env bash
lsof -i:8913 |grep gunicorn|awk '{print $2}'|xargs kill -9
