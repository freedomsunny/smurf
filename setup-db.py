#!/usr/bin/env python
import smurf.config as config
from smurf.db.models import init_db

print 'Setup database ' + config.DATABASE_URI
init_db()
print 'Success!'
