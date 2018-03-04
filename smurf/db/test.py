from models import Project
from openstack_db import NetworkSegments
from sqlalchemy import and_

project = Project('dddddddd', 'eeeeeeeeeee', 'fffffffffffff')

print dir(project)

project.services = 11111111111111


network = NetworkSegments.query.filter(NetworkSegments.network_id == '43758034-9041-48ea-9679-259589428d69').first()
print network.segmentation_id
