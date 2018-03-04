#!/usr/bin/env python
import json
from smurf.db.models import init_db
from smurf.db.models import db_session, ServiceTemplate, Project, Service, VlanIpAddress
from smurf.resources.project import get_compose_project

print 'Import vlan ip address info for active projects.'

projects = Project.query.filter().all()
for project in projects:
    if project.state == 'active':
        print 'Project ' + project.name + ' is importing.'
        compose_project = get_compose_project(project)
        containers = compose_project.containers(stopped=True)
        services = Service.query.filter(Service.project_id == project.id).all()
        for service in services:
            con= [c for c in containers if c.service == service.name]
            if len(con) == 0:
                break
            container = con[0]
            data = json.loads(service.data)
            networks = data.get('networks')
            for network in networks:
                if network != 'default':
                    service_address = networks.get(network).get('ipv4_address')
                    container_address = container.get('NetworkSettings.Networks').get(network).get('IPAddress')
                    if container_address != '':
                        networks.get(network)['ipv4_address'] = container_address
                    Service.query.filter(Service.id == service.id).update({Service.data: json.dumps(data)})
                    VlanIpAddress.query.filter(VlanIpAddress.ip_address == container_address).update({VlanIpAddress.service_id: service.id, VlanIpAddress.user_id: project.user_id, VlanIpAddress.state: 'allocated'})
                    
db_session.commit()
print 'Success.'
