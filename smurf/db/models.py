import datetime
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, Boolean, DateTime, Text
from sqlalchemy.orm import scoped_session, sessionmaker, relationship
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.pool import NullPool

import smurf.config as config

# pool_recycle should less than MySQL wait_timeout
# engine = create_engine(config.DATABASE_URI, convert_unicode=True, pool_recycle=3600)
# db_session = scoped_session(sessionmaker(autocommit=False,
#                                          autoflush=False,
#                                          bind=engine))
# poolclass=NullPool,
engine = create_engine(config.DATABASE_URI, poolclass=NullPool, pool_recycle=20)
db_session = scoped_session(sessionmaker(autocommit=False,
                                         autoflush=False,
                                         bind=engine))


Base = declarative_base()
Base.query = db_session.query_property()


def init_db():
    Base.metadata.create_all(bind=engine)


class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    name = Column(String(50), unique=True)
    uid = Column(String(255))
    type = Column(String(50))
    state = Column(String(50))

    def __init__(self, name=None, uid=None, type='User', state='Active'):
        self.name = name
        self.uid = uid
        self.type = type
        self.state = state

    def __repr__(self):
        return '<User %r>' % (self.name)


class UserGroupUserRef(Base):
    __tablename__ = 'user_group_user_ref'
    id = Column(Integer, primary_key=True)
    user_id = Column('user_id', Integer, ForeignKey('users.id'))
    group_id = Column('group_id', Integer, ForeignKey('user_groups.id'))

    def __init__(self, group_id, user_id):
        self.group_id = group_id
        self.user_id = user_id


class UserGroup(Base):
    __tablename__ = 'user_groups'
    id = Column(Integer, primary_key=True)
    name = Column(String(50))
    description = Column(String(255))
    user_id = Column('user_id', Integer, ForeignKey('users.id'))
    created = Column(DateTime, default=datetime.datetime.now())
    removed = Column(DateTime)
    users = relationship('User', secondary=UserGroupUserRef.__tablename__, backref='groups')

    def __init__(self, name, description, user_id):
        self.name = name
        self.description = description
        self.user_id = user_id

    def __repr__(self):
        return '<usergroup %r>' % (self.name)


class ServiceTemplate(Base):
    __tablename__ = 'service_templates'
    id = Column(Integer, primary_key=True)
    name = Column(String(50))
    description = Column(String(255))
    image = Column(String(120))
    yml = Column(Text)
    user_id = Column('user_id', String(50))
    independent = Column(Boolean, default=True)

    def __init__(self, name, description, image, yml, user_id=None, independent=True):
        self.name = name
        self.description = description
        self.image = image
        self.yml = yml
        self.user_id = user_id
        self.independent = independent

    def __repr__(self):
        return '<ServiceTemplate %r>' % (self.name)


class Project(Base):
    __tablename__ = 'projects'
    id = Column(Integer, primary_key=True)
    name = Column(String(50))
    description = Column(String(255))
    user_id = Column(String(50))
    yml = Column(Text)
    state = Column(String(50))
    created = Column(DateTime, default=datetime.datetime.now())
    removed = Column(DateTime)
    detail = Column(Text)
    resource = Column(String(100))

    def __init__(self, name, description, user_id, yml=None, detail=None, resource=None):
        self.name = name
        self.description = description
        self.user_id = user_id
        self.state = 'created'
        self.yml = yml
        self.detail = detail
        self.resource = resource

    def __repr__(self):
        return '<project %r>' % (self.name)


class Service(Base):
    __tablename__ = 'services'
    id = Column(Integer, primary_key=True)
    name = Column(String(50))
    project_id = Column('project_id', Integer, ForeignKey('projects.id'))
    template_id = Column('template_id', Integer, ForeignKey('service_templates.id'))
    data = Column(Text)

    def __init__(self, name, project_id, template_id, data):
        self.name = name
        self.project_id = project_id
        self.template_id = template_id
        self.data = data

    def __repr__(self):
        return '<Service %r>' % (self.name)


class ProjectUserRef(Base):
    __tablename__ = 'project_user_ref'
    id = Column(Integer, primary_key=True)
    project_id = Column('project_id', Integer, ForeignKey('projects.id'))
    user_id = Column('user_id', Integer, ForeignKey('users.id'))
    role = Column(String(32))

    def __init__(self, project_id, user_id, role):
        self.project_id = project_id
        self.user_id = user_id
        self.role = role


class ProjectUserGroupRef(Base):
    __tablename__ = 'project_user_group_ref'
    id = Column(Integer, primary_key=True)
    project_id = Column('project_id', Integer, ForeignKey('projects.id'))
    user_group_id = Column('user_group_id', Integer, ForeignKey('user_groups.id'))
    role = Column(String(32))

    def __init__(self, project_id, user_group_id, role):
        self.project_id = project_id
        self.user_group_id = user_group_id
        self.role = role


class Network(Base):
    __tablename__ = 'networks'
    id = Column(Integer, primary_key=True)
    name = Column(String(50))
    description = Column(String(255))
    public = Column(Boolean, default=False)
    user_id = Column(String(50))
    created = Column(DateTime, default=datetime.datetime.now())
    removed = Column(DateTime)
    vlan = Column(Integer)
    vni = Column(Integer)
    iscreated = Column(Boolean)
    network_id = Column(String(50))
    subnet_id = Column(String(50))
    cidr = Column(String(50))
    gateway = Column(String(50))
    status = Column(String(10))

    def __init__(self, name, description, user_id, vlan, iscreated=False, network_id=None, subnet_id=None, vni=None,
                 cidr=None, public=True, gateway=None, status=None):
        self.name = name
        self.description = description
        self.user_id = user_id
        self.public = public
        self.vlan = vlan
        self.vni = vni
        self.iscreated = iscreated
        self.network_id = network_id
        self.subnet_id = subnet_id
        self.cidr = cidr
        self.gateway = gateway
        self.status = status

    def __repr__(self):
        return '<network %r>' % (self.name)


class ComposeTemplateRef(Base):
    __tablename__ = 'compose_template_ref'
    id = Column(Integer, primary_key=True)
    compose_id = Column('compose_id', Integer, ForeignKey('template_composes.id'))
    template_id = Column('template_id', Integer, ForeignKey('service_templates.id'))

    def __init__(self, compose_id, template_id):
        self.compose_id = compose_id
        self.template_id = template_id


class TemplateCompose(Base):
    __tablename__ = 'template_composes'
    id = Column(Integer, primary_key=True)
    name = Column(String(50))
    description = Column(String(255))
    public = Column(Boolean, default=True)
    user_id = Column(String(50))
    created = Column(DateTime, default=datetime.datetime.now())
    removed = Column(DateTime)
    templates = relationship('ServiceTemplate', secondary=ComposeTemplateRef.__tablename__, backref='composes')
    environment = Column(Text)

    def __init__(self, name, description, user_id=None, public=True, environment=None):
        self.name = name
        self.description = description
        self.user_id = user_id
        self.public = public
        self.environment = environment

    def __repr__(self):
        return '<TemplateCompose %r>' % self.name


class VlanIpAddress(Base):
    __tablename__ = 'vlan_ip_address'
    id = Column(Integer, primary_key=True)
    ip_address = Column(String(20))
    network_id = Column('network_id', Integer, ForeignKey('networks.id'))
    service_id = Column('service_id', Integer, ForeignKey('services.id'))
    user_id = Column(String(50))
    state = Column(String(20))
    port_id = Column(String(50))

    def __init__(self, ip_address, network_id, service_id, user_id, port_id, state='Active'):
        self.network_id = network_id
        self.service_id = service_id
        self.user_id = user_id
        self.state = state
        self.ip_address = ip_address
        self.port_id = port_id


class ServiceTemplateDepends(Base):
    __tablename__ = 'service_template_depends'
    id = Column(Integer, primary_key=True)
    template_id = Column('template_id', Integer, ForeignKey('service_templates.id'))
    template_id_depend = Column('template_id_depend', Integer, ForeignKey('service_templates.id'))

    def __init__(self, template_id, template_id_depend):
        self.template_id = template_id
        self.template_id_depend = template_id_depend


class Containers(Base):
    __tablename__ = 'containers'
    uid = Column(String(50), primary_key=True)
    name = Column(String(50))
    id = Column(String(100))
    status = Column(String(10))
    owner = Column(String(20))
    project_id = Column('project_id', Integer, ForeignKey('projects.id'))
    ip = Column(String(20))
    password = Column(String(50))

    def __init__(self, uid, name, id, status, owner, project_id, ip=None, password=None):
        self.uid = uid
        self.name = name
        self.id = id
        self.status = status
        self.owner = owner
        self.project_id = project_id
        self.ip = ip
        self.password = password
