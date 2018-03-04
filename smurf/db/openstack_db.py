from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import scoped_session, sessionmaker
from sqlalchemy.ext.declarative import declarative_base

import smurf.config as config
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import scoped_session, sessionmaker
from sqlalchemy.pool import NullPool

# pool_recycle should less than MySQL wait_timeout
# engine = create_engine(config.OPENSTACK_DATABASE_URI, convert_unicode=True, pool_recycle=5, poolclass=NullPool)
engine = create_engine(config.OPENSTACK_DATABASE_URI, pool_recycle=20,  poolclass=NullPool)
db_session = scoped_session(sessionmaker(autocommit=False,
                                         autoflush=False,
                                         bind=engine))
Base = declarative_base()
Base.query = db_session.query_property()


def init_db():
    Base.metadata.create_all(bind=engine)


class NetworkSegments(Base):
    __tablename__ = 'networksegments'
    id = Column(String, primary_key=True)
    network_id = Column(String)
    network_type = Column(String)
    physical_network = Column(String)
    segmentation_id = Column(Integer)
    is_dynamic = Column(Integer)
    segment_index = Column(Integer)
    standard_attr_id = Column(Integer)
    name = Column(String)

    def __repr__(self):
        return '<NetworkSegments %r>' % (self.name)


class Ml2VxlanEndpoints(Base):
    __tablename__ = 'ml2_vxlan_endpoints'
    ip_address = Column(String, primary_key=True)
    udp_port = Column(Integer)
    host = Column(String)

    def __repr__(self):
        return '<Ml2VxlanEndpoints %r>' % (self.host)
