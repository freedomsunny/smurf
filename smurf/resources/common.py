from flask_restful import fields


GROUP_FIELDS = {
    "id": fields.Integer,
    "name": fields.String,
    "description": fields.String,
    "user_id": fields.String,
    "public": fields.Boolean
}

TEMPLATE_FIELDS = {
    "id": fields.Integer,
    "name": fields.String,
    "description": fields.String,
    "service": fields.String,
    "image": fields.String,
    "hostname": fields.String,
    "aliases": fields.List(fields.String),
    "environment": fields.Raw,
    "user_id": fields.String,
    # "group_id": fields.Integer,
    "independent": fields.Boolean,
    "depends": fields.List(fields.Integer)
}

CONTAINER_FIELDS = {
    "id": fields.String,
    "short_id": fields.String,
    "name": fields.String,
    "status": fields.String,
    "ip": fields.String
}

SERVICE_FIELDS = {
    "id": fields.Integer,
    "name": fields.String,
    # "template_id": fields.String,
    "service_template": fields.Nested(TEMPLATE_FIELDS),
    "hostname": fields.String,
    "command": fields.String,
    "restart": fields.String,
    "tty": fields.Boolean,
    "environment": fields.Raw,
    "networks": fields.Raw,
    "state": fields.String,
    "containers": fields.List(fields.Nested(CONTAINER_FIELDS))
}

USER_FIELDS = {
    "id": fields.String,
    "name": fields.String,
    "cname": fields.String,
    "type": fields.String
}

PROJECT_FIELDS = {
    "id": fields.Integer,
    "name": fields.String,
    "description": fields.String,
    "user": fields.Nested(USER_FIELDS),
    "state": fields.String,
    "services": fields.List(fields.Nested(SERVICE_FIELDS)),
    "yml": fields.String,
    "created": fields.DateTime('iso8601'),
    "detail": fields.String,
}

DETAIL_FIELDS = {
    ""
}

PROJECT_USER_FIELDS = {
    "id": fields.String,
    "name": fields.String,
    "cname": fields.String,
    "type": fields.String,
    "role": fields.String
}

USER_GROUP_FIELDS = {
    "id": fields.String,
    "name": fields.String,
    "description": fields.String,
    "users": fields.List(fields.Nested(USER_FIELDS))
}

PROJECT_USER_GROUP_FIELDS = {
    "id": fields.String,
    "name": fields.String,
    "description": fields.String,
    "role": fields.String
}

NETWORK_FIELDS = {
    "id": fields.Integer,
    "name": fields.String,
    "description": fields.String,
    "public": fields.Boolean,
    "user_id": fields.String,
    "vlan": fields.Integer,
    "vni": fields.Integer,
    "iscreated": fields.Boolean,
    "network_id": fields.String,
    "cidr": fields.String,
    "gateway": fields.String,
    "status": fields.String,
    "subnet_id": fields.String,
    "created": fields.DateTime('iso8601')
}

TEMPLATE_COMPOSE_FIELDS = {
    "id": fields.Integer,
    "name": fields.String,
    "description": fields.String,
    "public": fields.Boolean,
    "user_id": fields.String,
    "created": fields.DateTime('iso8601'),
    "templates": fields.List(fields.Nested(TEMPLATE_FIELDS)),
    "environment": fields.String,
}

VLAN_IP_ADDRESS = {
    "id": fields.Integer,
    "ip_address": fields.String,
    "network_id": fields.Integer
}

PROJECT_ROLE_MANAGER = 'Manager'
PROJECT_ROLE_GUEST = 'Guest'
PROJECT_ROLES = [PROJECT_ROLE_MANAGER, PROJECT_ROLE_GUEST]
