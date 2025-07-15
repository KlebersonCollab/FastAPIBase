from enum import Enum


class Permissions(str, Enum):
    READ_USERS = "read_users"
    CREATE_USERS = "create_users"
    UPDATE_USERS = "update_users"
    DELETE_USERS = "delete_users"
    MANAGE_ROLES = "manage_roles"
