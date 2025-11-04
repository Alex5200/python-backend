"""
Мок-данные для тестов без PostgreSQL.

Схема связей (RBAC):
- roles: список ролей
- permissions: список прав (resource, action)
- role_permissions: связка ролей и прав (многие-ко-многим)
- users: тестовые пользователи (без паролей, только справочные id/email)
- user_roles: назначение ролей пользователям (многие-ко-многим)

"""

from uuid import UUID


roles = [
    {"id": "11111111-1111-1111-1111-111111111111", "name": "admin"},
    {"id": "22222222-2222-2222-2222-222222222222", "name": "user"},
]

permissions = [
    {"id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "resource": "articles", "action": "read"},
    {"id": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", "resource": "articles", "action": "write"},
]

role_permissions = [
    # admin получает все права
    {"role_id": "11111111-1111-1111-1111-111111111111", "permission_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"},
    {"role_id": "11111111-1111-1111-1111-111111111111", "permission_id": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"},
    # user только читать
    {"role_id": "22222222-2222-2222-2222-222222222222", "permission_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"},
]

users = [
    {"id": "33333333-3333-3333-3333-333333333333", "email": "admin@example.com"},
    {"id": "44444444-4444-4444-4444-444444444444", "email": "user@example.com"},
]

user_roles = [
    {"user_id": "33333333-3333-3333-3333-333333333333", "role_id": "11111111-1111-1111-1111-111111111111"},
    {"user_id": "44444444-4444-4444-4444-444444444444", "role_id": "22222222-2222-2222-2222-222222222222"},
]


def get_roles_for_user(user_id: str):
    assigned = [ur["role_id"] for ur in user_roles if ur["user_id"] == user_id]
    return [r for r in roles if r["id"] in assigned]


def get_permissions_for_role(role_id: str):
    assigned = [rp["permission_id"] for rp in role_permissions if rp["role_id"] == role_id]
    return [p for p in permissions if p["id"] in assigned]


def user_has_permission(user_id: str, resource: str, action: str) -> bool:
    for role in get_roles_for_user(user_id):
        perms = get_permissions_for_role(role["id"])
        if any(p["resource"] == resource and p["action"] == action for p in perms):
            return True
    return False


