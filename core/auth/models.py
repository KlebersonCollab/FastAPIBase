from tortoise.models import Model
from tortoise import fields

class Role(Model):
    id = fields.IntField(pk=True)
    name = fields.CharField(max_length=50, unique=True)
    permissions = fields.JSONField(default=[])

    def __str__(self):
        return self.name

class RefreshToken(Model):
    id = fields.IntField(pk=True)
    user = fields.ForeignKeyField('models.User', related_name='refresh_tokens')
    token = fields.CharField(max_length=255, unique=True)
    expires_at = fields.DatetimeField()
    created_at = fields.DatetimeField(auto_now_add=True)
    is_revoked = fields.BooleanField(default=False)

    def __str__(self):
        return f"Refresh Token for {self.user.username}"