from datetime import datetime

from pydantic import ConfigDict, EmailStr, Field, HttpUrl, field_validator, model_validator
from typing_extensions import Self

from backend.common.enums import StatusType
from backend.common.schema import SchemaBase
from backend.app.admin.schema.role import GetRoleListDetails



class UserBase(SchemaBase):
    firstname: str | None = None
    lastname: str | None = None
    fullname: str | None = None
    phone: str | None = None
    pseudo: str | None = None
    email_verified: bool = False
    country_code: str | None = None
    profile_image: dict | None = None
    

class UserLoginSchema(SchemaBase):
    email: EmailStr
    password: str


class UserRegister(SchemaBase):
    password: str
    email: EmailStr
    # International number, digits only (e.g. 2250152311124). Used for the WhatsApp
    # OTP. Optional so the CLI/admin creation still works; required by the public
    # register endpoint when OTP is enabled (checked in the service).
    phone: str | None = None

    @field_validator('password')
    @classmethod
    def _password_policy(cls, v: str) -> str:
        # Public sign-up: enforce the policy server-side (the API is reachable
        # directly, not only through the web form). >=8 chars, first letter uppercase.
        if not v or len(v) < 8:
            raise ValueError('Le mot de passe doit contenir au moins 8 caractères.')
        if not v[0].isupper():
            raise ValueError('Le mot de passe doit commencer par une majuscule.')
        return v

    @field_validator('phone')
    @classmethod
    def _phone_digits(cls, v: str | None) -> str | None:
        if v is None:
            return v
        digits = ''.join(ch for ch in v if ch.isdigit())
        if not (8 <= len(digits) <= 15):
            raise ValueError('Numéro de téléphone invalide (indicatif + numéro, chiffres uniquement).')
        return digits


class VerifyOtpParam(SchemaBase):
    email: EmailStr
    code: str = Field(min_length=4, max_length=8)


class ResendOtpParam(SchemaBase):
    email: EmailStr


class UserUpdate(UserBase):
    pass


class UpdateUserParam(SchemaBase):
    firstname: str | None = None
    lastname: str | None = None
    email: EmailStr | None = None
    phone: str | None = None


class UserResetPassword(SchemaBase):
    new_password: str
    confirm_password: str


class UserInfoSchemaBase(UserBase):
    email: EmailStr



class GetUserInfoNoRelationDetail(UserInfoSchemaBase):
    model_config = ConfigDict(from_attributes=True)

    id: int
    x_id: str
    profile_image: dict | None = None
    status: bool
    join_time: datetime = None
    last_login_time: datetime | None = None



class GetUserInfoListDetails(GetUserInfoNoRelationDetail):
    model_config = ConfigDict(from_attributes=True)

    roles: list[GetRoleListDetails] | None = []


class GetCurrentUserInfoDetail(GetUserInfoListDetails):
    model_config = ConfigDict(from_attributes=True)

    roles: list[GetRoleListDetails] | list[str] | None = []

    @model_validator(mode='after')
    def handel(self) -> Self:
        """Dealing with sectors and roles"""
        roles = self.roles
        if roles:
            self.roles = [{'name': role.name} for role in roles]  # type: ignore
        return self


class CurrentUserIns(GetUserInfoListDetails):
    model_config = ConfigDict(from_attributes=True)


class UpdatePasswordParam(SchemaBase):
    old_password: str
    new_password: str
    confirm_password: str
