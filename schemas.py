from typing import Optional

from pydantic import BaseModel, Field


class LoginRequest(BaseModel):
    username: str
    password: str


class UserCreate(BaseModel):
    username: str
    password: str


class UserResponse(BaseModel):
    id: int
    username: str
    is_admin: bool

    class Config:
        orm_mode = True


# PRODUCTS
class ProductCreate(BaseModel):
    name: str
    price: float = Field(..., gt=0)  # price > 0
    in_stock: bool


class ProductUpdate(BaseModel):
    name: Optional[str] = None
    price: Optional[float] = Field(None, gt=0)  # nếu có thì phải > 0
    in_stock: Optional[bool] = None


class ProductResponse(BaseModel):
    id: int
    name: str
    price: float
    in_stock: bool

    class Config:
        orm_mode = True
