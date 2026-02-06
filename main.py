from typing import List

from sqlalchemy.orm import Session

from auth import create_access_token, decode_token, hash_password, verify_password
from database import engine, get_db
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from models import Product, User
from schemas import (
    LoginRequest,
    ProductCreate,
    ProductResponse,
    ProductUpdate,
    UserCreate,
)

app = FastAPI()
security = HTTPBearer()

User.metadata.create_all(bind=engine)
Product.metadata.create_all(bind=engine)

# def seed_admin():
#     db = SessionLocal()
#     try:
#         admin = db.query(User).filter(User.username == "admin").first()
#         if not admin:
#             admin_user = User(
#                 username="admin",
#                 password_hash=hash_password("123"),
#                 is_admin=True
#             )
#             db.add(admin_user)
#             db.commit()
#     finally:
#         db.close()

# seed_admin()


@app.get("/")
def read_root():
    return {"Hello": "World"}


@app.post("/register", status_code=status.HTTP_201_CREATED)
def register(body: UserCreate, db: Session = Depends(get_db)):
    existing_user = db.query(User).filter(User.username == body.username).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already registered")

    hashed_password = hash_password(body.password)
    new_user = User(
        username=body.username, password_hash=hashed_password, is_admin=False
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return {"id": new_user.id, "username": new_user.username}


@app.post("/login")
def login(body: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == body.username).first()
    if not user or not verify_password(body.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token_data = {"sub": user.username, "is_admin": user.is_admin}
    token = create_access_token(token_data)
    return {"access_token": token, "token_type": "bearer"}


def get_current_user(creds: HTTPAuthorizationCredentials = Depends(security)):
    payload = decode_token(creds.credentials)
    username = payload.get("sub")
    is_admin = payload.get("is_admin")

    if username is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload"
        )

    return {"username": username, "is_admin": is_admin}


@app.get("/me")
def me(current_user=Depends(get_current_user)):
    return current_user


def require_admin(current_user=Depends(get_current_user)):
    if not current_user.get("is_admin", False):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Admin privileges required"
        )
    return current_user


@app.post("/products/", status_code=status.HTTP_201_CREATED)
def create_product(
    product: ProductCreate, db=Depends(get_db), admin=Depends(require_admin)
):
    if not admin.get("is_admin", False):
        raise HTTPException(status_code=403, detail="Admin privileges required")

    db_product = Product(
        name=product.name, price=product.price, in_stock=product.in_stock
    )

    db.add(db_product)
    db.commit()
    db.refresh(db_product)

    return db_product


@app.get("/products/", response_model=List[ProductResponse])
def get_products(page: int = 1, limit: int = 10, db: Session = Depends(get_db)):
    offset = (page - 1) * limit
    products = db.query(Product).offset(offset).limit(limit).all()
    return products


@app.get("/products/{product_id}", response_model=ProductResponse)
def get_product_detail(product_id: int, db=Depends(get_db)):
    db_product = db.query(Product).filter(Product.id == product_id).first()
    if db_product is None:
        raise HTTPException(status_code=404, detail="Product not found")
    return db_product


@app.put("/products/{product_id}", response_model=ProductResponse)
def update_product(
    product_id: int,
    product: ProductUpdate,
    db: Session = Depends(get_db),
    admin=Depends(require_admin),
):
    if not admin.get("is_admin", False):
        raise HTTPException(status_code=403, detail="Admin privileges required")

    db_product = db.query(Product).filter(Product.id == product_id).first()
    if db_product is None:
        raise HTTPException(status_code=404, detail="Product not found")

    if product.name is not None:
        db_product.name = product.name
    if product.price is not None:
        db_product.price = product.price
    if product.in_stock is not None:
        db_product.in_stock = product.in_stock

    db.commit()
    db.refresh(db_product)

    return db_product


@app.delete("/products/{product_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_product(
    product_id: int, db: Session = Depends(get_db), admin=Depends(require_admin)
):
    if not admin.get("is_admin", False):
        raise HTTPException(status_code=403, detail="Admin privileges required")

    db_product = db.query(Product).filter(Product.id == product_id).first()
    if db_product is None:
        raise HTTPException(status_code=404, detail="Product not found")

    db.delete(db_product)
    db.commit()

    return
