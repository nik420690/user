from fastapi import FastAPI, HTTPException, Response, Body
from pymongo import MongoClient
from pydantic import BaseModel
from typing import List
import uuid
from starlette.middleware.cors import CORSMiddleware
from passlib.context import CryptContext
import os
import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
import rabbitpy
import requests
import uuid
from datetime import datetime, timedelta

# pozeni kodo s tem: uvicorn main:app --host 0.0.0.0 --port 8000


# Function to log messages to RabbitMQ
def logMessageToRabbitMQ(correlationId, message, logType, url, applicationName):
    rabbit_conn = None
    rabbit_channel = None
    try:
        # RabbitMQ setup
        rabbitUser = "student"
        rabbitPassword = "student123"
        rabbitHost = "studentdocker.informatika.uni-mb.si"
        rabbitPort = "5672"
        vhost = ""
        amqpUrl = f"amqp://{rabbitUser}:{rabbitPassword}@{rabbitHost}:{rabbitPort}/{vhost}"
        exchange = 'upp-3'
        routingKey = 'zelovarnikey'
        # Connect to RabbitMQ
        rabbit_conn = rabbitpy.Connection(amqpUrl)
        rabbit_channel = rabbit_conn.channel()

        msg = f"{datetime.now().isoformat()} {logType} {url} Correlation: {correlationId} [{applicationName}] - {message}"

        message = rabbitpy.Message(rabbit_channel, msg)

        # Declare the exchange
        exchange = rabbitpy.Exchange(rabbit_channel, exchange, exchange_type='direct', durable=True)
        exchange.declare()

        # Send the message
        message.publish(exchange, routing_key=routingKey)

        print(f" [x] Sent {msg}")

    except Exception as e:
        print(f"Failed to send message: {str(e)}")

    finally:
        if rabbit_channel:
            rabbit_channel.close()
        if rabbit_conn:
            rabbit_conn.close()

# Function to send statistics
async def sendStatistics(data):
    try:
        response = requests.post('https://statistics-jeb4.onrender.com/add-statistic', data)
        print(response.json())
    except Exception as error:
        print(f"Error sending statistics: {str(error)}")

SECRET_KEY = "SUPER_STRONG_SECRET_BY_JAN"  # This should be a complex random value
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

def create_jwt_token(user: dict):
    to_encode = user.copy()
    to_encode.update({"iat": datetime.utcnow()})
    to_encode.update({"exp": datetime.utcnow() + timedelta(minutes=1440)})
    to_encode.update({"sub": user["_id"]})  # adding the user id as 'sub' claim
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm="HS256")
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        user_id = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid authorization code.")

        user = collection.find_one({"_id": user_id})
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        return user
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Could not validate credentials.")


client = MongoClient("mongodb+srv://nikkljucevsek:OldbtLLbshDbB69v@cluster0.9uuzozi.mongodb.net/")

db = client["usersDB"]

collection = db["users"]

app = FastAPI()

origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class User(BaseModel):
    username: str
    password: str
    name: str
    surname: str
    type: str  # "user" or "admin"

class LoginData(BaseModel):
    username: str
    password: str

class UserWithID(User):
    id: str

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

@app.post("/users/", response_model=User)
async def create_user(user: User):
    correlationId = str(uuid.uuid4())
    logMessageToRabbitMQ(correlationId, "Received a request to create a user", "INFO", "/users/", "user-service")
    await sendStatistics({
        'service': 'user-service',
        'endpoint': '/users/',
        'method': 'POST',
        'timestamp': datetime.now().isoformat()
    })
    
    existing_user = collection.find_one({"username": user.username})
    if existing_user:
        raise HTTPException(status_code=400, detail="User with this username already exists")

    user_id = str(uuid.uuid4())
    user_data = user.dict(by_alias=True)
    user_data["_id"] = user_id
    user_data["password"] = pwd_context.hash(user_data["password"])

    collection.insert_one(user_data)
    
    return user_data

@app.get("/users/", response_model=List[UserWithID])
async def get_users():
    correlationId = str(uuid.uuid4())
    logMessageToRabbitMQ(correlationId, "Received a request to get users", "INFO", "/users/", "user-service")
    await sendStatistics({
        'service': 'user-service',
        'endpoint': '/users/',
        'method': 'GET',
        'timestamp': datetime.now().isoformat()
    })
    users = list(collection.find())
    users_with_id = [{"id": user.pop("_id"), **user} for user in users]
    return users_with_id

@app.get("/users/{user_id}", response_model=UserWithID)
async def get_user_by_userid(user_id: str):
    correlationId = str(uuid.uuid4())
    logMessageToRabbitMQ(correlationId, "Received a request to get user by id", "INFO", f"/users/{user_id}", "user-service")
    await sendStatistics({
        'service': 'user-service',
        'endpoint': f"/users/{user_id}",
        'method': 'GET',
        'timestamp': datetime.now().isoformat()
    })

    user = collection.find_one({"_id": user_id})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return {"id": user.pop("_id"), **user}

@app.get("/getusers/", response_model=List[UserWithID])
async def get_all_users():
    correlationId = str(uuid.uuid4())
    logMessageToRabbitMQ(correlationId, "Received a request to get all users", "INFO", "/getusers/", "user-service")
    await sendStatistics({
        'service': 'user-service',
        'endpoint': "/getusers/",
        'method': 'GET',
        'timestamp': datetime.now().isoformat()
    })

    users = list(collection.find({"type": "user"}))
    users_with_id = [{"id": user.pop("_id"), **user} for user in users]
    return users_with_id

@app.get("/getadmins/", response_model=List[UserWithID])
async def get_all_admins():
    correlationId = str(uuid.uuid4())
    logMessageToRabbitMQ(correlationId, "Received a request to get all admins", "INFO", "/getadmins/", "user-service")
    await sendStatistics({
        'service': 'user-service',
        'endpoint': "/getadmins/",
        'method': 'GET',
        'timestamp': datetime.now().isoformat()
    })
    users = list(collection.find({"type": "admin"}))
    users_with_id = [{"id": user.pop("_id"), **user} for user in users]
    return users_with_id

# Delete User endpoint
@app.delete("/users/{user_id}", response_model=str)
async def delete_user(user_id: str):
    correlationId = str(uuid.uuid4())
    logMessageToRabbitMQ(correlationId, "Received a request to delete a user", "INFO", f"/users/{user_id}", "user-service")
    await sendStatistics({
        'service': 'user-service',
        'endpoint': f"/users/{user_id}",
        'method': 'DELETE',
        'timestamp': datetime.now().isoformat()
    })
    result = collection.delete_one({"_id": user_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="User not found")
    return f"User with ID {user_id} deleted successfully"


@app.delete("/users/", response_model=str)
async def delete_all_users():
    correlationId = str(uuid.uuid4())
    logMessageToRabbitMQ(correlationId, "Received a request to delete all users", "INFO", "/users/", "user-service")
    await sendStatistics({
        'service': 'user-service',
        'endpoint': "/users/",
        'method': 'DELETE',
        'timestamp': datetime.now().isoformat()
    })
    result = collection.delete_many({})
    return f"{result.deleted_count} users deleted successfully"

@app.put("/users/{user_id}", response_model=UserWithID)
async def update_user(user_id: str, updated_user: User):
    correlationId = str(uuid.uuid4())
    logMessageToRabbitMQ(correlationId, "Received a request to update a user", "INFO", f"/users/{user_id}", "user-service")
    await sendStatistics({
        'service': 'user-service',
        'endpoint': f"/users/{user_id}",
        'method': 'PUT',
        'timestamp': datetime.now().isoformat()
    })

    existing_user = collection.find_one({"_id": user_id})
    if not existing_user:
        raise HTTPException(status_code=404, detail="User not found")

    user_data = updated_user.dict(by_alias=True)
    user_data.pop("id", None)

    result = collection.update_one({"_id": user_id}, {"$set": user_data})

    if result.modified_count > 0:
        return UserWithID(id=user_id, **user_data)

    raise HTTPException(status_code=500, detail="Failed to update user")


@app.post("/login/")
async def login_user(login_data: LoginData):  # add async here
    correlationId = str(uuid.uuid4())
    logMessageToRabbitMQ(correlationId, "Received a request to login", "INFO", "/login/", "user-service")
    await sendStatistics({  # add await here
        'service': 'user-service',
        'endpoint': "/login/",
        'method': 'POST',
        'timestamp': datetime.now().isoformat()
    })
    username = login_data.username
    password = login_data.password

    user_data = collection.find_one({"username": username})
    if not user_data or not pwd_context.verify(password, user_data["password"]):
        raise HTTPException(status_code=401, detail="Invalid username or password")

    access_token = create_jwt_token(user_data)
    return {"access_token": access_token, "token_type": "bearer", "user_type": user_data["type"], "user_id": user_data["_id"]}


# Get Current User endpoint
@app.get("/me/")
async def read_users_me():
    raise HTTPException(status_code=400, detail="Endpoint disabled")

@app.get("/", include_in_schema=False)
def redirect_to_docs():
    return Response(content="", media_type="text/html", headers={"Location": "/docs"})
