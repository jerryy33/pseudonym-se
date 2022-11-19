# Pseudonymisation Service

### Built with
 - [fastapi](https://fastapi.tiangolo.com/) 
 - [charm-crypto](https://github.com/JHUISI/charm)
 - [Alpine.js](https://alpinejs.dev/)
 - [redis](https://redis.io/)
 - [poetry](https://python-poetry.org/)
 - [vite](https://vitejs.dev/)
 - [Docker](https://www.docker.com/)

---

# Getting started

There are two ways to start this project:

1. Use Docker
2. Local

For both you need to clone this repo first. If you just want to test the functionalities there is a template_system.py file in the test directory where you can experiment with the system

---
## Start the project with docker
Install docker if you dont have it already.
Then open a terminal in the top level directory and type:
```
docker compose up
```

This will start the complete project locally, if you start this for the first time this might take a while.
You can now check out the components:

1. Client frontend at http://localhost:5173
2. User-Management frontend at http://localhost:5174
3. Optional: A second client will run at http://localhost:5172 to show the multi-user capabilities
---
## Start the project locally
If you want to start every component locally and dont use docker it gets a lot more complicated:

#### Requirements:
 - Python 3.7
 - Install [charm-crypto](https://github.com/JHUISI/charm) for the chosen python version
 Note that charm-crypto doesnt work with python version > 3.7 and its very difficult or impossible to install it on windows (A linux vm or wsl is probably the better way). If poetry is used later than skip this step for now
 - Node.js
 - Optional: [Poetry](https://python-poetry.org/docs/)

 The first step is to install all the required dependencies:
Either install them manually with `pip install` (an overview is given in pyproject.toml) or use poetry to install them automatically (except charm-crypto).
With poetry you can run
```
poetry install --without charm
```
 this will install all dependencies into a virtual environment.

 Now run:
 ```
poetry shell
```
to activate the virtual environment.

Now you can install [charm-crypto](https://github.com/JHUISI/charm) into the venv.
Note that if you ever delete the virtual env the charm-crypto install is also gone.
Now the backends + databases can be started.

### User-Management

Start the backend:
```
cd management/backend
uvicorn user_manager:app --reload --port 8080
```
Start the frontend:
```
cd management/frontend
npm i
npm run dev
```

### Clients

Start the backend:
```
cd clients/backend
uvicorn api:app --reload --port 9090
```
Start the frontend:
```
cd clients/frontend
npm i
npm run dev
```

### Vault

Start the api:
```
cd vault
uvicorn api:app --reload --port 8000
```

### Databases

You can start 3 redis instances via the redis-cli and assign them different ports or also docker to easily expose the required ports:

```
cd databases
docker compose up
```

This will start 3 (one for each component) redis databases on different ports.

---
