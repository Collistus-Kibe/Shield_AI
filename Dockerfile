# Stage 1: Use an official, lightweight Python image as our base.
FROM python:3.11-slim

# Stage 2: Set the working directory inside the container.
WORKDIR /app

# Stage 3: Copy the dependency list and install requirements.
# This is done first to leverage Docker's layer caching.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Stage 4: Copy the rest of our application's source code into the container.
COPY . .

# Stage 5: Define the default command to run when the container starts.
# We will run the "headless" CLI agent inside the container.
CMD ["python", "main.py"]