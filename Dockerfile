
FROM python:3.11-slim

# Set the working directory inside the container
# All commands from here on run inside /app
WORKDIR /app

# Copy requirements.txt from laptop to container
COPY requirements.txt .

# Install dependencies inside the container
RUN pip install -r requirements.txt

# Copy all files into the container
COPY . .

# Container listens on port 5000
EXPOSE 5000

# Command to run when the container starts
CMD ["python", "app.py"]