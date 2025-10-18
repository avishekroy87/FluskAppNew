# Use an official Python runtime as a parent image
FROM python:3.9-slim

# Set the working directory in the container
WORKDIR /

# Copy the requirements file into the container at /app
COPY requirements.txt .

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application's code into the container at /app
COPY . .

# Expose the port the app runs on
EXPOSE 8000

# Define environment variables (optional)
# ENV FLASK_APP=app.py

# Run the application using Gunicorn (a production-ready server)
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "app:app"]