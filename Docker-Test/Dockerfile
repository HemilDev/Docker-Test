# Use Python base image
FROM python

# Set the working directory inside the container
WORKDIR /app

# Copy all necessary files into the container
COPY app.py app.py

# Install necessary Python dependencies
COPY requirements.txt requirements.txt
COPY . .

# Copy and install dependencies
RUN pip install -r requirements.txt

# Expose port 5000 for Flask
EXPOSE 5000

# Command to run the Flask app
CMD ["python", "app.py"]
