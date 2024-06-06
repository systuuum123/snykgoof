import os
from datetime import datetime

# Create a timestamp
timestamp = datetime.now().strftime('%Y%m%d%H%M%S')

# Define the directory and filename
directory = '.github/data/'
filename = f'{timestamp}.txt'

# Ensure the directory exists
os.makedirs(directory, exist_ok=True)

# Define the content to be saved
content = f'test123 {timestamp}'

# Define the full path
file_path = os.path.join(directory, filename)

# Save the content to the file
with open(file_path, 'w') as file:
    file.write(content)

print(f"File saved as {file_path}")
