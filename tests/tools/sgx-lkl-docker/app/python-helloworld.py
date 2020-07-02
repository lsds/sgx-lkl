import os

print("Hello world!")

# Check that second disk was embedded in Docker image.
assert os.path.exists('/data/app/python-helloworld.py')
