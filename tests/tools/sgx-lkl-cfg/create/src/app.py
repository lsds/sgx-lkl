import os
import sys

# Check metadata originally coming from the Dockerfile.
cwd = os.getcwd()
assert cwd == '/src', cwd

name = sys.argv[1]
assert name == 'John', name

# TODO uncomment once https://github.com/lsds/sgx-lkl/issues/207 is fixed
#greeting = os.environ["GREETING"]
#assert greeting == 'Hello', greeting
greeting = 'Hello'

print(f'{greeting} {name}!')

# Check naming of extra disk.
assert os.path.exists('/data_1')
