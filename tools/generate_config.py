#!/usr/bin/env python3

import argparse
from pathlib import Path
import json
try:
    import jsonschema
except ImportError:
    jsonschema = None

THIS_DIR = Path(__file__).parent

if (THIS_DIR / 'schemas').exists():
    SCHEMAS_DIR = THIS_DIR / 'schemas'
else:
    SCHEMAS_DIR = THIS_DIR.parent / 'share' / 'schemas'

ENCLAVE_CFG_SCHEMA_PATH = SCHEMAS_DIR / 'enclave-config.schema.json'

# Validates a particular enclave_cfg_path against ENCLAVE_CFG_SCHEMA_PATH
def validate(args):
    if jsonschema is None:
        raise RuntimeError('validate requires the "jsonschema" Python package')
    schema_path = ENCLAVE_CFG_SCHEMA_PATH
    print(f'Validating {args.file}')
    with open(args.file) as f:
      cfg = json.load(f)
    with open(schema_path) as f:
      cfg_schema = json.load(f)
    jsonschema.validate(instance=cfg, schema=cfg_schema)
    print('No errors found.')

def jtype_to_ctype(st):
  # print('J2C: %s' % st)
  if 'type' in st:
    stt = st['type']
    if stt == 'boolean': return 'bool'
    elif stt == 'none': return 'null'
    elif stt == 'string': return 'char*'
    elif stt == 'array':
      item_ctype = jtype_to_ctype(st['items'])
      return item_ctype + "*"
    elif isinstance(stt, list) and 'string' in stt and 'null' in stt:
      return 'char*'
    else:
      print('unknown: %s' % st)
  elif '$ref' in st:
    rtype = st['$ref'][st['$ref'].rfind('/')+1:]
    if rtype == 'safe_number':
      return 'size_t'
    else:
      return rtype
  else:
    print('unhandled: %s' % st)
    return None

def print_type(file, typedef):
  # print('PT: %s' % typedef)
  if 'enum' in typedef:
    i = 0
    for value in typedef['enum']:
        file.write('  %s = %d, \n' % (value.upper(), i))
        i += 1
  elif 'type' in typedef and typedef['type'] == 'object':
    for name, jtype in typedef['properties'].items():
      if 'type' in jtype and jtype['type'] == 'array':
        item_ctype = jtype_to_ctype(jtype['items'])
        file.write('  size_t num_%s;\n' % (name))
        file.write('  %s* %s;\n' % (item_ctype, name))
      else:
        ctype = jtype_to_ctype(jtype)
        if 'minLength' in jtype and 'maxLength' in jtype and jtype['minLength'] == jtype['maxLength']:
          file.write('  %s %s[%s];\n' % (ctype, name, jtype['maxLength']+1))
        else:
          file.write('  %s %s;\n' % (ctype, name))
  elif 'type' in typedef and typedef['type'] == 'array':
    for name, jtype in typedef['items'].items():
      ctype = jtype_to_ctype(jtype)
      file.write('  %s %s;\n' % (ctype, name))
  elif isinstance(typedef, dict): # top-level
    for name, jtype in typedef.items():
      ctype = jtype_to_ctype(jtype)
      file.write('  %s %s;\n' % (ctype, name))
  else:
    file.write('unhandled: %s' % typedef)

def generate_header(schema_file_name, root, args):
  with open(args.header, "w") as header:
    header.write('#ifndef SGXLKL_ENCLAVE_CONFIG_H\n');
    header.write('#define SGXLKL_ENCLAVE_CONFIG_H\n');

    header.write('\n/* Automatically generated from %s; do not modify. */\n\n' % schema_file_name);

    header.write('#include <inttypes.h>\n');
    header.write('#include <stdbool.h>\n');
    header.write('#include <elf.h>\n');
    header.write('\n');

    for typename, typedef in root['definitions'].items():
      if (typename.startswith('sgxlkl_')):
        ttype = 'enum' if 'enum' in typedef else 'struct'
        header.write('typedef %s %s {\n' % (ttype, typename[:-2]))
        print_type(header, typedef)
        header.write('} %s;\n\n' % typename)

    header.write('\n#endif /* SGXLKL_ENCLAVE_CONFIG_H */');

def generate_source(schema_file_name, root, args):
  with open(args.source, "w") as source:
    source.write('\n/* Automatically generated from %s; do not modify. */\n\n' % schema_file_name);

    source.write('#include "%s"\n' % args.header);

def generate(args):
  schema_file_name = ENCLAVE_CFG_SCHEMA_PATH
  with open(schema_file_name, "r") as schema_file:
    root = json.load(schema_file)

  generate_header(schema_file_name, root, args)
  generate_source(schema_file_name, root, args)

def main():
    parser = argparse.ArgumentParser(description='Generator for SGX-LKL configuration sources')
    parser.set_defaults(func=lambda _: parser.print_help())
    subparsers = parser.add_subparsers()

    parser_validate = subparsers.add_parser('validate', help='validate an enclave config file against the schema')
    parser_validate.add_argument(
        'file', type=Path,
        help='Path to enclave config file to validate',
        default=ENCLAVE_CFG_SCHEMA_PATH)
    parser_validate.set_defaults(func=validate)

    parser_generate = subparsers.add_parser('generate', help='generate enclave config sources')
    parser_generate.add_argument(
        '--header', type=Path,
        help='Header file to generate',
        default='sgxlkl_config_gen.h')
    parser_generate.add_argument(
        '--source', type=Path,
        help='Source file to generate',
        default='sgxlkl_config_gen.c')
    parser_generate.set_defaults(func=generate)

    args = parser.parse_args()
    args.func(args)


if __name__ == '__main__':
    main()