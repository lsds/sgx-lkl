#!/usr/bin/env python3

import argparse
from pathlib import Path
import json
try:
    import jsonschema
except ImportError:
    jsonschema = None
from collections import OrderedDict

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
    print('Validating {args.file}')
    with open(args.file) as f:
      cfg = json.load(f)
    with open(schema_path) as f:
      cfg_schema = json.load(f)
    jsonschema.validate(instance=cfg, schema=cfg_schema)
    print('No errors found.')

def post_type(jtype):
  if 'type' in jtype:
    jtt = jtype['type']
    if 'maxLength' in jtype:
      if jtt == 'string':
        return '[' + str(jtype['maxLength']+1) + ']'
      elif jtt == 'array':
        return '[' + str(jtype['maxLength']) + ']'
    return ''
  else:
    return ''

def pre_type(jtype):
  if 'type' in jtype:
    jtt = jtype['type']
    if jtt == 'array':
      items = jtype['items']
      item_type = pre_type(items)
      if 'maxLength' in jtype:
        return item_type
      else:
        return item_type + '*'
    elif jtt == 'boolean': return 'bool'
    elif jtt == 'none': return 'null'
    elif jtt == 'string' or (isinstance(jtt, list) and 'string' in jtt and 'null' in jtt):
      return 'char' if 'maxLength' in jtype else 'char*'
    else:
        print('unhandled typed: %s' % jtype)
  elif '$ref' in jtype:
    rtype = jtype['$ref'][jtype['$ref'].rfind('/')+1:]
    if rtype.startswith('safe_'):
      return rtype[5:]
    else:
      return rtype
  else:
    print('unhandled: %s' % jtype)
    return jtype

def write_member(file, name, jtype):
  # print('%s := %s' % (name, jtype))
  file.write('    %s %s%s;\n' % (pre_type(jtype), name, post_type(jtype)))

def need_size_var(jtype):
  return 'type' in jtype and jtype['type'] == 'array' and 'maxLength' not in jtype

def generate_header(schema_file_name, root, args):
  with open(str(args.header), "w") as header:
    header.write('#ifndef SGXLKL_ENCLAVE_CONFIG_GEN_H\n');
    header.write('#define SGXLKL_ENCLAVE_CONFIG_GEN_H\n');

    header.write('\n/* Automatically generated from %s; do not modify. */\n\n' % schema_file_name);

    header.write('#include <inttypes.h>\n');
    header.write('#include <stdbool.h>\n');
    header.write('#include <stddef.h>\n');
    header.write('#include <elf.h>\n\n');

    header.write('#define SGXLKL_ENCLAVE_CONFIG_VERSION 1UL\n\n');

    for typename, typedef in root['definitions'].items():
      if (typename.startswith('sgxlkl_')):
        if 'enum' in typedef:
          header.write('typedef enum\n{\n')
          i = 0
          num_vals = len(typedef['enum'])
          for value in typedef['enum']:
              header.write('    %s = %d' % (value.upper(), i))
              if i < num_vals - 1: header.write(',')
              header.write('\n')
              i += 1
          header.write('} %s;\n\n' % typename)
        else:
          # print('%s ==> %s' % (typename, typedef))
          # print(typedef['properties'])
          header.write('typedef struct %s\n{\n' % (typename[:-2]))
          for name, jtype in typedef['properties'].items():
            if name == 'format_version':
              continue
            elif (need_size_var(jtype)):
              var_name = 'num_' + name;
              if name == 'key':
                var_name = 'key_len'
              header.write('    size_t %s;\n' % var_name)
            write_member(header, name, jtype)
          header.write('} %s;\n\n' % typename)

    header.write('#endif /* SGXLKL_ENCLAVE_CONFIG_H */');

def generate_source(schema_file_name, root, args):
  with open(str(args.source), "w") as source:
    source.write('\n/* Automatically generated from %s; do not modify. */\n\n' % schema_file_name);

    source.write('#include "%s"\n' % args.header);

def generate(args):
  schema_file_name = str(ENCLAVE_CFG_SCHEMA_PATH)
  with open(schema_file_name, "r") as schema_file:
    root = json.load(schema_file, object_pairs_hook=OrderedDict)

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