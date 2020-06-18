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
        print('unhandled json type: %s' % jtype)
  elif '$ref' in jtype:
    rtype = jtype['$ref'][jtype['$ref'].rfind('/')+1:]
    if rtype.startswith('safe_'):
      return rtype[5:]
    else:
      return rtype
  else:
    print('unknown json type: %s' % jtype)
    return jtype

def need_size_var(jtype):
  return 'type' in jtype and jtype['type'] == 'array' and 'maxLength' not in jtype

num_settings = 0

def generate_header(schema_file_name, root, args):
  global num_settings

  with open(str(args.header), "w") as header:
    header.write('#ifndef SGXLKL_ENCLAVE_CONFIG_GEN_H\n');
    header.write('#define SGXLKL_ENCLAVE_CONFIG_GEN_H\n');

    header.write('\n/* Automatically generated from %s; do not modify. */\n\n' % schema_file_name);

    header.write('#include <inttypes.h>\n');
    header.write('#include <stdbool.h>\n');
    header.write('#include <stddef.h>\n');
    header.write('#include <elf.h>\n\n');

    header.write('#define SGXLKL_ENCLAVE_CONFIG_VERSION 1UL\n\n');

    num_settings = 0
    for typename, typedef in root['definitions'].items():
      if (typename.startswith('sgxlkl_')):
        if 'enum' in typedef:
          header.write('typedef enum\n{\n')
          i = 0
          num_vals = len(typedef['enum'])
          for value in typedef['enum']:
            header.write('    %s = %d' % (value.upper(), i))
            if i < num_vals - 1: header.write(',')
            if 'description' in typedef:
              header.write(' /* %s */' % typedef['description'])
            header.write('\n')
            i += 1
          header.write('} %s;\n\n' % typename)
        else:
          header.write('typedef struct %s\n{\n' % (typename[:-2]))
          for name, jtype in typedef['properties'].items():
            if name == 'format_version':
              continue
            elif (need_size_var(jtype)):
              var_name = 'num_' + name;
              if name == 'key':
                var_name = 'key_len'
              header.write('    size_t %s;\n' % var_name)
            header.write('    %s %s%s;\n' % (pre_type(jtype), name, post_type(jtype)))
            num_settings += 1
          num_settings -= 1
          header.write('} %s;\n\n' % typename)

    header.write('extern const sgxlkl_enclave_config_t sgxlkl_default_enclave_config;\n\n');

    header.write(
      "typedef struct {\n"
      "    char* scope;\n"
      "    char* type;\n"
      "    char* description;\n"
      "    char* default_value;\n"
      "    char* override_var;\n"
      "} sgxlkl_enclave_setting_t;\n\n");

    header.write("extern const sgxlkl_enclave_setting_t sgxlkl_enclave_settings[%d];\n\n" % num_settings);

    header.write('#endif /* SGXLKL_ENCLAVE_CONFIG_H */');

def generate_source(schema_file_name, root, args):
  with open(str(args.source), "w") as source:
    source.write('\n/* Automatically generated from %s; do not modify. */\n\n' % schema_file_name);

    source.write('#include "%s"\n\n' % args.header);

    source.write('const sgxlkl_enclave_config_t sgxlkl_default_enclave_config = {\n')
    scope = []
    def initialize(scope, elem):
      indent = '    ' * (len(scope) + 1)
      typedef = root['definitions'][elem]
      if 'enum' not in typedef:
        for name, jtype in typedef['properties'].items():
          if name == 'format_version':
            continue
          tname = pre_type(jtype)
          if tname.startswith('sgxlkl_'):
            if tname.endswith('*'):
              source.write('%s.%s=NULL,\n' % (indent, name))
            else:
              tdef = root['definitions'][tname]
              if 'type' in jtype and jtype['type'] == 'array':
                if 'default' in jtype:
                  dflt = jtype['default']
                  source.write('%s.%s = %s,\n' % (indent, name, dflt))
                else:
                  source.write('%s.%s = {0},\n' % (indent, name))
              elif 'enum' not in tdef:
                scope.append(name)
                source.write('%s.%s = {\n' % (indent, name))
                initialize(scope, tname)
                source.write('%s},\n' % indent)
                scope = scope[:-1]
          else:
            scope.append(name)
            sname = '.'.join(scope)
            ctype = pre_type(jtype) + post_type(jtype)
            dflt = jtype['default'] if 'default' in jtype else ''
            if dflt == '':
              raise Exception("ERROR: no default provided for %s" % sname)
            if ctype == 'bool':
              dflt = "true" if dflt else "false"
            if ctype == 'char*' or ctype.startswith('char['):
              if dflt is None or dflt == []:
                source.write('%s.%s=NULL,\n' % (indent, name))
              else:
                source.write('%s.%s="%s",\n' % (indent, name, dflt))
            else:
              if need_size_var(jtype):
                size_var_name = 'num_' + name;
                if name == 'key':
                  size_var_name = 'key_len'
                source.write('%s.%s=%s,\n' % (indent, size_var_name, 0))
              if dflt == []:
                dflt = 'NULL'
              source.write('%s.%s=%s,\n' % (indent, name, dflt))
          scope = scope[:-1]
      scope = scope[:-1]
    initialize(scope, 'sgxlkl_enclave_config_t')
    source.write('};\n\n')

    source.write('// clang-format off\n')
    source.write('const sgxlkl_enclave_setting_t sgxlkl_enclave_settings[%s] = {\n' % num_settings)
    scope = []
    def describe(scope, elem):
      typedef = root['definitions'][elem]
      if 'enum' not in typedef:
        for name, jtype in typedef['properties'].items():
          if name == 'format_version':
            continue
          tname = pre_type(jtype)
          if (tname.endswith('*')):
            tname = tname[:-1]
          if tname.startswith('sgxlkl_'):
            scope.append(name)
            describe(scope, tname)
            scope = scope[:-1]
          else:
            scope.append(name)
            sname = '.'.join(scope)
            ctype = pre_type(jtype) + post_type(jtype)
            desc = jtype['description'] if 'description' in jtype else ''
            desc = desc.replace("\"", "\\\"")
            dflt = 'NULL'
            if 'default' in jtype:
              dflt = jtype['default'];
            if dflt == []:
                dflt = 'NULL'
            if ctype == 'bool':
              dflt = "true" if dflt else "false"
            override_var = 'NULL'
            if 'overridable' in jtype:
                override_var = '"' + jtype['overridable'] + '"'
            source.write('    {"%s", "%s", "%s", "%s", %s},\n' % (sname, ctype, desc, dflt, override_var))
          scope = scope[:-1]
      scope = scope[:-1]
    describe(scope, 'sgxlkl_enclave_config_t')

    source.write('};\n')
    source.write('// clang-format on\n')

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