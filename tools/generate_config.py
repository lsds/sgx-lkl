#!/usr/bin/env python3

import argparse
from pathlib import Path
import json
import os

from collections import OrderedDict

THIS_DIR = Path(__file__).parent

if (THIS_DIR / 'schemas').exists():
    SCHEMAS_DIR = THIS_DIR / 'schemas'
else:
    SCHEMAS_DIR = THIS_DIR.parent / 'share' / 'schemas'

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
    if jtt == 'array' or (isinstance(jtt, list) and 'array' in jtt and 'null' in jtt):
      items = jtype['items']
      item_type = pre_type(items)
      if 'maxLength' in jtype:
        return item_type
      else:
        return item_type + '*'
    elif jtt == 'boolean':
      return 'bool'
    elif jtt == 'none':
      return 'null'
    elif jtt == 'string' or (isinstance(jtt, list) and 'string' in jtt and 'null' in jtt):
      return 'char' if 'maxLength' in jtype else 'char*'
    else:
        raise Exception('unhandled json type: %s' % jtype)
  elif '$ref' in jtype:
    rtype = jtype['$ref'][jtype['$ref'].rfind('/')+1:]
    if rtype.startswith('safe_'):
      return rtype[5:]
    elif rtype == 'hex_string':
      return 'uint8_t*'
    else:
      return rtype
  else:
    raise Exception('unknown json type: %s' % jtype)
    return jtype

def need_size_var(jtype):
  if 'type' in jtype:
    jtt = jtype['type']
    return (jtt == 'array' and 'maxLength' not in jtype) or (isinstance(jtt, list) and 'array' in jtt and 'null' in jtt)
  else:
    return '$ref' in jtype and jtype['$ref'] == '#/definitions/hex_string'

num_settings = 0

def generate_header(schema_file_name, root, args):
  global num_settings

  with open(str(args.header), "w") as header:
    h = os.path.basename(schema_file_name).upper().replace('.', '_').replace('-', '_')
    header.write('#ifndef _%s_H_\n' % h);
    header.write('#define _%s_H_\n'% h);

    header.write('\n/* Automatically generated from %s; do not modify. */\n\n' % schema_file_name);

    header.write('#include <inttypes.h>\n');
    header.write('#include <stdbool.h>\n');
    header.write('#include <stddef.h>\n');
    header.write('#include <elf.h>\n\n');

    top = root['$ref'].rsplit('/')[-1]

    header.write('#define %s_VERSION 1UL\n\n' % top.upper());

    num_settings = 0
    for typename, typedef in root['definitions'].items():
      if (typename.startswith('sgxlkl_')):
        if 'enum' in typedef:
          names = typedef['c_enum'] if 'c_enum' in typedef else typedef['enum']
          header.write('typedef enum\n{\n')
          i = 0
          num_vals = len(names)
          for value in names:
            header.write('    %s = %d' % (value.upper(), i))
            if i < num_vals - 1:
              header.write(',')
            if 'description' in typedef:
              header.write(' /* %s */' % typedef['description'])
            header.write('\n')
            i += 1
          header.write('} %s;\n\n' % typename)

          if 'c_enum' in typedef:
            header.write('const char* %s_to_string(%s e);\n' % (typename, typename))
            header.write('%s string_to_%s(const char *e);\n\n' % (typename, typename))
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
          header.write('} %s;\n\n' % typename)

    header.write('extern const %s %s_default;\n\n' % (top, top[:-2]));

    header.write(
      "typedef struct {\n"
      "    char* scope;\n"
      "    char* type;\n"
      "    char* description;\n"
      "    char* default_value;\n"
      "    char* override_var;\n"
      "} %s_setting_t;\n\n" % top[:-2]);

    header.write("extern const %s_setting_t %s_settings[%d];\n\n" % (top[:-2], top[:-2], num_settings));

    header.write('#endif /* _%s_H_ */' % h);

source_includes = """
#ifdef SGXLKL_ENCLAVE
#include <enclave/enclave_util.h>
#include <shared/oe_compat.h>
#define FAIL sgxlkl_fail
#else
#include <host/sgxlkl_util.h>
#include <string.h>
#define FAIL sgxlkl_host_fail
#endif
"""

def generate_source(schema_file_name, root, args):
  with open(str(args.source), "w") as source:
    source.write('/* Automatically generated from %s; do not modify. */\n' % schema_file_name);

    source.write(source_includes)
    source.write('\n')

    source.write('#include "%s"\n\n' % args.header)

    top = root['$ref'].rsplit('/')[-1]

    # enum conversions
    for typename, typedef in root['definitions'].items():
      if 'enum' in typedef:
        if 'c_enum' in typedef:
          names = typedef['enum']
          c_names = typedef['c_enum']
          if len(names) != len(c_names):
            raise Exception("ERROR: length of c_enum does not match enum in %s" % typename)
          source.write('const char* %s_to_string(%s e)\n{\n' % (typename, typename))
          source.write('  switch(e) {\n')
          for i in range(len(names)):
            name = names[i]
            c_name = c_names[i]
            source.write('    case %s: return "%s";\n' % (c_name, name))
          source.write('    default: return ""; /* Unreachable */\n')
          source.write('  }\n')
          source.write('}\n\n')
          source.write('%s string_to_%s(const char *e)\n{\n' % (typename, typename))
          for i in range(len(names)):
            name = names[i]
            c_name = c_names[i]
            source.write('  if (strcmp(e, "%s") == 0) return %s;\n' % (name, c_name))
          source.write('  FAIL("unknown enum value \'%s\'\\n", e);\n')
          source.write('  return %s;\n\n' % (c_names[0]))
          source.write('}\n\n')


    # default config
    source.write('const %s %s_default = {\n' % (top, top[:-2]))
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
                  t = '{'
                  for i in dflt:
                    if type(i) is OrderedDict:
                      t += '{'
                      for k, v in i.items():
                        t += '.' + str(k) + '="' + v + '"'
                      t += '},'
                  t += '}'
                  source.write('%s.%s = %s,\n' % (indent, name, t))
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
            if 'default' not in jtype:
              raise Exception("ERROR: no default provided for %s" % sname)
            dflt = jtype['default']
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
              if dflt is None or dflt == [] or dflt == '':
                dflt = 'NULL'
              source.write('%s.%s=%s,\n' % (indent, name, dflt))
          scope = scope[:-1]
      scope = scope[:-1]
    initialize(scope, top)
    source.write('};\n\n')

    source.write('// clang-format off\n')
    source.write('const %s_setting_t %s_settings[%d] = {\n' % (top[:-2], top[:-2], num_settings))
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
            if dflt == [] or dflt == None:
                dflt = 'NULL'
            if ctype == 'bool':
              dflt = "true" if dflt else "false"
            override_var = 'NULL'
            if 'overridable' in jtype:
                override_var = '"' + jtype['overridable'] + '"'
            source.write('    {"%s", "%s", "%s", "%s", %s},\n' % (sname, ctype, desc, dflt, override_var))
          scope = scope[:-1]
      scope = scope[:-1]
    describe(scope, top)

    source.write('};\n')
    source.write('// clang-format on\n')

def generate(args):
  with open(args.schema_file, "r") as schema_file:
    root = json.load(schema_file, object_pairs_hook=OrderedDict)

  generate_header(args.schema_file, root, args)
  generate_source(args.schema_file, root, args)

def main():
    parser = argparse.ArgumentParser(description='Generator for SGX-LKL configuration sources')
    parser.set_defaults(func=lambda _: parser.print_help())

    parser.add_argument(
        'schema_file', type=Path,
        help='Schema file path',
        metavar='PATH')
    parser.add_argument(
        '--header', type=Path,
        help='Header file to generate',
        default='sgxlkl_config_gen.h')
    parser.add_argument(
        '--source', type=Path,
        help='Source file to generate',
        default='sgxlkl_config_gen.c')
    parser.set_defaults(func=generate)

    args = parser.parse_args()
    args.func(args)


if __name__ == '__main__':
    main()