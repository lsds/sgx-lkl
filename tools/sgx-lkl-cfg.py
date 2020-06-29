import pkg_resources
import argparse
from pathlib import Path
import json

THIS_DIR = Path(__file__).parent

if (THIS_DIR / 'schemas').exists():
    SCHEMAS_DIR = THIS_DIR / 'schemas'
else:
    SCHEMAS_DIR = THIS_DIR.parent / 'share' / 'schemas'

APP_CFG_SCHEMA_PATH = SCHEMAS_DIR / 'app-config.schema.json'
HOST_CFG_SCHEMA_PATH = SCHEMAS_DIR / 'host-config.schema.json'

INDENT = 2

def main():
    parser = argparse.ArgumentParser(description='Tool that helps creating SGX-LKL configuration files')
    parser.set_defaults(func=lambda _: parser.print_help())
    subparsers = parser.add_subparsers()

    parser_create = subparsers.add_parser(
        'create', help='Create host and app config files')
    parser_create.add_argument(
        '--disk', metavar='PATH', dest='img_paths', type=Path, required=True, nargs='+',
        help='Paths of disk images to be included (first path must be root disk)')
    parser_create.add_argument(
        '--host-cfg', metavar='PATH', type=Path, default=Path('host-config.json'),
        help='Path to host config file to be created')
    parser_create.add_argument(
        '--app-cfg', metavar='PATH', type=Path, default=Path('app-config.json'),
        help='Path to app config file to be created')
    parser_create.add_argument(
        '--complete', action='store_true',
        help='Whether to add optional fields (using default values)')
    parser_create.set_defaults(func=create)

    parser_make_complete = subparsers.add_parser(
        'make-complete', help='Add optional fields with default values')
    parser_make_complete.add_argument(
        '--host-cfg', metavar='PATH', type=Path,
        help='Path to host config file to be modified')
    parser_make_complete.add_argument(
        '--app-cfg', metavar='PATH', type=Path,
        help='Path to app config file to be modified')
    parser_make_complete.add_argument(
        '--dry-run', action='store_true',
        help='Print what would happen without doing it')
    parser_make_complete.set_defaults(func=make_complete)

    parser_validate = subparsers.add_parser(
        'validate', help='Validate host and app config files')
    parser_validate.add_argument(
        '--app-cfg', metavar='PATH', type=Path,
        help='Path to app config file to validate')
    parser_validate.add_argument(
        '--host-cfg', metavar='PATH', type=Path,
        help='Path to host config file to validate')
    parser_validate.set_defaults(func=validate)

    parser_finalize = subparsers.add_parser(
        'finalize', help='Finalize an app config file for use with attestation')
    parser_finalize.add_argument(
        '--app-cfg', metavar='PATH', type=Path, required=True,
        help='Path to input app config file')
    parser_finalize.add_argument(
        '--app-cfg-final', metavar='PATH', type=Path, required=True,
        help='Path to output app config file')
    parser_finalize.set_defaults(func=finalize)

    parser_dockerize = subparsers.add_parser(
        'dockerize', help='(Internal) Prepare (host) configurations for use in Docker images')
    parser_dockerize.add_argument(
        '--host-cfg', metavar='PATH', type=Path, required=True,
        help='Path to input host config file')
    parser_dockerize.add_argument(
        '--host-cfg-docker', metavar='PATH', type=Path, required=True,
        help='Path to patched host config file')
    parser_dockerize.add_argument(
        '--print-disk-paths', action='store_true',
        help='Prints the disk paths in the form <path>:<patched>, separated by newlines')
    
    parser_dockerize.set_defaults(func=dockerize)

    args = parser.parse_args()
    args.func(args)

def create(args):
    host_cfg = {
    }
    app_cfg = {
        'run': 'PATH/TO/EXECUTABLE',
        'args': [],
        'environment': {},
        'disk_config': []
    }
    for i, img_path in enumerate(args.img_paths):
        img_folder = img_path.parent
        img_filename = img_path.name
        docker_meta_path = img_folder / (img_filename + '.docker')
        docker_entrypoint_path = img_folder / (img_filename + '.docker_entrypoint')
        img_roothash_path = img_folder / (img_filename + '.roothash')
        img_roothash_offset_path = img_folder / (img_filename + '.hashoffset')
        
        # Extend host config
        if i == 0:
            host_cfg['hd'] = str(img_path.resolve())
        else:
            hds = host_cfg.get('hds', '')
            if hds:
                hds += ','
            hds += f'{img_path.resolve()}:/data_{i}:0'
            host_cfg['hds'] = hds

        # Extend app config
        mnt_point = '/' if i == 0 else f'/data_{i}'
        disk_cfg = {
            'disk': mnt_point,
            'readonly': img_roothash_path.exists()
        }
        if img_roothash_path.exists():
            with open(img_roothash_path) as f:
                disk_cfg['roothash'] = f.read().strip()
            with open(img_roothash_offset_path) as f:
                disk_cfg['roothash_offset'] = int(f.read().strip())
        app_cfg['disk_config'].append(disk_cfg)

        if i == 0 and docker_meta_path.exists():
            with open(docker_meta_path) as f:
                docker_meta = json.load(f)
            if docker_entrypoint_path.exists():
                with open(docker_entrypoint_path) as f:
                    docker_entrypoint_abs = f.read().strip()
            else:
                docker_entrypoint_abs = None
            docker_cfg = docker_meta[0]['Config']
            docker_entrypoint = docker_cfg['Entrypoint'] or [] # type: List[str]
            docker_cmd = docker_cfg['Cmd'] or [] # type: List[str]
            docker_wd = docker_cfg['WorkingDir'] # type: str
            docker_env = docker_cfg['Env'] # type: List[str]

            if docker_entrypoint:
                app_cfg['run'] = docker_entrypoint.pop(0)
            elif docker_cmd:
                app_cfg['run'] = docker_cmd.pop(0)

            if docker_entrypoint_abs:
                app_cfg['run'] = docker_entrypoint_abs

            app_cfg['args'] = docker_entrypoint + docker_cmd

            if docker_wd:
                app_cfg['cwd'] = docker_wd
            
            for entry in docker_env:
                name, val = entry.split('=', maxsplit=1)
                app_cfg['environment'][name] = val

    if args.complete:
        with open(APP_CFG_SCHEMA_PATH) as f:
            app_cfg_schema = json.load(f)
        with open(HOST_CFG_SCHEMA_PATH) as f:
            host_cfg_schema = json.load(f)
        _make_complete(app_cfg, app_cfg_schema, quiet=True)
        _make_complete(host_cfg, host_cfg_schema, quiet=True)

    with open(args.host_cfg, 'w') as f:
        json.dump(host_cfg, f, indent=INDENT)
    
    with open(args.app_cfg, 'w') as f:
        json.dump(app_cfg, f, indent=INDENT)

    print('Host and application configuration files successfully created.')
    print()
    print('You should now do the following:')
    print('- Review the generated files.')
    if len(args.img_paths) > 1:
        print('- Change the default mount paths for the extra disks from /data_<i> if needed.')
    print('- Change the "run" and "args" fields in the app configuration if needed.')
    if app_cfg['run'] in ['/bin/sh', '/bin/bash']:
        print(f'  Note: {app_cfg["run"]} was detected as Docker image entrypoint.')
        print( '        This entrypoint is the default of many Docker images.')
        print( '        It is also implicitly used in the \'shell\' form of CMD or ENTRYPOINT.')
        print( '        Please modify "run" in the app configuration if needed.')
    print('- Change any additional fields if needed (see documentation).')

def make_complete(args):
    items = [
        (args.app_cfg, APP_CFG_SCHEMA_PATH),
        (args.host_cfg, HOST_CFG_SCHEMA_PATH)
    ]
    for cfg_path, schema_path in items:
        if not cfg_path:
            continue
        dry_run_text = ' (dry run)' if args.dry_run else ''
        print(f'Adding optional fields in {cfg_path}{dry_run_text}')
        print()
        with open(cfg_path) as f:
            cfg = json.load(f, object_pairs_hook=dict_raise_on_duplicates)
        with open(schema_path) as f:
            cfg_schema = json.load(f)

        modified = _make_complete(cfg, cfg_schema)
        if not modified:
            print('No fields were missing.')

        if not args.dry_run:
            with open(cfg_path, 'w') as f:
                json.dump(cfg, f, indent=INDENT)

def _make_complete(obj, obj_schema, obj_key_path='$', quiet=False):
    modified = False
    for key, field_schema in obj_schema['properties'].items():
        field_key_path = f'{obj_key_path}.{key}'
        if 'default' in field_schema:
            default_value = field_schema['default']
            if key not in obj:
                if not quiet:
                    print(f'Added {field_key_path}: {json.dumps(default_value)}')
                obj[key] = default_value
                modified = True
        item_schema = field_schema.get('items')
        if item_schema and 'properties' in item_schema:
            for i, item_obj in enumerate(obj[key]):
                item_key_path = f'{field_key_path}[{i}]'
                modified |= _make_complete(item_obj, item_schema, item_key_path)
    return modified

def dict_raise_on_duplicates(ordered_pairs):
    # https://stackoverflow.com/a/14902564
    d = {}
    for k, v in ordered_pairs:
        if k in d:
           raise ValueError("duplicate key: %r" % (k,))
        else:
           d[k] = v
    return d

def validate(args):
    _validate(args.app_cfg, args.host_cfg)

def _validate(app_cfg_path=None, host_cfg_path=None):
    try:
        pkg_resources.require('jsonschema>=3')
        import jsonschema
    except pkg_resources.DistributionNotFound:
        raise RuntimeError('validate requires the "jsonschema" Python package')
    except pkg_resources.VersionConflict:
        raise RuntimeError('validate requires the "jsonschema" Python package '
                           'but your version is too old (<3)')

    items = [
        (app_cfg_path, APP_CFG_SCHEMA_PATH),
        (host_cfg_path, HOST_CFG_SCHEMA_PATH)
    ]
    for cfg_path, schema_path in items:
        if not cfg_path:
            continue
        print(f'Validating {cfg_path}')
        with open(cfg_path) as f:
            cfg = json.load(f, object_pairs_hook=dict_raise_on_duplicates)
        with open(schema_path) as f:
            cfg_schema = json.load(f)
        jsonschema.validate(instance=cfg, schema=cfg_schema)
    print('No errors found.')

def finalize(args):
    _validate(args.app_cfg)
    with open(args.app_cfg) as f:
        cfg = json.load(f)
    with open(args.app_cfg_final, 'w') as f:
        json.dump(cfg, f, separators=(',', ':'), sort_keys=True)
    print('Finalized app configuration successfully created.')

def dockerize(args):
    patched_img_path_tmpl = 'disk_{i}.img'

    with open(args.host_cfg) as f:
        cfg = json.load(f)
    
    root_img_path = cfg['hd']
    patched_root_img_path = patched_img_path_tmpl.format(i=0)
    cfg['hd'] = patched_root_img_path
    if args.print_disk_paths:
        print(f'{root_img_path}:{patched_root_img_path}')

    hds = ''
    if cfg.get('hds'):
        for i, entry in enumerate(cfg['hds'].split(',')):
            img_path, mount_path, mode = entry.split(':')
            patched_img_path = patched_img_path_tmpl.format(i=i + 1)
            if hds:
                hds += ','
            hds += f'{patched_img_path}:{mount_path}:{mode}'
            if args.print_disk_paths:
                print(f'{img_path}:{patched_img_path}')
    if hds:
        cfg['hds'] = hds
        
    with open(args.host_cfg_docker, 'w') as f:
        json.dump(cfg, f, indent=INDENT)
    
    if not args.print_disk_paths:
        print('Host config successfully patched.')

if __name__ == '__main__':
    main()
