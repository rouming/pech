#!/usr/bin/env python3

"""Fio runner

Requires:
  fio >= 3.13
  docopt (python3-docopt package)

Usage:
  fio-runner.py rbd --dir=<path> --name=<name> --fio-servers=<server>... --image=<image>  [--fio-opt=<key=value>...]
  fio-runner.py rbd-blkdev --dir=<path> --name=<name> --fio-servers=<server>... --dev=<dev> [--fio-opt=<key=value>...]
  fio-runner.py cephfs --dir=<path> --name=<name> --fio-servers=<server>... --file=<file> [--fio-opt=<key=value>...]
  fio-runner.py show-results --dir=<path> --column=<name>... [--order=<str>]  [--include=<name>...] [--exclude=<name>...] [--csv] [--no-format]

Options:
  -h --help              Show this screen.
  --order <str>          Order rows, comma separated string
  --fio-opt <key=valey>  FIO option.  Check FIO HOWTO.
  --include <name>       Include only this particular name. Regexp is supported.
  --exclude <name>       Exclude this particular name, have higher priority than include. Regexp is supported.
  --csv                  Shows results in CSV format.
  --no-format            Do not format values

  --image=<image>
  --dev=<dev>
  --file=<file>          All have same meaning and denote image, device or file name
                         which needs to be opened. Supports range '[N, M]', where N
                         and M are unsigned integers, e.g. /mnt/cephfs/file[1-16] .
                         Supports %FIO_SERVER_ID and %FIO_SERVER_NAME patterns, which
                         are replaced with server sequence order number or server
                         name, which helps to run loads on different images, e.g.
                         /mnt/cephfs/file-%FIO_SERVER_ID-[1-16] option tells script
                         to run a load on the first server with image range
                         /mnt/cephfs/file-1-[1-16] and with the following image on
                         the second server /mnt/cephfs/file-2-[1-16].

Testing examples:
  # RBD userspace client
  fio-runner.py rbd --dir=./RESULTS --name=rbd/N/M/4k --fio-servers=ses-client-[1-8] --image=fio_test[1-16] --fio-opt="bs=4k"

  # RBD block device client
  fio-runner.py rbd-blkdev --dir=./RESULTS --name=rbd-blkdev/N/M/8k --fio-servers=ses-client-[1-8] --dev=/dev/rbd[1-16] --fio-opt="bs=8k"

  # CephFS client
  fio-runner.py cephfs --dir=./RESULTS --name=cephfs/N/M/8k --fio-servers=ses-client-[1-8] --file=/mnt/cephfs/file[1-16] --fio-opt="bs=8k"


Getting results example:
  # write iops
  fio-runner.py show-results --dir=./RESULTS --column=write/iops

  # read and write bandwidth with a special order
  fio-runner.py show-results --dir=./RESULTS --order="4k,8k,16k,32k,64k,128k,256k,512k,1m" --column=write/bw --column=write/iops

  # write latency, stddev and mean
  fio-runner.py show-results --dir=./RESULTS --column=write/lat_ns/stddev --column=write/lat_ns/mean
"""
from docopt import docopt, DocoptExit
import configparser
import subprocess
import tempfile
import math
import json
import os
import re
import io
import sys

FIO_RBD_PATTERN = """
[global]
ioengine=rbd
clientname=admin
pool=rbd

rw=randwrite
size=256m

### Careful, verify does not work with time_based
#do_verify=1
#verify=md5

time_based=1
runtime=10
ramp_time=10

iodepth=32
numjobs=1

"""

FIO_RBD_BLKDEV_PATTERN = """
[global]
fadvise_hint=0
direct=1
#ioengine=io_uring
ioengine=libaio

#iodepth_batch_submit=128
#iodepth_batch_complete=128

rw=randwrite
size=256m

### Careful, verify does not work with time_based
#do_verify=1
#verify=md5

time_based=1
runtime=10
ramp_time=10

iodepth=32
numjobs=1

"""

FIO_CEPHFS_PATTERN = """
[global]
fadvise_hint=0
direct=1
#ioengine=io_uring
ioengine=libaio

#iodepth_batch_submit=128
#iodepth_batch_complete=128

rw=randwrite
size=256m

### Careful, verify does not work with time_based
#do_verify=1
#verify=md5

time_based=1
runtime=10
ramp_time=10

iodepth=32
numjobs=1

"""

FIO_JOB_SECTION = """
[job%d]
%s=%s
"""

modes = {
    'rbd' : {
        'fio_pattern'   : FIO_RBD_PATTERN,
        'filename_key'  : '--image',
        'filename_name' : 'rbdname',
    },
    'rbd-blkdev' : {
        'fio_pattern'   : FIO_RBD_BLKDEV_PATTERN,
        'filename_key'  : '--dev',
        'filename_name' : 'filename',
    },
    'cephfs' : {
        'fio_pattern'   : FIO_CEPHFS_PATTERN,
        'filename_key'  : '--file',
        'filename_name' : 'filename',
    }
}

def create_fio_job_file(path, fio_job):
    dir = os.path.dirname(path)
    if not os.path.exists(dir):
        os.makedirs(dir)
    with open(path ,"w+") as f:
        f.write(fio_job)

def run_fio(ipath, servers, fio_job, cmd):
    srv_id = 1
    for srv in servers:
        srv_ipath = ipath
        srv_fio_job = fio_job
        srv_fio_job = srv_fio_job.replace('%FIO_SERVER_ID', str(srv_id))
        srv_fio_job = srv_fio_job.replace('%FIO_SERVER_NAME', srv)
        srv_id += 1
        # Replace server name for ipath
        srv_ipath %= srv
        create_fio_job_file(srv_ipath, srv_fio_job)
        cmd.append("--client=%s" % srv)
        cmd.append("%s" % srv_ipath)
    #cmd.insert(0, 'echo')
    subprocess.call(cmd)

def base26_to_str(val):
    base = 26
    val -= ord('a')
    str = ""
    while True:
        num = val % base
        str = chr(num + ord('a')) + str
        val = int(val / base)
        if val == 0:
            break
        val -= 1

    return str

def expand_names(names_):
    names = []
    N = 1

    for name in names_:
        m = re.search('(\[(\d+)-(\d+)\])', name)
        if m:
            N = int(m.group(2))
            M = int(m.group(3))
            for i in range(N, M + 1):
                # Substitute [\d+-\d+\] with a number
                name = "%s%d%s" % (name[:m.span(1)[0]], i, name[m.span(1)[1]:])
                names.append(name)
        else:
            names.append(name)

    return (names, N)

def start_load(mode, args):
    odir = args['--dir']
    name = args['--name']
    filename = args[mode['filename_key']]
    servers = args['--fio-servers']

    fio_job = mode['fio_pattern']
    if args['--fio-opt']:
        fio_job = replace_fio_opts(fio_job, args['--fio-opt'])

    (servers, _) = expand_names(servers)
    (filenames, start) = expand_names([filename])

    odir = os.path.join(odir, name)
    if not os.path.exists(odir):
        os.makedirs(odir)

    for i in range(0, len(filenames)):
        fio_job += FIO_JOB_SECTION % (i+1, mode['filename_name'], filenames[i])

    opath = odir + '/fio-results.json'
    ipath = odir + '/JOBS/%s/fio.ini' # Where '%s' is fio-server-name path
    cmd = ['fio', '--output-format=json', '--output=%s' % opath]

    run_fio(ipath, servers, fio_job, cmd)

def get_json_element(json_path, json_node):
    results = []
    node = json_node

    for name in json_path.split('/'):
        key_val = name.split('=')
        if len(key_val) > 2:
            raise Exception("Incorrect path syntax: %s" % name)
        elif len(key_val) == 1:
            try:
                node = node[key_val[0]]
            except:
                return None
        else:
            if type(node) != list:
                raise Exception("Path element '%s' does not correspond "
                                "to node type, which must be a list" % (name))
            key = key_val[0]
            val = key_val[1]
            found = False
            for element in node:
                if key in element and element[key] == val:
                    node = element
                    found = True
                    break
            if not found:
                return None

    return node

def load_json(path):
    with open(path, 'r') as json_file:
        try:
            file_pos = 0
            # Find first '{' json beggining and start parsing
            for line in json_file:
                if re.match('\{', line):
                    break
                file_pos += len(line)
            json_file.seek(file_pos)
            return json.load(json_file)
        except:
            return None

def choose_format(args, row_names, results):
    fstr = ""
    if args['--csv']:
        # CSV
        fstr = "{}"
        for row_name in row_names:
            fstr += ",{}"
    else:
        # For humans
        fstr = "{:>5}"
        for row_name in row_names:
            # Get max size of element inside a column
            max_sz = max([len(str(results[num].get(row_name, ""))) for num in results.keys()] \
                         + [len(row_name)])
            fstr += "  {:>%d}" % max_sz

    return fstr

def choose_format(args, cells, min_len):
    fstr = ""
    if args['--csv']:
        # CSV
        fstr = "{}"
    else:
        # For humans

        # Get max len
        max_len = max([len(el) for el in cells])
        max_len = max(min_len, max_len)
        fstr = "  {:>%d}" % max_len

    return fstr

def intersection(lst1, lst2):
    lst3 = [value for value in lst1 if value in lst2]
    return lst3

def sort_row_names(row_names, row_order):
    if not row_order:
        return row_names

    row_order = row_order.split(',')
    sorted_names = intersection(row_order, row_names)
    sorted_names += list(set(row_names) - set(row_order))

    return sorted_names

def format_bw(bw_bytes):
    if bw_bytes == 0:
        return "0B/s"
    name = ("B/s", "KB/s", "MB/s", "GB/s", "TB/s",
            "PB/s", "EB/s", "ZB/s", "YB/s")
    i = int(math.floor(math.log(bw_bytes, 1024)))
    p = math.pow(1024, i)
    s = round(bw_bytes / p, 2)
    return "%.2f %s" % (s, name[i])

def format_iops(iops):
    if iops == 0:
        return "0"
    name = (" ", "K", "M", "G")
    i = int(math.floor(math.log(iops, 1000)))
    p = math.pow(1000, i)
    s = round(iops / p, 2)
    return "%.2f %s" % (s, name[i])

def format_latency(lat_ns):
    if lat_ns == 0:
        return "0"
    name = ("ns", "us", "ms", "s ")
    i = int(math.floor(math.log(lat_ns, 1000)))
    p = math.pow(1000, i)
    s = round(lat_ns / p, 2)
    return "%.2f %s" % (s, name[i])

def format_value(args, val, col_name):
    no_format = args['--no-format']

    if re.search("iops", col_name) and not no_format:
        val = format_iops(val)
    elif re.search("bw_bytes", col_name) and not no_format:
        val = format_bw(val)
    elif re.search("bw", col_name) and not no_format:
        val = format_bw(val * 1024)
    elif re.search("lat_ns", col_name) and not no_format:
        val = format_latency(val)
    elif type(val) == float:
        # .3f should be enough
        val = "{:.3f}".format(val)
    else:
        val = str(val)

    return val

def show_table(args, title, results):
    row_order = args['--order']

    # Print header
    print("%s" % title)
    print()

    min_row_format = 3
    min_col_format = 5

    # Get row names (first column)
    row_names = results.keys();
    row_fstr = choose_format(args, row_names, min_row_format)

    # Get column names and format float values
    col_names = []
    vals_by_cols = {}
    for row in results.values():
        col_ind = 0
        for col in row:
            for col_name in col.keys():
                # Get all unique column names
                if not col_name in col_names:
                    col_names.append(col_name)

                # Format value
                val = col[col_name]
                val = format_value(args, val, col_name)
                col[col_name] = val

                vals = vals_by_cols.setdefault(col_ind, [])
                vals.append(val)
                col_ind += 1

    cols_fstr = []
    for col_num in sorted(vals_by_cols.keys()):
        vals = vals_by_cols[col_num]
        vals = [col_names[col_num]] + vals

        # Get column format
        fstr = choose_format(args, vals, min_col_format)
        cols_fstr.append(fstr)

    # Format for each row in a table
    fstr = row_fstr + " " + " ".join(cols_fstr)

    # Print header
    print(fstr.format("", *col_names))

    # Print results
    for row_name in sort_row_names(row_names, row_order):
        row = results[row_name]
        vals = []

        for col in row:
            val = list(col.values())[0]
            vals.append(val)

        print(fstr.format(row_name, *vals))

    print()

def show_results(args):
    odir = args['--dir']
    dirs = []
    runs = {}

    for root, directories, files in os.walk(odir):
        for file in files:
            if not re.search('^fio-results.json$', file):
                continue

            json_path = os.path.join(root, file)
            path = os.path.relpath(json_path, odir)
            path = os.path.dirname(path)
            run = os.path.basename(path)
            path = os.path.dirname(path)

            if args['--include']:
                # Include those which are in include list
                found = False
                for inc in args['--include']:
                    if re.search("^%s" % inc, path):
                        found = True
                        break;
                if not found:
                    continue;

            if args['--exclude']:
                # Exclude those which are in exclude list
                found = False
                for exc in args['--exclude']:
                    if re.search("^%s" % exc, path):
                        found = True
                        break;
                if found:
                    continue;

            json_node = load_json(json_path)
            if json_node:
                runs.setdefault(path, {})[run] = json_node

    #
    # Print everything
    #

    results = {}
    columns = args['--column']
    for column in columns:

        json_path = column
        if not json_path.startswith('client_stats'):
            json_path = 'client_stats/jobname=All clients/' + json_path

        for group_name in runs.keys():
            run = runs[group_name]

            for row_name in run.keys():
                value = get_json_element(json_path, run[row_name])
                group = results.setdefault(group_name, {})
                row = group.setdefault(row_name, [])
                row.append({column : value})

    for group_name in sorted(results.keys()):
        title = "%s" % (group_name);
        show_table(args, title, results[group_name])

    return

def replace_fio_opts(fio_job, fio_opts):
    cfg = configparser.ConfigParser(strict=False, allow_no_value=True)
    cfg.read_string(fio_job)

    for opt in fio_opts:
        m = re.search('(\w+)=(.*)$', opt)
        if m:
            cfg.set('global', m.group(1), m.group(2))

    stream = io.StringIO()
    cfg.write(stream, space_around_delimiters=False)

    return stream.getvalue()


if __name__ == '__main__':
    try:
        args = docopt(__doc__, version='Fio runner')
        for mode in modes.keys():
            if args[mode]:
                start_load(modes[mode], args)
                sys.exit()
        if args['show-results']:
            show_results(args)
        else:
            assert()
    except DocoptExit:
        print(__doc__)
