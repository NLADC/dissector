import logging
import os
import io
import shutil
import subprocess
import multiprocessing
import time
import random
import string
import pprint
import tempfile
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq
import pyarrow.csv

from logger import LOGGER
from util import error, IPPROTO_TABLE, FileType, ETHERNET_TYPES, ICMP_TYPES, DNS_QUERY_TYPES

__all__ = ['read_flow', 'read_pcap', 'read_files']


###############################################################################
# taken from https://stackoverflow.com/questions/69156181/pyarrow-find-bad-lines-in-csv-to-parquet-conversion
# Since some pcap->csv files may have UTF-8 errors
class UnicodeErrorIgnorerIO(io.IOBase):
    """Simple wrapper for a BytesIO that removes non-UTF8 input.

    If a file contains non-UTF8 input, it causes problems in pyarrow and other libraries
    that try to decode the input to unicode strings. This just removes the offending bytes.

    >>> io = io.BytesIO(b"INT\xbfL LICENSING INDUSTRY MERCH ASSOC")
    >>> io = UnicodeErrorIgnorerIO(io)
    >>> io.read()
    'INTL LICENSING INDUSTRY MERCH ASSOC'
    """

    def __init__(self, file: io.BytesIO) -> None:
        self.file = file

    def read(self, n=-1):
        return self.file.read(n).decode("utf-8", "ignore").encode("utf-8")

    def readline(self, n=-1):
        return self.file.readline(n).decode("utf-8", "ignore").encode("utf-8")

    def readable(self):
        return True


###############################################################################
class Pcap2Parquet:
    PCAP_COLUMN_NAMES: dict[str, dict] = {
        '_ws.col.Time': {'frame_time': pa.timestamp('us')},
        # 'frame.time': {'frame_time1': pa.timestamp('us')},
        'ip.src': {'ip_src': pa.string()},
        'ip.dst': {'ip_dst': pa.string()},
        'ip.proto': {'ip_proto': pa.uint8()},
        'tcp.flags.str': {'tcp_flags': pa.string()},
        '_ws.col.Source': {'col_source': pa.string()},
        '_ws.col.Destination': {'col_destination': pa.string()},
        '_ws.col.Protocol': {'col_protocol': pa.string()},
        'dns.qry.name': {'dns_qry_name': pa.string()},
        'dns.qry.type': {'dns_qry_type': pa.string()},
        # should be pa.uint16() but docker version seems to export as 32bit hex value
        'eth.type': {'eth_type': pa.uint32()},
        'frame.len': {'frame_len': pa.uint16()},
        'udp.length': {'udp_length': pa.uint16()},
        'http.request.uri': {'http_request_uri': pa.string()},
        'http.host': {'http_host': pa.string()},
        'http.request.method': {'http_request_method': pa.string()},
        'http.user_agent': {'http_user_agent': pa.string()},
        'http.file_data': {'http_file_data': pa.string()},
        'icmp.type': {'icmp_type': pa.uint8()},
        'ip.frag_offset': {'ip_frag_offset': pa.uint16()},
        'ip.ttl': {'ip_ttl': pa.uint8()},
        'ntp.priv.reqcode': {'ntp_priv_reqcode': pa.uint8()},
        'tcp.dstport': {'tcp_dstport': pa.uint16()},
        'tcp.srcport': {'tcp_srcport': pa.uint16()},
        'udp.dstport': {'udp_dstport': pa.uint16()},
        'udp.srcport': {'udp_srcport': pa.uint16()},
        '_ws.col.Info': {'col_info': pa.string()},
    }

    # Max size of chunk to read at a time
    block_size = 512 * 1024 * 1024

    # Max size of pcap to read in one go (in MB)
    max_pcap_chunk = 50

    chunks = None
    chunks_csv = None

    # ------------------------------------------------------------------------------
    def __init__(self, source_file: str, destination_dir: str, log_parse_errors=False, nr_procs=2):
        """Initialises Nfdump2Parquet instance.

        Provide nfdump_fields parameter **only** if defaults don't work
        Defaults for parquet_fields: ts, te, td, sa, da, sp, dp, pr, flg, ipkt, ibyt, opkt, obyt

        :param source_file: name of the nfcapd file to convert
        :param destination_dir: directory for storing resulting parquet file
        :param parquet_fields: the fields from ncapd file to translate to parquet
        :param nfdump_fields: the fields (and order) in the nfcapd file
        """
        if not os.path.isfile(source_file):
            raise FileNotFoundError(source_file)
        self.src_file = source_file
        self.basename = os.path.basename(source_file)
        self.dst_dir = destination_dir
        LOGGER.debug(self.dst_dir)
        self.parse_errors = 0
        self.log_parse_errors = log_parse_errors
        self.nr_procs = int(nr_procs)
        letters = string.ascii_lowercase
        self.random = ''.join(random.choice(letters) for i in range(10))

        # Honour proper way of setting temp dir (e.g. using $TMPDIR)
        # Needed if /tmp is set to tmpfs in RAM (which may not be big enough)
        self.tmp_dir = tempfile.gettempdir()

        # Determine splitsize bases on filesize, max pcap size and nr of cores to use.
        # Split files even if smaller than max pcap size to make maximum use of parallel
        # processing. If filesize > nr_procs*maxpcapchunk then just use that.
        filesize = round(os.path.getsize(self.src_file)/(1024*1024))
        LOGGER.debug(f"Filesize is approximately {filesize}MB")
        LOGGER.debug(f"nr_of_cores x chunk_size = {nr_procs*self.max_pcap_chunk}MB")

        self.splitsize = self.max_pcap_chunk
        if (nr_procs * self.max_pcap_chunk) > filesize:
            self.splitsize = 5
        LOGGER.debug(f"Split size set to {self.splitsize}MB")

    # ------------------------------------------------------------------------------
    def __prepare_file(self):

        # Chop up a file into multiple chunks if it is bigger than a certain size
        # Returns either a list of chunk files or the same single file

        use_tmp = False
        filename = Path(self.src_file)
        # Now check if the file ends in .pcap
        # If not: tcpdump on Ubuntu variants will return permission denied
        # when splitting into multiple chunks
        # Solution: copy to tmp folder with extension .pcap...
        if not str(self.src_file).endswith('.pcap'):
            LOGGER.debug(f'Copy/rename file since it does not end in .pcap')
            shutil.copyfile(self.src_file, f'{self.tmp_dir}/{self.random}.pcap')
            filename = Path(f'{self.tmp_dir}/{self.random}.pcap')
            use_tmp = True
        LOGGER.debug(f'Splitting PCAP file {filename} into chunks of {self.splitsize}MB.')
        process = subprocess.run(
            ['tcpdump', '-r', filename, '-w', f'{self.tmp_dir}/pcap2parquet_{self.random}_chunk', '-C', f'{self.splitsize}'],
            stderr=subprocess.PIPE)
        output = process.stderr
        if process.returncode != 0:
            err = output.decode('utf-8').strip()
            LOGGER.error(f'splitting file failed: {err}')
        else:
            self.chunks = [Path(rootdir) / file for rootdir, _, files in os.walk(self.tmp_dir)
                           for file in files if file.startswith(f'pcap2parquet_{self.random}_chunk')]
            LOGGER.debug(f"Split into {len(self.chunks)} chunks")

        if use_tmp:
            os.remove(filename)

    # ------------------------------------------------------------------------------
    def __cleanup(self):
        if self.chunks:
            if len(self.chunks) > 1:
                for chunk in self.chunks:
                    os.remove(chunk)
            self.chunks = None

        if self.chunks_csv:
            if len(self.chunks_csv) > 1:
                for chunk in self.chunks_csv:
                    os.remove(chunk)
            self.chunks_csv = None

    # ------------------------------------------------------------------------------
    def __parse_error(self, row):
        # LOGGER.debug(row.text)
        self.parse_errors += 1
        if self.log_parse_errors:
            # Append to file
            with open(self.basename + '-parse-errors.txt', 'a', encoding='utf-8') as f:
                f.write(row.text + '\n')
        return 'skip'

    # ------------------------------------------------------------------------------
    def convert_chunk_to_csv(self, pcap_chunk):
        # Create the list of columns tshark has to export to CSV
        col_extract = list(self.PCAP_COLUMN_NAMES.keys())

        new_env = dict(os.environ)
        new_env['LC_ALL'] = 'C.utf8'
        new_env['LC_TIME'] = 'POSIX'
        new_env['LC_NUMERIC'] = 'C.utf8'

        tmp_file, tmp_filename = tempfile.mkstemp()
        # tshark_error = False
        # Create command
        csv_file = None
        command = ['tshark', '-r', str(pcap_chunk), '-t', 'ud', '-T', 'fields']
        for field in col_extract:
            command.extend(['-e', field])
        for option in ['header=n', 'separator=/t', 'quote=n', 'occurrence=f']:
            command.extend(['-E', option])

        LOGGER.debug(" ".join(command))
        try:
            process = subprocess.run(command, stdout=tmp_file, stderr=subprocess.PIPE, env=new_env)
            output = process.stderr
            if process.returncode != 0:
                err = output.decode('utf-8')
                LOGGER.error(f'tshark command failed:{err}')
                os.close(tmp_file)
                os.remove(tmp_filename)
            else:
                if len(output) > 0:
                    err = output.decode('utf-8')
                    for errline in err.split('\n'):
                        # Ignore warnings/errors unless --debug specified
                        if len(errline) > 0 and LOGGER.getEffectiveLevel() == logging.DEBUG:
                            LOGGER.warning(errline)
                os.close(tmp_file)
                csv_file = tmp_filename
        except Exception as e:
            LOGGER.error(f'Error reading {str(pcap_chunk)} : {e}')
            os.close(tmp_file)
            os.remove(tmp_filename)

        return csv_file

    # ------------------------------------------------------------------------------
    def convert(self):

        pp = pprint.PrettyPrinter(indent=4)

        # Create the list of columns tshark has to export to CSV
        col_extract = list(self.PCAP_COLUMN_NAMES.keys())

        # Create the list of names pyarrow gives to the columns in the CSV
        col_names = []
        for extr_name in col_extract:
            col_names.append(next(iter(self.PCAP_COLUMN_NAMES[extr_name])))

        # Dict mapping column names to the pyarrow types
        col_type = {}
        [col_type.update(valtyp) for valtyp in self.PCAP_COLUMN_NAMES.values()]

        start = time.time()

        # Split source pcap into chunks if need be
        self.__prepare_file()
        if not self.chunks:
            LOGGER.error("conversion aborted")
            return None
        duration = time.time() - start
        sf = os.path.basename(self.src_file)
        LOGGER.debug(f"Splitting {sf} took {duration:.2f}s")
        start = time.time()

        # Convert chunks to csv individually and in parallel
        pool = multiprocessing.Pool(self.nr_procs)
        results = pool.map(self.convert_chunk_to_csv, self.chunks)  # Convert the PCAP chunks concurrently
        pool.close()
        pool.join()

        self.chunks_csv = []
        for result in results:
            if result:
                self.chunks_csv.append(result)

        duration = time.time() - start
        sf = os.path.basename(self.src_file)
        LOGGER.debug(f"{sf} to CSV in {duration:.2f}s")
        start = time.time()

        pqwriter = None

        # Now read the produced CSVs and convert them to parquet one by one
        output_file = f'{self.dst_dir}/{self.basename}.parquet'
        LOGGER.debug(output_file)
        for chunknr, chunkcsv in enumerate(self.chunks_csv):
            LOGGER.debug(f"Writing to parquet: {chunknr + 1}/{len(self.chunks_csv)}")
            try:
                with open(chunkcsv, "rb") as f:
                    f = UnicodeErrorIgnorerIO(f)
                    with pyarrow.csv.open_csv(
                            input_file=f,
                            # input_file='tmp.csv',
                            read_options=pyarrow.csv.ReadOptions(
                                block_size=self.block_size,
                                column_names=col_names,
                                encoding='utf-8',
                            ),
                            parse_options=pyarrow.csv.ParseOptions(
                                delimiter='\t',
                                # quote_char="'",
                                invalid_row_handler=self.__parse_error
                            ),
                            convert_options=pyarrow.csv.ConvertOptions(
                                timestamp_parsers=[pyarrow.csv.ISO8601],
                                # timestamp_parsers=["%b %d, %Y %H:%M:%S.%f000 %Z"],
                                column_types=col_type,
                            ),
                    ) as reader:
                        for next_chunk in reader:
                            if next_chunk is None:
                                break
                            table = pa.Table.from_batches([next_chunk])
                            # Add a column with the basename of the source file
                            # This will allow detailed investigation of the proper
                            # original pcap file with tshark if needed
                            table = table.append_column('pcap_file',
                                                        pa.array([self.basename] * len(table), pa.string()))

                            if not pqwriter:
                                pqwriter = pq.ParquetWriter(output_file, table.schema)

                            pqwriter.write_table(table)

            except pyarrow.lib.ArrowInvalid as e:
                LOGGER.error(e)

        if pqwriter:
            pqwriter.close()
            duration = time.time() - start
            LOGGER.debug(f"CSV to Parquet in {duration:.2f}s")

        self.__cleanup()
        return output_file


def read_flow(filename: Path, dst_dir: str) -> str:
    # Max size of chunk to read at a time
    block_size = 512 * 1024 * 1024

    # The default fields (order) present in the nfcapd files
    nf_fields = ['ts', 'te', 'td', 'sa', 'da', 'sp', 'dp', 'pr', 'flg',
                 'fwd', 'stos', 'ipkt', 'ibyt', 'opkt', 'obyt', 'in',
                 'out', 'sas', 'das', 'smk', 'dmk', 'dtos', 'dir',
                 'nh', 'nhb', 'svln', 'dvln', 'ismc', 'odmc', 'idmc',
                 'osmc', 'mpls1', 'mpls2', 'mpls3', 'mpls4', 'mpls5',
                 'mpls6', 'mpls7', 'mpls8', 'mpls9', 'mpls10', 'cl',
                 'sl', 'al', 'ra', 'eng', 'exid', 'tr']

    # The default fields that should be carried over to the parquet file
    # exid == exporter id
    parquet_fields = ['ts', 'te', 'sa', 'da', 'sp', 'dp', 'pr', 'flg',
                      'ipkt', 'ibyt', 'ra']

    drop_columns = [a for a in nf_fields if a not in parquet_fields]

    start = time.time()
    # Create a temp file for the intermediate CSV
    tmp_file, tmp_filename = tempfile.mkstemp()
    os.close(tmp_file)

    try:
        with open(tmp_filename, 'a', encoding='utf-8') as f:
            subprocess.run(['nfdump', '-r', str(filename), '-o', 'csv', '-q'], stdout=f)
    except Exception as e:
        LOGGER.error(f'Error reading {str(filename)} : {e}')
        return None

    duration = time.time() - start
    LOGGER.debug(f"{filename.name} to CSV in {duration:.2f}s")

    # Create a temp file for the parquet file
    parquetfile = f"{dst_dir}/{filename.name}.parquet"
    LOGGER.debug(parquetfile)

    start = time.time()
    pqwriter = None

    try:
        with pyarrow.csv.open_csv(input_file=tmp_filename,
                                  read_options=pyarrow.csv.ReadOptions(
                                      block_size=block_size,
                                      column_names=nf_fields)
                                  ) as reader:
            chunk_nr = 0
            for next_chunk in reader:
                chunk_nr += 1
                if next_chunk is None:
                    break
                table = pa.Table.from_batches([next_chunk])
                try:
                    table = table.drop(drop_columns)
                except KeyError as ke:
                    LOGGER.error(ke)

                table = table.append_column('flowsrc', [[filename.name] * table.column('te').length()])

                if not pqwriter:
                    pqwriter = pq.ParquetWriter(parquetfile, table.schema)

                pqwriter.write_table(table)

    except pyarrow.lib.ArrowInvalid as e:
        LOGGER.error(e)

    if pqwriter:
        pqwriter.close()

    duration = time.time() - start
    LOGGER.debug(f"{filename.name} CSV to Parquet in {duration:.2f}s")

    # Remove temporary file
    os.remove(tmp_filename)

    return parquetfile

def _pcap_convert(source_file: Path, dst_dir: str, nr_processes: int) -> str:
    if not os.path.isfile(source_file):
        raise FileNotFoundError(source_file)
    basename = os.path.basename(source_file)
    output_file = f'{dst_dir}/{basename}.parquet'

    command = ['pcap-converter', '-f', str(source_file), '-o', output_file, '-j', '6']
    if LOGGER.isEnabledFor(logging.DEBUG):
        command.append('-v')

    LOGGER.debug(" ".join(command))
    try:
        process = subprocess.run(command) #, stdout=tmp_file, stderr=subprocess.PIPE)
    except Exception as e:
        LOGGER.error(f'Error reading {str(source_file)} : {e}')

    return output_file

def read_pcap(filename: Path, dst_dir: str, nr_processes: int, rust_converter: bool) -> str:
    # Store converted parquet file in the current working directory
    start = time.time()
    if rust_converter:
        LOGGER.debug("Using experimental Rust converter")
        parquet_file = _pcap_convert(filename, dst_dir, nr_processes)
        duration = time.time() - start
        LOGGER.debug(f"conversion took {duration:.2f} seconds")
    else:
        pcap2pqt = Pcap2Parquet(filename, dst_dir, False, nr_processes)
        parquet_file = pcap2pqt.convert()
        duration = time.time() - start
        if parquet_file:
            LOGGER.debug(f"conversion took {duration:.2f} seconds")
        else:
            LOGGER.error('Conversion failed')
            return error('Conversion failed')

        if pcap2pqt.parse_errors > 0:
            LOGGER.debug(f'{pcap2pqt.parse_errors} parse errors during conversion. Error lines were skipped')

    return parquet_file


def read_files(filenames: list[Path], dst_dir: str, filetype: FileType, nr_processes: int, rust_converter: bool) -> list[Path]:
    """
    Convert capture files into parquet using either read_flow or read_pcap
    :param filenames: Paths to capture files
    :param dst_dir: Path where to store resulting parquet files
    :param filetype: FLOW or PCAP
    :param nr_processes: int: number of processes used to concurrently process the capture file.
    :return: Filename of the resulting parquet file
    """

    LOGGER.debug(f'Converting "{filenames}" with {nr_processes} CPUs, storing them in {dst_dir}')
    os.makedirs(dst_dir, exist_ok=True)
    if filetype == FileType.PQT:
        return filenames
    elif filetype == FileType.PCAP:
        pqt_files = [read_pcap(f, dst_dir=dst_dir, nr_processes=nr_processes, rust_converter=rust_converter)
                     for f in filenames]
    elif filetype == FileType.FLOW:
        # No way to parallel process individual flow files, so process files in parallel instead
        # return read_flow(filename, dst_dir)
        items = [(filename, dst_dir) for filename in filenames]
        pool = multiprocessing.Pool(nr_processes)
        pqt_files = pool.starmap(read_flow, items)  # Convert the flow files concurrently
        pool.close()
        pool.join()

    return pqt_files