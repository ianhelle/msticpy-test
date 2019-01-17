# -------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# --------------------------------------------------------------------------
"""Module for IoCExtract class."""

import re
import pandas as pd

__all__ = ['IoCExtract']
__version__ = '0.1'
__author__ = 'Ian Hellen'


def _compile_regex(regex):

    return re.compile(regex, re.I | re.X | re.M)


class IoCExtract(object):
    """
    IoC Extractor - looks for common IoC patterns in input strings.

    The extract() method takes either a string or a pandas DataFrame
    as input. When using the string option as an input extract will
    return a dictionary of results. When using a DataFrame the results
    will be returned as a new DataFrame with the following columns:
    IoCType: the mnemonic used to distinguish different IoC Types
    Observable: the actual value of the observable
    SourceIndex: the index of the row in the input DataFrame from
    which the source for the IoC observable was extracted.

    The class has a number of built-in IoC regex definitions.
    These can be retrieved using the ioc_types attribute.

    Addition IoC definitions can be added using the add_ioc_type
    method.

    Note: due to some ambiguity in the regular expression patterns
    for different types and observable may be returned assigned to
    multiple observable types. E.g. 192.168.0.1 is a also a legal file
    name in both Linux and Windows. Linux file names have a particularly
    large scope in terms of legal characters so it will be quite common
    to see other IoC observables (or parts of them) returned as a
    possible linux path.
    """

    IPV4_REGEX = r'(?P<ipaddress>(?:[0-9]{1,3}\.){3}[0-9]{1,3})'
    IPV6_REGEX = r'(?<![:.\w])(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}(?![:.\w])'
    DNS_REGEX = r'((?=[a-z0-9-]{1,63}\.)[a-z0-9]+(-[a-z0-9]+)*\.){2,}[a-z]{2,63}'
    # dns_regex = '\\b((?=[a-z0-9-]{1,63}\\.)[a-z0-9]+(-[a-z0-9]+)*\\.){2,}[a-z]{2,63}\\b'

    URL_REGEX = r'''
            (?P<protocol>(https?|ftp|telnet|ldap|file)://)
            (?P<userinfo>([a-z0-9-._~!$&\'()*+,;=:]|%[0-9A-F]{2})*@)?
            (?P<host>([a-z0-9-._~!$&\'()*+,;=]|%[0-9A-F]{2})*)
            (:(?P<port>\d*))?
            (/(?P<path>([^?\# ]|%[0-9A-F]{2})*))?
            (\?(?P<query>([a-z0-9-._~!$&'()*+,;=:/?@]|%[0-9A-F]{2})*))?
            (\#(?P<fragment>([a-z0-9-._~!$&'()*+,;=:/?@]|%[0-9A-F]{2})*))?\b'''

    WINPATH_REGEX = r'''
            (?P<root>[a-z]:|\\\\[a-z0-9_.$-]+||[.]+)
            (?P<folder>\\(?:[^\/:*?"\'<>|\r\n]+\\)*)
            (?P<file>[^\\/*?""<>|\r\n ]+)'''
    # Linux simplified - this ignores some legal linux paths avoid matching too much
    # TODO - also matches URLs!
    LXPATH_REGEX = r'''(?P<root>/+||[.]+)
            (?P<folder>/(?:[^\\/:*?<>|\r\n]+/)*)
            (?P<file>[^/\0<>|\r\n ]+)'''

    MD5_REGEX = r'(?:^|[^A-Fa-f0-9])(?P<hash>[A-Fa-f0-9]{32})(?:$|[^A-Fa-f0-9])'
    SHA1_REGEX = r'(?:^|[^A-Fa-f0-9])(?P<hash>[A-Fa-f0-9]{40})(?:$|[^A-Fa-f0-9])'
    SHA256_REGEX = r'(?:^|[^A-Fa-f0-9])(?P<hash>[A-Fa-f0-9]{64})(?:$|[^A-Fa-f0-9])'

    _content_regex = {}

    def __init__(self):
        """Intialize new instance of IoCExtract."""
        # IP Addresses
        self.add_ioc_type('ipv4', self.IPV4_REGEX)
        self.add_ioc_type('ipv6', self.IPV6_REGEX)

        # Dns Domains
        # TODO - This also matches IP addresses
        self.add_ioc_type('dns', self.DNS_REGEX)

        # Http requests
        self.add_ioc_type('url', self.URL_REGEX)

        # File paths
        # Windows
        self.add_ioc_type('windows_path', self.WINPATH_REGEX)

        self.add_ioc_type('linux_path', self.LXPATH_REGEX)

        # MD5, SHA1, SHA256 hashes
        self.add_ioc_type('md5_hash', self.MD5_REGEX)
        self.add_ioc_type('sha1_hash', self.SHA1_REGEX)
        self.add_ioc_type('sha256_hash', self.SHA256_REGEX)

    # Public members

    def add_ioc_type(self, ioc_type='', ioc_regex=''):
        """
        Add an IoC type and regular expression to use to the built-in set.

        Note: adding an ioc_type that exists in the internal set will overwrite that item
        Regular expressions are compiled with re.I | re.X | re.M (Ignore case, Verbose
        and MultiLine)
            :param: ioc_type - a unique name for the IoC type
            :param: ioc_regex - a regular expression used to search for the type
            :type ioc_type: str
            :type ioc_regex: str
        """
        if ioc_type is None or ioc_type.strip() is None:
            raise Exception('No value supplied for ioc_type parameter')
        if ioc_regex is None or ioc_regex.strip() is None:
            raise Exception('No value supplied for ioc_regex parameter')

        self._content_regex[ioc_type] = _compile_regex(regex=ioc_regex)

    @property
    def ioc_types(self):
        """
        Return the current set of IoC types and regular expressions.

            :rtype: dict of IoC Type names and regular expressions
        """
        return self._content_regex

    def extract(self, src: str = None, data: pd.DataFrame = None, columns: list = None):
        """
        Extract IoCs from either a string or pandas DataFrame.

            :param data: input DataFrame from which to read source strings
            :type data: DataFrame
            :param columns: The list of columns to use as source strings,
                if the data parameter is used.
            :type columns: list[str]
            :param src: source string in which to look for IoC patterns
            :type src: str
            :rtype: dict of found observables (if input is a string) or
                DataFrame of observables

        Extract takes either a string or a pandas DataFrame as input.
        When using the string option as an input extract will
        return a dictionary of results.
        When using a DataFrame the results will be returned as a new
        DataFrame with the following columns:
        - IoCType: the mnemonic used to distinguish different IoC Types
        - Observable: the actual value of the observable
        - SourceIndex: the index of the row in the input DataFrame from
        which the source for the IoC observable was extracted.
        """
        if src and src.strip():
            return self._analyze_for_iocs(src)

        if data is None:
            raise Exception('No source data was supplied to extract')

        # Handle DataFrame option
        assert isinstance(data, pd.DataFrame)

        if columns is None:
            raise Exception(
                'No values where supplied for the columns parameter')

        col_set = set(columns)
        if not col_set <= set(data.columns):
            missing_cols = [elem for elem in col_set if elem not in data.colums]
            raise Exception('Source column(s) {} not found in supplied DataFrame'
                            .format(', '.join(missing_cols)))

        result_columns = ['IoCType', 'Observable', 'SourceIndex']
        result_frame = pd.DataFrame(columns=result_columns)
        for idx, datarow in data.iterrows():
            for col in columns:
                ioc_results = self._analyze_for_iocs(datarow[col])
                for result_type, result_set in ioc_results.items():
                    if result_set:
                        for observable in result_set:
                            result_row = pd.Series(
                                data=[result_type, observable, idx], index=result_columns)
                            result_frame = result_frame.append(
                                result_row, ignore_index=True)

        return result_frame

    # Private methods
    def _analyze_for_iocs(self, src):
        # process the string for IoCs

        iocs_found = {}

        from urllib.parse import unquote
        for (ioc_type, rgx) in self._content_regex.items():
            match_pos = 0
            while True:
                rgx_match = rgx.search(src, match_pos)
                if rgx_match is not None:
                    if ioc_type not in iocs_found:
                        iocs_found[ioc_type] = set()

                    iocs_found[ioc_type].add(rgx_match.group())
                    if ioc_type == 'url':
                        decoded_url = unquote(rgx_match.group())
                        decoded_match = rgx.search(decoded_url)
                        if decoded_match is not None:
                            iocs_found[ioc_type].add(decoded_match.group())
                            if 'dns' not in iocs_found:
                                iocs_found['dns'] = set()
                            iocs_found['dns'].add(
                                decoded_match.groupdict()['host'])
                    match_pos = rgx_match.end()
                else:
                    break
        return iocs_found
