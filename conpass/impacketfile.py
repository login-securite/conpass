import logging
import time

from impacket.smb3structs import *


class ImpacketFile:
    """
    Remote file representation

    This class uses impacket method to create a file object with usual read methods so that it looks like a local
    file from another library point of view. Methods are
    - open
    - read
    - close
    - seek
    - tell
    """
    def __init__(self, session, console, debug=False):
        self.session = session
        self.console = console
        self.debug = debug
        self._share_name = None
        self._fpath = None
        self._currentOffset = 0
        self._total_read = 0
        self._tid = None
        self._fid = None
        self._fileInfo = None
        self._endOfFile = None

        self._opened = False

        self._buffer_min_size = 1024 * 8
        self._buffer_data = {
            "offset": 0,
            "size": 0,
            "buffer": ""
        }

    def get_connection(self):
        """
        Method to access a private attribute
        :return: session instance
        """
        return self.session

    def _open_share(self):
        try:
            self._tid = self.session.smb_session.connectTree(self._share_name)
        except Exception as e:
            self.console.log("ConnectTree error with '{}'".format(self._share_name))
            return None
        return self

    def open(self, share, path, file):
        """
        Open remote file
        :param share: Share location of the remote file
        :param path: Path of the remote file on provided share
        :param file: Remote filename
        :param timeout: Timeout if file access hangs
        :return: instance of this class
        """
        path = path.replace("\\", "/")
        try:
            self._share_name, self._fpath = share, path + "/" + file
        except Exception as e:
            self.console.log("Parsing error with '{}'".format(path))
            return None

        if self._open_share() is None:
            return None

        try:
            self._fid = self.session.smb_session.openFile(self._tid, self._fpath, desiredAccess=FILE_READ_DATA)
        except Exception as e:
            self.debug and self.console.log("Unable to open remote file {}".format(self._fpath))
            return None

        self._fileInfo = self.session.smb_session.queryInfo(self._tid, self._fid)
        self._endOfFile = self._fileInfo.fields["EndOfFile"]
        self._opened = True
        return self

    def read(self, size):
        """
        Read an amount of bytes on the remote file

        This method uses some caching mechanisms to increase reading speed
        :param size: Number of bytes to read
        :return: Buffer containing file's content
        """
        if size == 0:
            return b''
        if (self._buffer_data["offset"] <= self._currentOffset <= self._buffer_data["offset"] + self._buffer_data[
            "size"]
                and self._buffer_data["offset"] + self._buffer_data["size"] > self._currentOffset + size):
            value = self._buffer_data["buffer"][
                    self._currentOffset - self._buffer_data["offset"]:self._currentOffset - self._buffer_data[
                        "offset"] + size]
        else:
            self._buffer_data["offset"] = self._currentOffset

            """
            If data size is too small, read self._buffer_min_size bytes and cache them
            """
            if size < self._buffer_min_size:
                value = self.session.smb_session.readFile(self._tid, self._fid, self._currentOffset, self._buffer_min_size)
                self._buffer_data["size"] = self._buffer_min_size
                self._total_read += self._buffer_min_size

            else:
                value = self.session.smb_session.readFile(self._tid, self._fid, self._currentOffset, size + self._buffer_min_size)
                while len(value) < size+self._buffer_min_size and self._currentOffset + len(value) < self._endOfFile:
                    value += self.session.smb_session.readFile(self._tid, self._fid, self._currentOffset + len(value), size + self._buffer_min_size - len(value))
                self._buffer_data["size"] = size + self._buffer_min_size
                self._total_read += size

            self._buffer_data["buffer"] = value

        self._currentOffset += size

        return value[:size]

    def close(self):
        """
        Close handle to remote file
        """
        if self._opened:
            self.session.smb_session.closeFile(self._tid, self._fid)
            self.session.smb_session.disconnectTree(self._tid)
        self._share_name = None
        self._fpath = None
        self._currentOffset = 0
        self._total_read = 0
        self._tid = None
        self._fid = None
        self._fileInfo = None
        self._endOfFile = None

        self._opened = False

        self._buffer_min_size = 1024 * 8
        self._buffer_data = {
            "offset": 0,
            "size": 0,
            "buffer": ""
        }

    def seek(self, offset, whence=0):
        """
        Seek a certain byte on the remote file
        :param offset: Offset on the remote file
        :param whence: 0 if absolute offset, 1 if relative offset, 2 if relative to the end of file
        """
        if whence == 0:
            self._currentOffset = offset
        elif whence == 1:
            self._currentOffset += offset
        elif whence == 2:
            self._currentOffset = self._endOfFile - offset
        else:
            raise Exception('Seek function whence value must be between 0-2')

    def tell(self):
        """
        Get current offset
        :return: Current offset
        """
        return self._currentOffset

    def size(self):
        """
        Get remote file size
        :return: Remote file size
        """
        return self._endOfFile

    def get_path(self):
        """
        Get remote file path
        :return: Remote file path (share, path)
        """
        return self._share_name, self._fpath

    def get_file_path(self):
        """
        Get relative file path
        :return:  Relative file path
        """
        return self._fpath

    def get_session(self):
        """
        Get current session
        :return: Current session
        """
        return self.session
