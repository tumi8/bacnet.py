"""
bacnet.py: Parse BACnet responses from hex data.
"""

import datetime
import struct

__author__ = "Oliver Gasser"
__copyright__ = "Copyright 2016"
__license__ = "GPL 3"
__maintainer__ = "Oliver Gasser"
__email__ = "gasser@net.in.tum.de"

class Response:
    """
    Class for handling BACnet Complex-ACK responses.

    """

    TYPE_COMPLEX_ACK_PDU = 0x03

    # Context specific tags
    TAG_NUM_OBJECT_ID = 0
    TAG_NUM_ERROR = 5
    TAG_NUM_OPENING = 6
    TAG_NUM_CLOSING = 7

    # Application specific tags
    TAG_NUM_NULL = 0
    TAG_NUM_UINT = 2
    TAG_NUM_CHAR_STRING = 7
    TAG_NUM_ENUMERATED = 9
    TAG_NUM_DATE = 10
    TAG_NUM_TIME = 11

    PROP_ID_OBJECT_ID = -1

    ENCODING_UTF8 = 0
    ENCODING_DBCS = 1 # Not available on Linux
    ENCODING_JISX0208 = 2
    ENCODING_UCS2 = 4
    ENCODING_LATIN1 = 5

    # Initializes a bacnet reponse by parsing the UDP payload
    def __init__(self, data):
        self.bvlc_transport = None    # 0x81
        self.bvlc_npdu = None         # 0x0a
        self.bvlc_len = None

        self.npdu_version = None      # 0x01
        self.npdu_ctrl = None

        self.ndpu_dnet = None
        self.npdu_dlen = None
        self.npdu_dadr = None

        self.ndpu_snet = None
        self.npdu_slen = None
        self.npdu_sadr = None

        self.npdu_hop_count = None

        self.apdu_type = None
        self.apdu_seg = None
        self.apdu_invoke_id = None
        self.apdu_confirmed_service_choice = None

        # Derived from Object ID
        self.object_type = None
        self.instance = None

        self.properties = None

        # Parse header fields
        data_bin = bytearray.fromhex(data)
        curr_byte = 0

        self.bvlc_transport = data_bin[curr_byte]
        self.bvlc_npdu = data_bin[curr_byte+1]
        self.bvlc_len = self.parse_uint(data_bin, curr_byte+2, 2)

        if len(data_bin) <= 6:
            return

        curr_byte += 4 # 4

        self.npdu_version = data_bin[curr_byte]
        self.npdu_ctrl = data_bin[curr_byte+1]

        curr_byte += 2 # 6

        if self.ctrl_dnet_present():
            if curr_byte + 3 + 1 >= len(data_bin):
                return
            self.npdu_dnet = self.parse_uint(data_bin, curr_byte, 2)
            self.npdu_dlen = data_bin[curr_byte+2]
            # Check for valid MAC destination address length
            if self.npdu_dlen in [1, 2, 3, 6, 7]:
                self.npdu_dadr = self.parse_uint(data_bin, curr_byte+3, self.npdu_dlen)

            curr_byte += 2+1+self.npdu_dlen

        if self.ctrl_snet_present():
            if curr_byte + 3 >= len(data_bin):
                return
            self.npdu_snet = self.parse_uint(data_bin, curr_byte, 2)
            self.npdu_slen = data_bin[curr_byte+2]
            # Check for valid MAC source address length
            if self.npdu_slen in [1, 2, 3, 6]:
                self.npdu_sadr = self.parse_uint(data_bin, curr_byte+3, self.npdu_slen)

            curr_byte += 2+1+self.npdu_slen

        if self.ctrl_dnet_present():
            if curr_byte + 1 >= len(data_bin):
                return
            self.npdu_hop_count = data_bin[curr_byte]

            curr_byte += 1


        if len(data_bin) < curr_byte + 4:
            return


        self.apdu_type = (data_bin[curr_byte] & 0xf0) >> 4

        if self.apdu_type == self.TYPE_COMPLEX_ACK_PDU:
            self.parse_complex_ack_pdu(data_bin, curr_byte)


    def parse_complex_ack_pdu(self, data_bin, curr_byte):
        self.apdu_seg = (data_bin[curr_byte] & 0x0c) >> 2

        if self.seg_segmented():
            self.apdu_seq_nr = data_bin[curr_byte+1]
            self.apdu_window_size = data_bin[curr_byte+2]
            curr_byte += 2

        self.apdu_invoke_id = data_bin[curr_byte+1]
        self.apdu_confirmed_service_choice = data_bin[curr_byte+2]

        curr_byte += 3

        self.properties = dict()

        # Read all tags and their content
        while curr_byte < self.bvlc_len:
            prop_id, val, curr_byte = self.parse_tag_content(data_bin, curr_byte)

            # Object ID
            if prop_id == self.PROP_ID_OBJECT_ID and val:
                self.object_type = (val & 0xffc00000) >> 22
                self.instance = val & 0x003fffff
            elif prop_id is not None:
                self.properties[prop_id] = val

    # Returns the parsed tag and the updated curr_byte
    def parse_tag(self, data_bin, curr_byte):
        tag = Tag(data_bin, curr_byte)
        curr_byte += 1

        if not hasattr(tag, "context_spec"):
            return (None, curr_byte)

        # Check for extended data length
        if not tag.context_spec:
            if tag.len_val_type == 5:
                tag.len_val_type = data_bin[curr_byte]
                curr_byte += 1

            if tag.len_val_type == 254:
                tag.len_val_type = self.parse_uint(data_bin, curr_byte, 2)
                curr_byte += 2
            elif tag.len_val_type == 255:
                tag.len_val_type = self.parse_uint(data_bin, curr_byte, 4)
                curr_byte += 4

        return (tag, curr_byte)


    # Returns (property ID, value, curr_byte)
    def parse_tag_content(self, data_bin, curr_byte, prop_id=None):

        error = False

        prop_content = None

        tag, curr_byte = self.parse_tag(data_bin, curr_byte)

        # Skip opening and closing tags
        while tag and tag.context_spec and (tag.len_val_type == self.TAG_NUM_OPENING or tag.len_val_type == self.TAG_NUM_CLOSING):
            if curr_byte >= self.bvlc_len:
                return None, None, curr_byte
            if tag.number == self.TAG_NUM_ERROR:
                error = True
            tag, curr_byte = self.parse_tag(data_bin, curr_byte)

        if not tag:
            return (None, None, curr_byte)

        # Object ID
        if tag.context_spec and tag.number == self.TAG_NUM_OBJECT_ID:
            prop_id = self.PROP_ID_OBJECT_ID

            if tag.len_val_type != 4:
                print("WARN: Object ID with length " + str(tag.len_val_type) + " found: " + str(tag))
            else:
                prop_content = self.parse_uint(data_bin, curr_byte, 4)

        # Tag for property information
        elif tag.context_spec:
            if tag.len_val_type != 1:
                print("WARN: Tag length/value/type with length " + str(tag.len_val_type) + " found: " + str(tag))
            else:
                prop_id = data_bin[curr_byte]
                return self.parse_tag_content(data_bin, curr_byte+1, prop_id)

        # Application specific tag = content
        elif not tag.context_spec:
            try:
                if not prop_id:
                    print("WARN: No property ID set for application specific tag: " + str(tag))
                elif tag.number == self.TAG_NUM_DATE:
                    prop_content = self.parse_date(data_bin, curr_byte)
                elif tag.number == self.TAG_NUM_TIME:
                    prop_content = self.parse_time(data_bin, curr_byte)
                elif tag.number == self.TAG_NUM_CHAR_STRING:
                    prop_content = self.parse_char_string(data_bin, curr_byte, tag.len_val_type)
                elif tag.number == self.TAG_NUM_UINT:
                    prop_content = self.parse_uint(data_bin, curr_byte, tag.len_val_type)
                elif tag.number == self.TAG_NUM_ENUMERATED and error:
                    prop_content, curr_byte = self.parse_error(data_bin, curr_byte, tag.len_val_type)
                elif tag.number == self.TAG_NUM_NULL:
                    prop_content = None
                else:
                    print("WARN: Not implemented application tag: " + str(tag))

            except (ValueError, LookupError) as err:
                prop_content = EncodingError(prop_id, curr_byte, err)

        curr_byte += tag.len_val_type

        return (prop_id, prop_content, curr_byte)


    def parse_date(self, data_bin, curr_byte):
        return datetime.date(1900 + data_bin[curr_byte], data_bin[curr_byte+1], data_bin[curr_byte+2])

    def parse_time(self, data_bin, curr_byte):
        return datetime.time(data_bin[curr_byte], data_bin[curr_byte+1], data_bin[curr_byte+2])

    def parse_char_string(self, data_bin, curr_byte, length):
        if data_bin[curr_byte] == self.ENCODING_UTF8:
            return data_bin[curr_byte+1:curr_byte+length].decode("utf8")
        elif data_bin[curr_byte] == self.ENCODING_DBCS:
            return data_bin[curr_byte+1:curr_byte+length].decode("dbcs")
        elif data_bin[curr_byte] == self.ENCODING_JISX0208:
            return data_bin[curr_byte+1:curr_byte+length].decode("shift_jis")
        elif data_bin[curr_byte] == self.ENCODING_UCS2:
            return data_bin[curr_byte+1:curr_byte+length].decode("UTF-16BE")
        elif data_bin[curr_byte] == self.ENCODING_LATIN1:
            return data_bin[curr_byte+1:curr_byte+length].decode("iso-8859-1")
        else:
            print("WARN: Not implemented char string encoding: " + str(data_bin[curr_byte]))

    def parse_uint(self, data_bin, curr_byte, length):
        if length > len(data_bin[curr_byte:]):
            print("WARN: Expecting uint of length " + str(length) + " but have only " + str(len(data_bin[curr_byte:])) + " of payload left")
            return
        if length == 1:
            return data_bin[curr_byte]
        elif length == 2:
            return struct.unpack("!H", bytes(data_bin[curr_byte:curr_byte+2]))[0]
        elif length == 3:
            upper_two = struct.unpack("!H", bytes(data_bin[curr_byte:curr_byte+2]))[0]
            lower_one = data_bin[curr_byte+2]
            return upper_two << 8 + lower_one
        elif length == 4:
            return struct.unpack("!I", bytes(data_bin[curr_byte:curr_byte+4]))[0]
        elif length == 6:
            upper_two = struct.unpack("!H", bytes(data_bin[curr_byte:curr_byte+2]))[0]
            lower_four = struct.unpack("!I", bytes(data_bin[curr_byte+2:curr_byte+6]))[0]
            return upper_two << 32 + lower_four
        elif length == 7:
            return self.parse_uint(data_bin, curr_byte, 6) << 8 + self.parse_uint(data_bin, curr_byte+6, 1)
        else:
            print("WARN: Not implemented length for uint parsing: " + str(length))


    def parse_error(self, data_bin, curr_byte, length):
        err_class = self.parse_uint(data_bin, curr_byte, length)
        curr_byte += length
        tag = Tag(data_bin, curr_byte)
        curr_byte += 1
        err_code = self.parse_uint(data_bin, curr_byte, tag.len_val_type)
        curr_byte += tag.len_val_type

        # Subtract length from curr_byte as it will be added again later
        return (BacError(err_class, err_code), curr_byte-length)


    def ctrl_network_msg(self):
        return self.npdu_ctrl & 0x80

    def ctrl_reserved_set(self):
        return self.npdu_ctrl & 0x50

    def ctrl_dnet_present(self):
        return self.npdu_ctrl & 0x20

    def ctrl_snet_present(self):
        return self.npdu_ctrl & 0x08

    def ctrl_reply_expected(self):
        return self.npdu_ctrl & 0x04

    def ctrl_priority(self):
        return self.npdu_ctrl & 0x03

    def seg_segmented(self):
        return self.apdu_seg & 0x02

    def seg_more(self):
        return self.apdu_seg & 0x01


class Tag:
    """
    Class for handling BACnet tags.

    """

    def __init__(self, data_bin, curr_byte):

        if curr_byte >= len(data_bin):
            print("WARN: Wanted to initialize tag after end of payload")
            return None

        self.number = data_bin[curr_byte] >> 4
        self.context_spec = (data_bin[curr_byte] & 0x08) >> 3
        self.len_val_type = data_bin[curr_byte] & 0x07

    def __str__(self):
        return ("context" if self.context_spec else "application") + " specific tag: number=" + str(self.number) + \
            " length/value/type=" + str(self.len_val_type)


class EncodingError(Exception):
    """
    Class for handling encoding errors inside responses.

    """

    def __init__(self, prop_id, curr_byte, error):
        super(EncodingError, self).__init__("")
        self.prop_id = prop_id
        self.curr_byte = curr_byte
        self.error = error

    def __str__(self):
        return "encoding error: property " + str(self.prop_id) + ", curr_byte " + \
            str(self.curr_byte) + ", payload" + str(self.error)


class BacError(Exception):
    """
    Class for handling BACnet errors in responses.
    """

    def __init__(self, err_class, err_code):
        super(BacError, self).__init__("")
        self.err_class = err_class
        self.err_code = err_code

    def __str__(self):
        return "error: class " + str(self.err_class) + ", code " + str(self.err_code)
