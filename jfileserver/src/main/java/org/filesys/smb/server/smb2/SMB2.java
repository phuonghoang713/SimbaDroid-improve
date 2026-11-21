/*
 * Copyright (C) 2026 SimbaDroid contributors
 *
 * This file is part of JFileServer.
 *
 * JFileServer is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * JFileServer is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with JFileServer. If not, see <http://www.gnu.org/licenses/>.
 */

package org.filesys.smb.server.smb2;

/**
 * SMB2/SMB3 protocol constants, see [MS-SMB2].
 */
public final class SMB2 {

    private SMB2() {
    }

    // Header layout, offsets are relative to the start of the SMB2 header
    public static final int HEADER_LEN = 64;

    public static final int OFF_PROTOCOL_ID = 0;
    public static final int OFF_STRUCT_SIZE = 4;
    public static final int OFF_CREDIT_CHARGE = 6;
    public static final int OFF_STATUS = 8;
    public static final int OFF_COMMAND = 12;
    public static final int OFF_CREDITS = 14;
    public static final int OFF_FLAGS = 16;
    public static final int OFF_NEXT_COMMAND = 20;
    public static final int OFF_MESSAGE_ID = 24;
    public static final int OFF_ASYNC_ID = 32;
    public static final int OFF_PROCESS_ID = 32;
    public static final int OFF_TREE_ID = 36;
    public static final int OFF_SESSION_ID = 40;
    public static final int OFF_SIGNATURE = 48;

    public static final int SIGNATURE_LEN = 16;

    // Transform (encryption) header
    public static final int TRANSFORM_HEADER_LEN = 52;
    public static final int TF_OFF_SIGNATURE = 4;
    public static final int TF_OFF_NONCE = 20;
    public static final int TF_OFF_ORIG_SIZE = 36;
    public static final int TF_OFF_FLAGS = 42;
    public static final int TF_OFF_SESSION_ID = 44;

    // Commands
    public static final int CMD_NEGOTIATE = 0x00;
    public static final int CMD_SESSION_SETUP = 0x01;
    public static final int CMD_LOGOFF = 0x02;
    public static final int CMD_TREE_CONNECT = 0x03;
    public static final int CMD_TREE_DISCONNECT = 0x04;
    public static final int CMD_CREATE = 0x05;
    public static final int CMD_CLOSE = 0x06;
    public static final int CMD_FLUSH = 0x07;
    public static final int CMD_READ = 0x08;
    public static final int CMD_WRITE = 0x09;
    public static final int CMD_LOCK = 0x0A;
    public static final int CMD_IOCTL = 0x0B;
    public static final int CMD_CANCEL = 0x0C;
    public static final int CMD_ECHO = 0x0D;
    public static final int CMD_QUERY_DIRECTORY = 0x0E;
    public static final int CMD_CHANGE_NOTIFY = 0x0F;
    public static final int CMD_QUERY_INFO = 0x10;
    public static final int CMD_SET_INFO = 0x11;
    public static final int CMD_OPLOCK_BREAK = 0x12;

    private static final String[] CMD_NAMES = {"Negotiate", "SessionSetup", "Logoff", "TreeConnect", "TreeDisconnect",
            "Create", "Close", "Flush", "Read", "Write", "Lock", "IOCtl", "Cancel", "Echo", "QueryDirectory",
            "ChangeNotify", "QueryInfo", "SetInfo", "OplockBreak"};

    public static String commandName(int cmd) {
        return cmd >= 0 && cmd < CMD_NAMES.length ? CMD_NAMES[cmd] : "0x" + Integer.toHexString(cmd);
    }

    // Header flags
    public static final int FLG_SERVER_TO_REDIR = 0x00000001;
    public static final int FLG_ASYNC_COMMAND = 0x00000002;
    public static final int FLG_RELATED_OPERATIONS = 0x00000004;
    public static final int FLG_SIGNED = 0x00000008;
    public static final int FLG_DFS_OPERATIONS = 0x10000000;
    public static final int FLG_REPLAY_OPERATION = 0x20000000;

    // Dialect revisions
    public static final int DIALECT_202 = 0x0202;
    public static final int DIALECT_210 = 0x0210;
    public static final int DIALECT_300 = 0x0300;
    public static final int DIALECT_302 = 0x0302;
    public static final int DIALECT_311 = 0x0311;
    public static final int DIALECT_WILDCARD = 0x02FF;

    // Negotiate security mode
    public static final int NEG_SIGNING_ENABLED = 0x0001;
    public static final int NEG_SIGNING_REQUIRED = 0x0002;

    // Global capabilities
    public static final int CAP_DFS = 0x00000001;
    public static final int CAP_LEASING = 0x00000002;
    public static final int CAP_LARGE_MTU = 0x00000004;
    public static final int CAP_MULTI_CHANNEL = 0x00000008;
    public static final int CAP_PERSISTENT_HANDLES = 0x00000010;
    public static final int CAP_DIRECTORY_LEASING = 0x00000020;
    public static final int CAP_ENCRYPTION = 0x00000040;

    // Negotiate context types (SMB 3.1.1)
    public static final int CTX_PREAUTH_INTEGRITY = 0x0001;
    public static final int CTX_ENCRYPTION = 0x0002;
    public static final int CTX_COMPRESSION = 0x0003;
    public static final int CTX_NETNAME = 0x0005;
    public static final int CTX_TRANSPORT = 0x0006;
    public static final int CTX_RDMA_TRANSFORM = 0x0007;
    public static final int CTX_SIGNING = 0x0008;

    public static final int HASH_SHA512 = 0x0001;

    public static final int CIPHER_NONE = 0x0000;
    public static final int CIPHER_AES128_CCM = 0x0001;
    public static final int CIPHER_AES128_GCM = 0x0002;

    public static final int SIGN_HMAC_SHA256 = 0x0000;
    public static final int SIGN_AES_CMAC = 0x0001;
    public static final int SIGN_AES_GMAC = 0x0002;

    // Session setup
    public static final int SESSION_FLAG_BINDING = 0x01;

    public static final int SESSION_IS_GUEST = 0x0001;
    public static final int SESSION_IS_NULL = 0x0002;
    public static final int SESSION_ENCRYPT_DATA = 0x0004;

    // Tree connect
    public static final int SHARE_TYPE_DISK = 0x01;
    public static final int SHARE_TYPE_PIPE = 0x02;
    public static final int SHARE_TYPE_PRINT = 0x03;

    public static final int SHAREFLAG_ENCRYPT_DATA = 0x00008000;

    // Oplock levels
    public static final int OPLOCK_NONE = 0x00;

    // Create
    public static final int CREATE_ACTION_SUPERSEDED = 0;
    public static final int CREATE_ACTION_OPENED = 1;
    public static final int CREATE_ACTION_CREATED = 2;
    public static final int CREATE_ACTION_OVERWRITTEN = 3;

    public static final int DISP_SUPERSEDE = 0;
    public static final int DISP_OPEN = 1;
    public static final int DISP_CREATE = 2;
    public static final int DISP_OPEN_IF = 3;
    public static final int DISP_OVERWRITE = 4;
    public static final int DISP_OVERWRITE_IF = 5;

    public static final int OPT_DIRECTORY_FILE = 0x00000001;
    public static final int OPT_NON_DIRECTORY_FILE = 0x00000040;
    public static final int OPT_DELETE_ON_CLOSE = 0x00001000;
    public static final int OPT_OPEN_REPARSE_POINT = 0x00200000;

    // Access mask bits
    public static final int ACC_READ_DATA = 0x00000001;
    public static final int ACC_WRITE_DATA = 0x00000002;
    public static final int ACC_APPEND_DATA = 0x00000004;
    public static final int ACC_READ_EA = 0x00000008;
    public static final int ACC_WRITE_EA = 0x00000010;
    public static final int ACC_EXECUTE = 0x00000020;
    public static final int ACC_DELETE_CHILD = 0x00000040;
    public static final int ACC_READ_ATTRIBUTES = 0x00000080;
    public static final int ACC_WRITE_ATTRIBUTES = 0x00000100;
    public static final int ACC_DELETE = 0x00010000;
    public static final int ACC_READ_CONTROL = 0x00020000;
    public static final int ACC_WRITE_DAC = 0x00040000;
    public static final int ACC_WRITE_OWNER = 0x00080000;
    public static final int ACC_SYNCHRONIZE = 0x00100000;
    public static final int ACC_MAXIMUM_ALLOWED = 0x02000000;
    public static final int ACC_GENERIC_ALL = 0x10000000;
    public static final int ACC_GENERIC_EXECUTE = 0x20000000;
    public static final int ACC_GENERIC_WRITE = 0x40000000;
    public static final int ACC_GENERIC_READ = 0x80000000;

    public static final int ACC_FILE_ALL = 0x001F01FF;
    public static final int ACC_FILE_READ_ONLY = 0x001200A9;

    /** Access bits that modify a file, its metadata or the namespace */
    public static final int ACC_WRITE_MASK = ACC_WRITE_DATA | ACC_APPEND_DATA | ACC_WRITE_EA | ACC_DELETE_CHILD
            | ACC_WRITE_ATTRIBUTES | ACC_DELETE | ACC_WRITE_DAC | ACC_WRITE_OWNER | ACC_GENERIC_WRITE | ACC_GENERIC_ALL;

    // File attributes
    public static final int ATTR_READONLY = 0x00000001;
    public static final int ATTR_HIDDEN = 0x00000002;
    public static final int ATTR_SYSTEM = 0x00000004;
    public static final int ATTR_DIRECTORY = 0x00000010;
    public static final int ATTR_ARCHIVE = 0x00000020;
    public static final int ATTR_NORMAL = 0x00000080;

    // Close flags
    public static final int CLOSE_POSTQUERY_ATTRIB = 0x0001;

    // Query directory flags
    public static final int QD_RESTART_SCANS = 0x01;
    public static final int QD_RETURN_SINGLE_ENTRY = 0x02;
    public static final int QD_INDEX_SPECIFIED = 0x04;
    public static final int QD_REOPEN = 0x10;

    // Info types
    public static final int INFO_FILE = 0x01;
    public static final int INFO_FILESYSTEM = 0x02;
    public static final int INFO_SECURITY = 0x03;
    public static final int INFO_QUOTA = 0x04;

    // File information classes
    public static final int FILE_DIRECTORY_INFO = 1;
    public static final int FILE_FULL_DIRECTORY_INFO = 2;
    public static final int FILE_BOTH_DIRECTORY_INFO = 3;
    public static final int FILE_BASIC_INFO = 4;
    public static final int FILE_STANDARD_INFO = 5;
    public static final int FILE_INTERNAL_INFO = 6;
    public static final int FILE_EA_INFO = 7;
    public static final int FILE_ACCESS_INFO = 8;
    public static final int FILE_NAME_INFO = 9;
    public static final int FILE_RENAME_INFO = 10;
    public static final int FILE_LINK_INFO = 11;
    public static final int FILE_NAMES_INFO = 12;
    public static final int FILE_DISPOSITION_INFO = 13;
    public static final int FILE_POSITION_INFO = 14;
    public static final int FILE_FULL_EA_INFO = 15;
    public static final int FILE_MODE_INFO = 16;
    public static final int FILE_ALIGNMENT_INFO = 17;
    public static final int FILE_ALL_INFO = 18;
    public static final int FILE_ALLOCATION_INFO = 19;
    public static final int FILE_END_OF_FILE_INFO = 20;
    public static final int FILE_ALTERNATE_NAME_INFO = 21;
    public static final int FILE_STREAM_INFO = 22;
    public static final int FILE_PIPE_INFO = 23;
    public static final int FILE_PIPE_LOCAL_INFO = 24;
    public static final int FILE_COMPRESSION_INFO = 28;
    public static final int FILE_NETWORK_OPEN_INFO = 34;
    public static final int FILE_ATTRIBUTE_TAG_INFO = 35;
    public static final int FILE_ID_BOTH_DIRECTORY_INFO = 37;
    public static final int FILE_ID_FULL_DIRECTORY_INFO = 38;
    public static final int FILE_VALID_DATA_LENGTH_INFO = 39;
    public static final int FILE_NORMALIZED_NAME_INFO = 48;
    public static final int FILE_ID_INFO = 59;
    public static final int FILE_DISPOSITION_INFO_EX = 64;
    public static final int FILE_RENAME_INFO_EX = 65;

    // Filesystem information classes
    public static final int FS_VOLUME_INFO = 1;
    public static final int FS_LABEL_INFO = 2;
    public static final int FS_SIZE_INFO = 3;
    public static final int FS_DEVICE_INFO = 4;
    public static final int FS_ATTRIBUTE_INFO = 5;
    public static final int FS_CONTROL_INFO = 6;
    public static final int FS_FULL_SIZE_INFO = 7;
    public static final int FS_OBJECT_ID_INFO = 8;
    public static final int FS_SECTOR_SIZE_INFO = 11;

    // Security information flags
    public static final int SECINFO_OWNER = 0x01;
    public static final int SECINFO_GROUP = 0x02;
    public static final int SECINFO_DACL = 0x04;
    public static final int SECINFO_SACL = 0x08;

    // IOCTL / FSCTL codes
    public static final int IOCTL_FLAG_IS_FSCTL = 0x00000001;

    public static final int FSCTL_DFS_GET_REFERRALS = 0x00060194;
    public static final int FSCTL_DFS_GET_REFERRALS_EX = 0x000601B0;
    public static final int FSCTL_PIPE_PEEK = 0x0011400C;
    public static final int FSCTL_PIPE_WAIT = 0x00110018;
    public static final int FSCTL_PIPE_TRANSCEIVE = 0x0011C017;
    public static final int FSCTL_SRV_COPYCHUNK = 0x001440F2;
    public static final int FSCTL_SRV_COPYCHUNK_WRITE = 0x001480F2;
    public static final int FSCTL_SRV_REQUEST_RESUME_KEY = 0x00140078;
    public static final int FSCTL_SRV_ENUMERATE_SNAPSHOTS = 0x00144064;
    public static final int FSCTL_QUERY_NETWORK_INTERFACE_INFO = 0x001401FC;
    public static final int FSCTL_VALIDATE_NEGOTIATE_INFO = 0x00140204;
    public static final int FSCTL_CREATE_OR_GET_OBJECT_ID = 0x000900C0;
    public static final int FSCTL_GET_REPARSE_POINT = 0x000900A8;
    public static final int FSCTL_SET_SPARSE = 0x000900C4;
    public static final int FSCTL_QUERY_ALLOCATED_RANGES = 0x000940CF;
    public static final int FSCTL_SET_ZERO_DATA = 0x000980C8;

    // Lock flags
    public static final int LOCK_SHARED = 0x01;
    public static final int LOCK_EXCLUSIVE = 0x02;
    public static final int LOCK_UNLOCK = 0x04;
    public static final int LOCK_FAIL_IMMEDIATELY = 0x10;

    // NT status codes
    public static final int STATUS_SUCCESS = 0x00000000;
    public static final int STATUS_PENDING = 0x00000103;
    public static final int STATUS_NOTIFY_CLEANUP = 0x0000010B;
    public static final int STATUS_NOTIFY_ENUM_DIR = 0x0000010C;
    public static final int STATUS_BUFFER_OVERFLOW = 0x80000005;
    public static final int STATUS_NO_MORE_FILES = 0x80000006;
    public static final int STATUS_UNSUCCESSFUL = 0xC0000001;
    public static final int STATUS_NOT_IMPLEMENTED = 0xC0000002;
    public static final int STATUS_INVALID_INFO_CLASS = 0xC0000003;
    public static final int STATUS_INFO_LENGTH_MISMATCH = 0xC0000004;
    public static final int STATUS_INVALID_HANDLE = 0xC0000008;
    public static final int STATUS_INVALID_PARAMETER = 0xC000000D;
    public static final int STATUS_NO_SUCH_FILE = 0xC000000F;
    public static final int STATUS_INVALID_DEVICE_REQUEST = 0xC0000010;
    public static final int STATUS_END_OF_FILE = 0xC0000011;
    public static final int STATUS_MORE_PROCESSING_REQUIRED = 0xC0000016;
    public static final int STATUS_ACCESS_DENIED = 0xC0000022;
    public static final int STATUS_BUFFER_TOO_SMALL = 0xC0000023;
    public static final int STATUS_OBJECT_NAME_INVALID = 0xC0000033;
    public static final int STATUS_OBJECT_NAME_NOT_FOUND = 0xC0000034;
    public static final int STATUS_OBJECT_NAME_COLLISION = 0xC0000035;
    public static final int STATUS_OBJECT_PATH_NOT_FOUND = 0xC000003A;
    public static final int STATUS_SHARING_VIOLATION = 0xC0000043;
    public static final int STATUS_EAS_NOT_SUPPORTED = 0xC000004F;
    public static final int STATUS_FILE_LOCK_CONFLICT = 0xC0000054;
    public static final int STATUS_LOCK_NOT_GRANTED = 0xC0000055;
    public static final int STATUS_DELETE_PENDING = 0xC0000056;
    public static final int STATUS_LOGON_FAILURE = 0xC000006D;
    public static final int STATUS_RANGE_NOT_LOCKED = 0xC000007E;
    public static final int STATUS_DISK_FULL = 0xC000007F;
    public static final int STATUS_INSUFFICIENT_RESOURCES = 0xC000009A;
    public static final int STATUS_MEDIA_WRITE_PROTECTED = 0xC00000A2;
    public static final int STATUS_FILE_IS_A_DIRECTORY = 0xC00000BA;
    public static final int STATUS_NOT_SUPPORTED = 0xC00000BB;
    public static final int STATUS_NETWORK_NAME_DELETED = 0xC00000C9;
    public static final int STATUS_BAD_NETWORK_NAME = 0xC00000CC;
    public static final int STATUS_REQUEST_NOT_ACCEPTED = 0xC00000D0;
    public static final int STATUS_NOT_SAME_DEVICE = 0xC00000D4;
    public static final int STATUS_INTERNAL_ERROR = 0xC00000E5;
    public static final int STATUS_DIRECTORY_NOT_EMPTY = 0xC0000101;
    public static final int STATUS_NOT_A_DIRECTORY = 0xC0000103;
    public static final int STATUS_CANCELLED = 0xC0000120;
    public static final int STATUS_CANNOT_DELETE = 0xC0000121;
    public static final int STATUS_FILE_CLOSED = 0xC0000128;
    public static final int STATUS_TOO_MANY_OPENED_FILES = 0xC000011F;
    public static final int STATUS_FS_DRIVER_REQUIRED = 0xC000019C;
    public static final int STATUS_USER_SESSION_DELETED = 0xC0000203;
    public static final int STATUS_NOT_FOUND = 0xC0000225;
    public static final int STATUS_INVALID_NETWORK_RESPONSE = 0xC00000C3;

    /**
     * Check if an NT status is an error severity code
     *
     * @param sts int
     * @return boolean
     */
    public static boolean isError(int sts) {
        return (sts & 0xC0000000) == 0xC0000000;
    }
}
