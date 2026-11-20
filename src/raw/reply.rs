//! reply structures.
use std::ffi::OsString;
use std::num::NonZeroU32;
use std::time::Duration;

use bytes::Bytes;
use futures_util::stream::Stream;

use crate::helper::mode_from_kind_and_perm;
use crate::mount_options::DEFAULT_MAX_WRITE;
use crate::raw::abi::{
    fuse_attr, fuse_attr_out, fuse_bmap_out, fuse_entry_out, fuse_kstatfs, fuse_lseek_out,
    fuse_open_out, fuse_poll_out, fuse_statfs_out, fuse_statx, fuse_statx_out, fuse_sx_time,
    fuse_write_out, STATX_BASIC_STATS, STATX_BTIME,
};
#[cfg(feature = "file-lock")]
use crate::raw::abi::{fuse_file_lock, fuse_lk_out};
use crate::{FileType, Result, Timestamp};

/// file attributes
#[derive(Clone, Copy, Debug, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct FileAttr {
    /// Inode number
    pub ino: u64,
    /// Size in bytes
    pub size: u64,
    /// Size in blocks
    pub blocks: u64,
    /// Time of last access
    pub atime: Timestamp,
    /// Time of last modification
    pub mtime: Timestamp,
    /// Time of last change
    pub ctime: Timestamp,
    #[cfg(target_os = "macos")]
    /// Time of creation (macOS only)
    pub crtime: Timestamp,
    /// Kind of file (directory, file, pipe, etc)
    pub kind: FileType,
    /// Permissions
    pub perm: u16,
    /// Number of hard links
    pub nlink: u32,
    /// User id
    pub uid: u32,
    /// Group id
    pub gid: u32,
    /// Rdev
    pub rdev: u32,
    #[cfg(target_os = "macos")]
    /// Flags (macOS only, see chflags(2))
    pub flags: u32,
    pub blksize: u32,
}

impl From<FileAttr> for fuse_attr {
    fn from(attr: FileAttr) -> Self {
        fuse_attr {
            ino: attr.ino,
            size: attr.size,
            blocks: attr.blocks,
            // NB: fuse_kernel.h defines the seconds fields as "uint64_t", but
            // they actually get cast to time_t (e.g. int64_t) inside the
            // kernel.
            atime: attr.atime.sec as u64,
            mtime: attr.mtime.sec as u64,
            ctime: attr.ctime.sec as u64,
            #[cfg(target_os = "macos")]
            crtime: attr.crtime.sec as u64,
            atimensec: attr.atime.nsec,
            mtimensec: attr.mtime.nsec,
            ctimensec: attr.ctime.nsec,
            #[cfg(target_os = "macos")]
            crtimensec: attr.crtime.nsec,
            mode: mode_from_kind_and_perm(attr.kind, attr.perm),
            nlink: attr.nlink,
            uid: attr.uid,
            gid: attr.gid,
            rdev: attr.rdev,
            blksize: attr.blksize,
            #[cfg(target_os = "macos")]
            flags: attr.flags,
            _padding: 0,
        }
    }
}

#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
/// init reply.
pub struct ReplyInit {
    /// Maximum size of write requests.
    pub max_write: NonZeroU32,
}

impl Default for ReplyInit {
    fn default() -> Self {
        Self {
            max_write: NonZeroU32::new(DEFAULT_MAX_WRITE).expect("default max_write is non-zero"),
        }
    }
}

#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
/// entry reply.
pub struct ReplyEntry {
    /// the attribute TTL.
    pub ttl: Duration,
    /// the attribute.
    pub attr: FileAttr,
    /// the generation.
    pub generation: u64,
}

impl From<ReplyEntry> for fuse_entry_out {
    fn from(entry: ReplyEntry) -> Self {
        let attr = entry.attr;

        fuse_entry_out {
            nodeid: attr.ino,
            generation: entry.generation,
            entry_valid: entry.ttl.as_secs(),
            attr_valid: entry.ttl.as_secs(),
            entry_valid_nsec: entry.ttl.subsec_nanos(),
            attr_valid_nsec: entry.ttl.subsec_nanos(),
            attr: attr.into(),
        }
    }
}

#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
/// reply attr.
pub struct ReplyAttr {
    /// the attribute TTL.
    pub ttl: Duration,
    /// the attribute.
    pub attr: FileAttr,
}

impl From<ReplyAttr> for fuse_attr_out {
    fn from(attr: ReplyAttr) -> Self {
        fuse_attr_out {
            attr_valid: attr.ttl.as_secs(),
            attr_valid_nsec: attr.ttl.subsec_nanos(),
            dummy: 0,
            attr: attr.attr.into(),
        }
    }
}

#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
/// statx reply.
pub struct ReplyStatx {
    /// the attribute TTL.
    pub ttl: Duration,
    /// the attribute.
    pub attr: FileAttr,
    /// the birth time, or `None` when the filesystem doesn't keep one.
    pub btime: Option<Timestamp>,
}

impl From<ReplyStatx> for fuse_statx_out {
    fn from(reply: ReplyStatx) -> Self {
        let attr = reply.attr;
        let mode = fuse_attr::from(attr).mode;
        let mut mask = STATX_BASIC_STATS;
        if reply.btime.is_some() {
            mask |= STATX_BTIME;
        }
        let time = |t: Timestamp| fuse_sx_time {
            tv_sec: t.sec,
            tv_nsec: t.nsec,
            _reserved: 0,
        };
        // FileAttr.rdev is the kernel's new_encode_dev() form, as in fuse_attr.
        let rdev = attr.rdev;
        fuse_statx_out {
            attr_valid: reply.ttl.as_secs(),
            attr_valid_nsec: reply.ttl.subsec_nanos(),
            flags: 0,
            _spare: [0; 2],
            stat: fuse_statx {
                mask,
                blksize: attr.blksize,
                attributes: 0,
                nlink: attr.nlink,
                uid: attr.uid,
                gid: attr.gid,
                mode: mode as u16,
                _spare0: 0,
                ino: attr.ino,
                size: attr.size,
                blocks: attr.blocks,
                attributes_mask: 0,
                atime: time(attr.atime),
                btime: reply.btime.map(time).unwrap_or_default(),
                ctime: time(attr.ctime),
                mtime: time(attr.mtime),
                rdev_major: (rdev >> 8) & 0xfff,
                rdev_minor: (rdev & 0xff) | ((rdev >> 12) & 0xfff00),
                dev_major: 0,
                dev_minor: 0,
                _spare2: [0; 14],
            },
        }
    }
}

#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
/// data reply.
pub struct ReplyData {
    /// the data.
    pub data: Bytes,
}

impl From<Bytes> for ReplyData {
    fn from(data: Bytes) -> Self {
        Self { data }
    }
}

#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
/// open reply.
pub struct ReplyOpen {
    /// the file handle id.
    ///
    /// # Notes:
    ///
    /// if set fh 0, means use stateless IO.
    pub fh: u64,
    /// the flags.
    pub flags: u32,
}

impl From<ReplyOpen> for fuse_open_out {
    fn from(opened: ReplyOpen) -> Self {
        fuse_open_out {
            fh: opened.fh,
            open_flags: opened.flags,
            _padding: 0,
        }
    }
}

#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
/// write reply.
pub struct ReplyWrite {
    /// the data written.
    pub written: u32,
}

impl From<ReplyWrite> for fuse_write_out {
    fn from(written: ReplyWrite) -> Self {
        fuse_write_out {
            size: written.written,
            _padding: 0,
        }
    }
}

#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
/// statfs reply.
pub struct ReplyStatFs {
    /// the number of blocks in the filesystem.
    pub blocks: u64,
    /// the number of free blocks.
    pub bfree: u64,
    /// the number of free blocks for non-priviledge users.
    pub bavail: u64,
    /// the number of inodes.
    pub files: u64,
    /// the number of free inodes.
    pub ffree: u64,
    /// the block size.
    pub bsize: u32,
    /// the maximum length of file name.
    pub namelen: u32,
    /// the fragment size.
    pub frsize: u32,
}

impl From<ReplyStatFs> for fuse_statfs_out {
    fn from(stat_fs: ReplyStatFs) -> Self {
        fuse_statfs_out {
            st: fuse_kstatfs {
                blocks: stat_fs.blocks,
                bfree: stat_fs.bfree,
                bavail: stat_fs.bavail,
                files: stat_fs.files,
                ffree: stat_fs.ffree,
                bsize: stat_fs.bsize,
                namelen: stat_fs.namelen,
                frsize: stat_fs.frsize,
                _padding: 0,
                spare: [0; 6],
            },
        }
    }
}

#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
/// xattr reply.
pub enum ReplyXAttr {
    Size(u32),
    Data(Bytes),
}

#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
/// directory entry.
pub struct DirectoryEntry {
    /// entry inode.
    pub inode: u64,
    /// entry kind.
    pub kind: FileType,
    /// entry name.
    pub name: OsString,
    /// Directory offset of the _next_ entry
    pub offset: i64,
}

/// readdir reply.
pub struct ReplyDirectory<S: Stream<Item = Result<DirectoryEntry>>> {
    pub entries: S,
}

impl<S: Stream<Item = Result<DirectoryEntry>> + std::fmt::Debug> std::fmt::Debug
    for ReplyDirectory<S>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReplyDirectory")
            .field("entries", &self.entries)
            .finish()
    }
}

#[cfg(feature = "file-lock")]
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
/// file lock reply.
pub struct ReplyLock {
    /// starting offset for lock.
    pub start: u64,
    /// end offset for lock.
    pub end: u64,
    /// type of lock, such as: [`F_RDLCK`], [`F_WRLCK`] and [`F_UNLCK`]
    ///
    /// [`F_RDLCK`]: libc::F_RDLCK
    /// [`F_WRLCK`]: libc::F_WRLCK
    /// [`F_UNLCK`]: libc::F_UNLCK
    pub r#type: u32,
    /// PID of process blocking our lock
    pub pid: u32,
}

#[cfg(feature = "file-lock")]
impl From<ReplyLock> for fuse_lk_out {
    fn from(lock: ReplyLock) -> Self {
        fuse_lk_out {
            lk: fuse_file_lock {
                start: lock.start,
                end: lock.end,
                r#type: lock.r#type,
                pid: lock.pid,
            },
        }
    }
}

#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
/// crate reply.
pub struct ReplyCreated {
    /// the attribute TTL.
    pub ttl: Duration,
    /// the attribute of file.
    pub attr: FileAttr,
    /// the generation of file.
    pub generation: u64,
    /// the file handle.
    pub fh: u64,
    /// the flags.
    pub flags: u32,
}

impl From<ReplyCreated> for (fuse_entry_out, fuse_open_out) {
    fn from(created: ReplyCreated) -> Self {
        let attr = created.attr;

        let entry_out = fuse_entry_out {
            nodeid: attr.ino,
            generation: created.generation,
            entry_valid: created.ttl.as_secs(),
            attr_valid: created.ttl.as_secs(),
            entry_valid_nsec: created.ttl.subsec_micros(),
            attr_valid_nsec: created.ttl.subsec_micros(),
            attr: attr.into(),
        };

        let open_out = fuse_open_out {
            fh: created.fh,
            open_flags: created.flags,
            _padding: 0,
        };

        (entry_out, open_out)
    }
}

#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
// TODO need more detail
/// bmap reply.
pub struct ReplyBmap {
    pub block: u64,
}

impl From<ReplyBmap> for fuse_bmap_out {
    fn from(bmap: ReplyBmap) -> Self {
        fuse_bmap_out { block: bmap.block }
    }
}

#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct ReplyIoctl {
    pub result: i32,
    pub flags: u32,
    pub in_iovs: u32,
    pub out_iovs: u32,
    pub data: Vec<u8>,
}

#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
// TODO need more detail
/// poll reply
pub struct ReplyPoll {
    pub revents: u32,
}

impl From<ReplyPoll> for fuse_poll_out {
    fn from(poll: ReplyPoll) -> Self {
        fuse_poll_out {
            revents: poll.revents,
            _padding: 0,
        }
    }
}

#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
/// directory entry with attribute
pub struct DirectoryEntryPlus {
    /// the entry inode.
    pub inode: u64,
    /// the entry generation.
    pub generation: u64,
    /// the entry kind.
    pub kind: FileType,
    /// the entry name.
    pub name: OsString,
    /// Directory offset of the _next_ entry
    pub offset: i64,
    /// the entry attribute.
    pub attr: FileAttr,
    /// the entry TTL.
    pub entry_ttl: Duration,
    /// the attribute TTL.
    pub attr_ttl: Duration,
}

/// the readdirplus reply.
pub struct ReplyDirectoryPlus<S: Stream<Item = Result<DirectoryEntryPlus>>> {
    pub entries: S,
}

impl<S: Stream<Item = Result<DirectoryEntryPlus>> + std::fmt::Debug> std::fmt::Debug
    for ReplyDirectoryPlus<S>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReplyDirectoryPlus")
            .field("entries", &self.entries)
            .finish()
    }
}

#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
/// the lseek reply.
pub struct ReplyLSeek {
    /// lseek offset.
    pub offset: u64,
}

impl From<ReplyLSeek> for fuse_lseek_out {
    fn from(seek: ReplyLSeek) -> Self {
        fuse_lseek_out {
            offset: seek.offset,
        }
    }
}

#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
/// copy_file_range reply.
pub struct ReplyCopyFileRange {
    /// data copied size.
    pub copied: u64,
}

impl From<ReplyCopyFileRange> for fuse_write_out {
    fn from(copied: ReplyCopyFileRange) -> Self {
        fuse_write_out {
            size: copied.copied as u32,
            _padding: 0,
        }
    }
}

#[cfg(target_os = "macos")]
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
/// macOS GETXTIMES reply: backup and create timestamps.
pub struct ReplyXTimes {
    /// Backup time.
    pub bkuptime: Timestamp,
    /// Creation time.
    pub crtime: Timestamp,
}

#[cfg(target_os = "macos")]
impl From<ReplyXTimes> for crate::raw::abi::fuse_getxtimes_out {
    fn from(t: ReplyXTimes) -> Self {
        crate::raw::abi::fuse_getxtimes_out {
            bkuptime: t.bkuptime.sec as u64,
            crtime: t.crtime.sec as u64,
            bkuptimensec: t.bkuptime.nsec,
            crtimensec: t.crtime.nsec,
        }
    }
}

#[cfg(test)]
mod tests {
    use bincode::Options;

    use super::*;
    use crate::helper::get_bincode_config;
    use crate::raw::abi::{fuse_opcode, fuse_statx_in, FUSE_STATX_OUT_SIZE};

    fn attr(kind: FileType, rdev: u32) -> FileAttr {
        FileAttr {
            ino: 7,
            size: 5,
            blocks: 1,
            atime: Timestamp::new(10, 1),
            mtime: Timestamp::new(20, 2),
            ctime: Timestamp::new(30, 3),
            #[cfg(target_os = "macos")]
            crtime: Timestamp::new(0, 0),
            kind,
            perm: 0o640,
            nlink: 1,
            uid: 1000,
            gid: 100,
            rdev,
            #[cfg(target_os = "macos")]
            flags: 0,
            blksize: 4096,
        }
    }

    fn encode(reply: ReplyStatx) -> Vec<u8> {
        let out: fuse_statx_out = reply.into();
        get_bincode_config().serialize(&out).unwrap()
    }

    fn u32_at(data: &[u8], at: usize) -> u32 {
        u32::from_le_bytes(data[at..at + 4].try_into().unwrap())
    }

    fn i64_at(data: &[u8], at: usize) -> i64 {
        i64::from_le_bytes(data[at..at + 8].try_into().unwrap())
    }

    // Offsets are those of struct fuse_statx_out in include/uapi/linux/fuse.h:
    // 32 bytes of header, then struct fuse_statx.
    #[test]
    fn statx_reply_has_the_kernel_layout() {
        let data = encode(ReplyStatx {
            ttl: Duration::new(1, 5),
            attr: attr(FileType::RegularFile, 0),
            btime: Some(Timestamp::new(1_600_000_000, 7)),
        });
        assert_eq!(data.len(), 288);
        assert_eq!(FUSE_STATX_OUT_SIZE, 288);
        assert_eq!(i64_at(&data, 0), 1);
        assert_eq!(u32_at(&data, 8), 5);
        assert_eq!(u32_at(&data, 32), STATX_BASIC_STATS | STATX_BTIME);
        assert_eq!(u32_at(&data, 36), 4096);
        assert_eq!(u32_at(&data, 52), 1000);
        assert_eq!(
            u16::from_le_bytes([data[60], data[61]]),
            (libc::S_IFREG | 0o640) as u16
        );
        assert_eq!(i64_at(&data, 64), 7);
        assert_eq!(i64_at(&data, 32 + 64), 10);
        assert_eq!(i64_at(&data, 32 + 80), 1_600_000_000);
        assert_eq!(u32_at(&data, 32 + 88), 7);
        assert_eq!(i64_at(&data, 32 + 96), 30);
        assert_eq!(i64_at(&data, 32 + 112), 20);
    }

    #[test]
    fn statx_reply_without_btime_leaves_it_out() {
        let data = encode(ReplyStatx {
            ttl: Duration::ZERO,
            attr: attr(FileType::Directory, 0),
            btime: None,
        });
        assert_eq!(u32_at(&data, 32), STATX_BASIC_STATS);
        assert_eq!(i64_at(&data, 32 + 80), 0);
    }

    #[test]
    fn statx_reply_splits_rdev() {
        let (major, minor) = (4u32, 300u32);
        let rdev = (minor & 0xff) | (major << 8) | ((minor & !0xff) << 12);
        let data = encode(ReplyStatx {
            ttl: Duration::ZERO,
            attr: attr(FileType::CharDevice, rdev),
            btime: None,
        });
        assert_eq!(u32_at(&data, 32 + 128), major);
        assert_eq!(u32_at(&data, 32 + 132), minor);
    }

    #[test]
    fn statx_request_parses() {
        assert!(matches!(
            fuse_opcode::try_from(52),
            Ok(fuse_opcode::FUSE_STATX)
        ));
        let mut data = Vec::new();
        for word in [1u32, 0] {
            data.extend_from_slice(&word.to_le_bytes());
        }
        data.extend_from_slice(&9u64.to_le_bytes());
        for word in [0u32, STATX_BASIC_STATS | STATX_BTIME] {
            data.extend_from_slice(&word.to_le_bytes());
        }
        let statx_in: fuse_statx_in = get_bincode_config().deserialize(&data).unwrap();
        assert_eq!(statx_in.getattr_flags, 1);
        assert_eq!(statx_in.fh, 9);
        assert_eq!(statx_in.sx_mask, 0xfff);
    }
}
