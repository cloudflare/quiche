use std::cmp;
use std::fmt::Debug;
use std::marker::PhantomData;
use std::ops::Deref;
use std::sync::Arc;

/// Buffer holding data at a specific offset.
///
/// The data is stored in a `Vec<u8>` in such a way that it can be shared
/// between multiple `RangeBuf` objects.
///
/// Each `RangeBuf` will have its own view of that buffer, where the `start`
/// value indicates the initial offset within the `Vec`, and `len` indicates the
/// number of bytes, starting from `start` that are included.
///
/// In addition, `pos` indicates the current offset within the `Vec`, starting
/// from the very beginning of the `Vec`.
///
/// Finally, `off` is the starting offset for the specific `RangeBuf` within the
/// stream the buffer belongs to.
#[derive(Clone, Debug, Default)]
pub struct RangeBuf<F = DefaultBufFactory>
where
    F: BufFactory,
{
    /// The internal buffer holding the data.
    ///
    /// To avoid needless allocations when a RangeBuf is split, this field
    /// should be reference-counted so it can be shared between multiple
    /// RangeBuf objects, and sliced using the `start` and `len` values.
    pub(crate) data: F::Buf,

    /// The initial offset within the internal buffer.
    pub(crate) start: usize,

    /// The current offset within the internal buffer.
    pub(crate) pos: usize,

    /// The number of bytes in the buffer, from the initial offset.
    pub(crate) len: usize,

    /// The offset of the buffer within a stream.
    pub(crate) off: u64,

    /// Whether this contains the final byte in the stream.
    pub(crate) fin: bool,

    _bf: PhantomData<F>,
}

/// A trait for providing internal storage buffers for [`RangeBuf`].
/// The associated type [`Buf`] can be any type that dereferences to
/// a slice, but should be fast to clone, eg. by wrapping it into an
/// [`Arc`].
pub trait BufFactory: Clone + Default + Debug {
    /// The type of the generated buffer.
    type Buf: Clone + Debug + AsRef<[u8]>;

    /// Generate a new buffer from a given slice, the buffer must contain the
    /// same data as the original slice.
    fn buf_from_slice(buf: &[u8]) -> Self::Buf;
}

/// The default [`BufFactory`] allocates buffers on the heap on demand.
#[derive(Debug, Clone, Default)]
pub struct DefaultBufFactory;

/// The default [`BufFactory::Buf`] is a boxes slices wrapped in an [`Arc`].
#[derive(Debug, Clone, Default)]
pub struct DefaultBuf(Arc<Box<[u8]>>);

impl BufFactory for DefaultBufFactory {
    type Buf = DefaultBuf;

    fn buf_from_slice(buf: &[u8]) -> Self::Buf {
        DefaultBuf(Arc::new(buf.into()))
    }
}

impl AsRef<[u8]> for DefaultBuf {
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}

impl<F: BufFactory> RangeBuf<F>
where
    F::Buf: Clone,
{
    /// Creates a new `RangeBuf` from the given slice.
    pub fn from(buf: &[u8], off: u64, fin: bool) -> RangeBuf<F> {
        RangeBuf {
            data: F::buf_from_slice(buf),
            start: 0,
            pos: 0,
            len: buf.len(),
            off,
            fin,
            _bf: Default::default(),
        }
    }

    /// Returns whether `self` holds the final offset in the stream.
    pub fn fin(&self) -> bool {
        self.fin
    }

    /// Returns the starting offset of `self`.
    pub fn off(&self) -> u64 {
        (self.off - self.start as u64) + self.pos as u64
    }

    /// Returns the final offset of `self`.
    pub fn max_off(&self) -> u64 {
        self.off() + self.len() as u64
    }

    /// Returns the length of `self`.
    pub fn len(&self) -> usize {
        self.len - (self.pos - self.start)
    }

    /// Returns true if `self` has a length of zero bytes.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Consumes the starting `count` bytes of `self`.
    pub fn consume(&mut self, count: usize) {
        self.pos += count;
    }

    /// Splits the buffer into two at the given index.
    pub fn split_off(&mut self, at: usize) -> RangeBuf<F>
    where
        F::Buf: Clone + AsRef<[u8]>,
    {
        assert!(
            at <= self.len,
            "`at` split index (is {}) should be <= len (is {})",
            at,
            self.len
        );

        let buf = RangeBuf {
            data: self.data.clone(),
            start: self.start + at,
            pos: cmp::max(self.pos, self.start + at),
            len: self.len - at,
            off: self.off + at as u64,
            _bf: Default::default(),
            fin: self.fin,
        };

        self.pos = cmp::min(self.pos, self.start + at);
        self.len = at;
        self.fin = false;

        buf
    }
}

impl<F: BufFactory> Deref for RangeBuf<F> {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.data.as_ref()[self.pos..self.start + self.len]
    }
}

impl<F: BufFactory> Ord for RangeBuf<F> {
    fn cmp(&self, other: &RangeBuf<F>) -> cmp::Ordering {
        // Invert ordering to implement min-heap.
        self.off.cmp(&other.off).reverse()
    }
}

impl<F: BufFactory> PartialOrd for RangeBuf<F> {
    fn partial_cmp(&self, other: &RangeBuf<F>) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<F: BufFactory> Eq for RangeBuf<F> {}

impl<F: BufFactory> PartialEq for RangeBuf<F> {
    fn eq(&self, other: &RangeBuf<F>) -> bool {
        self.off == other.off
    }
}
