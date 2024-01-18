use futures_core::ready;
use futures_io::{AsyncRead, AsyncWrite};
#[cfg(feature = "early-data")]
use rustls::client::WriteEarlyData;
use rustls::{ClientConnection, IoState, Reader, ServerConnection, Writer};
use std::io::{self, Read, Write};
use std::marker::Unpin;
use std::pin::Pin;
use std::task::{Context, Poll};

pub struct Stream<'a, IO> {
    pub io: &'a mut IO,
    pub conn: Conn<'a>,
    pub eof: bool,
}

pub(crate) enum Conn<'a> {
    Client(&'a mut ClientConnection),
    Server(&'a mut ServerConnection),
}

impl Conn<'_> {
    pub(crate) fn is_handshaking(&self) -> bool {
        match self {
            Conn::Client(c) => c.is_handshaking(),
            Conn::Server(c) => c.is_handshaking(),
        }
    }

    pub(crate) fn wants_write(&self) -> bool {
        match self {
            Conn::Client(c) => c.wants_write(),
            Conn::Server(c) => c.wants_write(),
        }
    }

    pub(crate) fn wants_read(&self) -> bool {
        match self {
            Conn::Client(c) => c.wants_read(),
            Conn::Server(c) => c.wants_read(),
        }
    }

    pub(crate) fn write_tls(&mut self, wr: &mut dyn io::Write) -> Result<usize, io::Error> {
        match self {
            Conn::Client(c) => c.write_tls(wr),
            Conn::Server(c) => c.write_tls(wr),
        }
    }

    pub(crate) fn reader(&mut self) -> Reader {
        match self {
            Conn::Client(c) => c.reader(),
            Conn::Server(c) => c.reader(),
        }
    }

    pub(crate) fn writer(&mut self) -> Writer {
        match self {
            Conn::Client(c) => c.writer(),
            Conn::Server(c) => c.writer(),
        }
    }

    pub(crate) fn send_close_notify(&mut self) {
        match self {
            Conn::Client(c) => c.send_close_notify(),
            Conn::Server(c) => c.send_close_notify(),
        }
    }

    pub(crate) fn read_tls(&mut self, rd: &mut dyn io::Read) -> Result<usize, io::Error> {
        match self {
            Conn::Client(c) => c.read_tls(rd),
            Conn::Server(c) => c.read_tls(rd),
        }
    }

    pub(crate) fn process_new_packets(&mut self) -> Result<IoState, rustls::Error> {
        match self {
            Conn::Client(c) => c.process_new_packets(),
            Conn::Server(c) => c.process_new_packets(),
        }
    }

    #[cfg(feature = "early-data")]
    pub(crate) fn is_early_data_accepted(&self) -> bool {
        match self {
            Conn::Client(c) => c.is_early_data_accepted(),
            Conn::Server(_) => false,
        }
    }

    #[cfg(feature = "early-data")]
    pub(crate) fn client_early_data(&mut self) -> Option<WriteEarlyData<'_>> {
        match self {
            Conn::Client(c) => c.early_data(),
            Conn::Server(_) => None,
        }
    }
}

impl<'a> From<&'a mut ClientConnection> for Conn<'a> {
    fn from(conn: &'a mut ClientConnection) -> Self {
        Conn::Client(conn)
    }
}

impl<'a> From<&'a mut ServerConnection> for Conn<'a> {
    fn from(conn: &'a mut ServerConnection) -> Self {
        Conn::Server(conn)
    }
}

trait WriteTls<IO: AsyncWrite> {
    fn write_tls(&mut self, cx: &mut Context) -> io::Result<usize>;
}

#[derive(Clone, Copy)]
enum Focus {
    Empty,
    Readable,
    Writable,
}

impl<'a, IO: AsyncRead + AsyncWrite + Unpin> Stream<'a, IO> {
    pub fn new(io: &'a mut IO, conn: impl Into<Conn<'a>>) -> Self {
        Stream {
            io,
            conn: conn.into(),
            // The state so far is only used to detect EOF, so either Stream
            // or EarlyData state should both be all right.
            eof: false,
        }
    }

    pub fn set_eof(mut self, eof: bool) -> Self {
        self.eof = eof;
        self
    }

    pub fn as_mut_pin(&mut self) -> Pin<&mut Self> {
        Pin::new(self)
    }

    pub fn complete_io(&mut self, cx: &mut Context) -> Poll<io::Result<(usize, usize)>> {
        self.complete_inner_io(cx, Focus::Empty)
    }

    fn complete_read_io(&mut self, cx: &mut Context) -> Poll<io::Result<usize>> {
        struct Reader<'a, 'b, T> {
            io: &'a mut T,
            cx: &'a mut Context<'b>,
        }

        impl<'a, 'b, T: AsyncRead + Unpin> Read for Reader<'a, 'b, T> {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                match Pin::new(&mut self.io).poll_read(self.cx, buf) {
                    Poll::Ready(result) => result,
                    Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
                }
            }
        }

        let mut reader = Reader { io: self.io, cx };

        let n = match self.conn.read_tls(&mut reader) {
            Ok(n) => n,
            Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => return Poll::Pending,
            Err(err) => return Poll::Ready(Err(err)),
        };

        self.conn.process_new_packets().map_err(|err| {
            // In case we have an alert to send describing this error,
            // try a last-gasp write -- but don't predate the primary
            // error.
            let _ = self.write_tls(cx);

            io::Error::new(io::ErrorKind::InvalidData, err)
        })?;

        Poll::Ready(Ok(n))
    }

    fn complete_write_io(&mut self, cx: &mut Context) -> Poll<io::Result<usize>> {
        match self.write_tls(cx) {
            Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => Poll::Pending,
            result => Poll::Ready(result),
        }
    }

    fn complete_inner_io(
        &mut self,
        cx: &mut Context,
        focus: Focus,
    ) -> Poll<io::Result<(usize, usize)>> {
        let mut wrlen = 0;
        let mut rdlen = 0;

        loop {
            let mut write_would_block = false;
            let mut read_would_block = false;

            while self.conn.wants_write() {
                match self.complete_write_io(cx) {
                    Poll::Ready(Ok(n)) => wrlen += n,
                    Poll::Pending => {
                        write_would_block = true;
                        break;
                    }
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                }
            }

            if !self.eof && self.conn.wants_read() {
                match self.complete_read_io(cx) {
                    Poll::Ready(Ok(0)) => self.eof = true,
                    Poll::Ready(Ok(n)) => rdlen += n,
                    Poll::Pending => read_would_block = true,
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                }
            }

            let would_block = match focus {
                Focus::Empty => write_would_block || read_would_block,
                Focus::Readable => read_would_block,
                Focus::Writable => write_would_block,
            };

            match (self.eof, self.conn.is_handshaking(), would_block) {
                (true, true, _) => {
                    let err = io::Error::new(io::ErrorKind::UnexpectedEof, "tls handshake eof");
                    return Poll::Ready(Err(err));
                }
                (_, false, true) => {
                    let would_block = match focus {
                        Focus::Empty => rdlen == 0 && wrlen == 0,
                        Focus::Readable => rdlen == 0,
                        Focus::Writable => wrlen == 0,
                    };

                    return if would_block {
                        Poll::Pending
                    } else {
                        Poll::Ready(Ok((rdlen, wrlen)))
                    };
                }
                (_, false, _) => return Poll::Ready(Ok((rdlen, wrlen))),
                (_, true, true) => return Poll::Pending,
                (..) => (),
            }
        }
    }
}

impl<'a, IO: AsyncRead + AsyncWrite + Unpin> WriteTls<IO> for Stream<'a, IO> {
    fn write_tls(&mut self, cx: &mut Context) -> io::Result<usize> {
        // TODO writev

        struct Writer<'a, 'b, T> {
            io: &'a mut T,
            cx: &'a mut Context<'b>,
        }

        impl<'a, 'b, T: AsyncWrite + Unpin> Write for Writer<'a, 'b, T> {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                match Pin::new(&mut self.io).poll_write(self.cx, buf) {
                    Poll::Ready(result) => result,
                    Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
                }
            }

            fn flush(&mut self) -> io::Result<()> {
                match Pin::new(&mut self.io).poll_flush(self.cx) {
                    Poll::Ready(result) => result,
                    Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
                }
            }
        }

        let mut writer = Writer { io: self.io, cx };
        self.conn.write_tls(&mut writer)
    }
}

impl<'a, IO: AsyncRead + AsyncWrite + Unpin> AsyncRead for Stream<'a, IO> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        while !this.eof && this.conn.wants_read() {
            match this.complete_inner_io(cx, Focus::Readable) {
                Poll::Ready(Ok((0, _))) => break,
                Poll::Ready(Ok(_)) => (),
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            }
        }

        let mut reader = this.conn.reader();
        match reader.read(buf) {
            Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => Poll::Pending,
            Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => {
                this.eof = true;
                Poll::Ready(Err(err))
            }
            result => Poll::Ready(result),
        }
    }
}

impl<'a, IO: AsyncRead + AsyncWrite + Unpin> AsyncWrite for Stream<'a, IO> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        let len = match this.conn.writer().write(buf) {
            Ok(n) => n,
            Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => return Poll::Pending,
            Err(err) => return Poll::Ready(Err(err)),
        };
        while this.conn.wants_write() {
            match this.complete_inner_io(cx, Focus::Writable) {
                Poll::Ready(Ok(_)) => (),
                Poll::Pending if len != 0 => break,
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            }
        }

        if len != 0 || buf.is_empty() {
            Poll::Ready(Ok(len))
        } else {
            // not write zero
            match this.conn.writer().write(buf) {
                Ok(0) => Poll::Pending,
                Ok(n) => Poll::Ready(Ok(n)),
                Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => Poll::Pending,
                Err(err) => Poll::Ready(Err(err)),
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        this.conn.writer().flush()?;
        while this.conn.wants_write() {
            ready!(this.complete_inner_io(cx, Focus::Writable))?;
        }
        Pin::new(&mut this.io).poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        while this.conn.wants_write() {
            ready!(this.complete_inner_io(cx, Focus::Writable))?;
        }
        Pin::new(&mut this.io).poll_close(cx)
    }
}

#[cfg(all(test, feature = "client"))]
#[path = "test_stream.rs"]
mod test_stream;
