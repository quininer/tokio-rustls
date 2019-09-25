#[cfg(feature = "nightly")]
#[cfg(feature = "tokio-support")]
mod vecbuf;

use std::io::{ self, Read, Write };
#[cfg(feature = "nightly")]
use std::io::Initializer;
use rustls::Session;
#[cfg(feature = "nightly")]
use rustls::WriteV;
#[cfg(feature = "nightly")]
#[cfg(feature = "tokio-support")]
use tokio_io::AsyncWrite;


pub struct Stream<'a, S: 'a, IO: 'a> {
    pub session: &'a mut S,
    pub io: &'a mut IO
}

pub trait WriteTls<'a, S: Session, IO: Read + Write>: Read + Write {
    fn write_tls(&mut self) -> io::Result<usize>;
}

#[derive(Clone, Copy)]
enum Focus {
    Empty,
    Readable,
    Writable
}

impl<'a, S: Session, IO: Read + Write> Stream<'a, S, IO> {
    pub fn new(session: &'a mut S, io: &'a mut IO) -> Self {
        Stream { session, io }
    }

    pub fn complete_io(&mut self) -> io::Result<(usize, usize)> {
        self.complete_inner_io(Focus::Empty)
    }

    fn complete_read_io(&mut self) -> io::Result<usize> {
        let n = self.session.read_tls(self.io)?;

        self.session.process_new_packets()
            .map_err(|err| {
                // In case we have an alert to send describing this error,
                // try a last-gasp write -- but don't predate the primary
                // error.
                let _ = self.write_tls();

                io::Error::new(io::ErrorKind::InvalidData, err)
            })?;

        Ok(n)
    }

    fn complete_write_io(&mut self) -> io::Result<usize> {
        self.write_tls()
    }

    fn complete_inner_io(&mut self, focus: Focus) -> io::Result<(usize, usize)> {
        let mut wrlen = 0;
        let mut rdlen = 0;
        let mut eof = false;

        loop {
            let mut write_would_block = false;
            let mut read_would_block = false;

            while self.session.wants_write() {
                match self.complete_write_io() {
                    Ok(n) => wrlen += n,
                    Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => {
                        write_would_block = true;
                        break
                    },
                    Err(err) => return Err(err)
                }
            }

            if let Focus::Writable = focus {
                if !write_would_block {
                    return Ok((rdlen, wrlen));
                } else {
                    return Err(io::ErrorKind::WouldBlock.into());
                }
            }

            if !eof && self.session.wants_read() {
                match self.complete_read_io() {
                    Ok(0) => eof = true,
                    Ok(n) => rdlen += n,
                    Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => read_would_block = true,
                    Err(err) => return Err(err)
                }
            }

            let would_block = match focus {
                Focus::Empty => write_would_block || read_would_block,
                Focus::Readable => read_would_block,
                Focus::Writable => write_would_block,
            };

            match (eof, self.session.is_handshaking(), would_block) {
                (true, true, _) => return Err(io::ErrorKind::UnexpectedEof.into()),
                (_, false, true) => {
                    let would_block = match focus {
                        Focus::Empty => rdlen == 0 && wrlen == 0,
                        Focus::Readable => rdlen == 0,
                        Focus::Writable => wrlen == 0
                    };

                    return if would_block {
                        Err(io::ErrorKind::WouldBlock.into())
                    } else {
                        Ok((rdlen, wrlen))
                    };
                },
                (_, false, _) => return Ok((rdlen, wrlen)),
                (_, true, true) => return Err(io::ErrorKind::WouldBlock.into()),
                (..) => ()
            }
        }
    }
}

#[cfg(not(feature = "nightly"))]
impl<'a, S: Session, IO: Read + Write> WriteTls<'a, S, IO> for Stream<'a, S, IO> {
    fn write_tls(&mut self) -> io::Result<usize> {
        self.session.write_tls(self.io)
    }
}

#[cfg(feature = "nightly")]
impl<'a, S: Session, IO: Read + Write> WriteTls<'a, S, IO> for Stream<'a, S, IO> {
    default fn write_tls(&mut self) -> io::Result<usize> {
        self.session.write_tls(self.io)
    }
}

#[cfg(feature = "nightly")]
#[cfg(feature = "tokio-support")]
impl<'a, S: Session, IO: Read + AsyncWrite> WriteTls<'a, S, IO> for Stream<'a, S, IO> {
    fn write_tls(&mut self) -> io::Result<usize> {
        use futures::Async;
        use self::vecbuf::VecBuf;

        struct V<'a, IO: 'a>(&'a mut IO);

        impl<'a, IO: AsyncWrite> WriteV for V<'a, IO> {
            fn writev(&mut self, vbytes: &[&[u8]]) -> io::Result<usize> {
                let mut vbytes = VecBuf::new(vbytes);
                match self.0.write_buf(&mut vbytes) {
                    Ok(Async::Ready(n)) => Ok(n),
                    Ok(Async::NotReady) => Err(io::ErrorKind::WouldBlock.into()),
                    Err(err) => Err(err)
                }
            }
        }

        let mut vecbuf = V(self.io);
        self.session.writev_tls(&mut vecbuf)
    }
}

impl<'a, S: Session, IO: Read + Write> Read for Stream<'a, S, IO> {
    #[cfg(feature = "nightly")]
    unsafe fn initializer(&self) -> Initializer {
        Initializer::nop()
    }

    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        while self.session.wants_read() {
            if let (0, 0) = self.complete_inner_io(Focus::Readable)? {
                break
            }
        }
        self.session.read(buf)
    }
}

impl<'a, S: Session, IO: Read + Write> io::Write for Stream<'a, S, IO> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let len = self.session.write(buf)?;
        while self.session.wants_write() {
            match self.complete_inner_io(Focus::Writable) {
                Ok(_) => (),
                Err(ref err) if err.kind() == io::ErrorKind::WouldBlock && len != 0 => break,
                Err(err) => return Err(err)
            }
        }
        Ok(len)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.session.flush()?;
        while self.session.wants_write() {
            self.complete_inner_io(Focus::Writable)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod test_stream;
