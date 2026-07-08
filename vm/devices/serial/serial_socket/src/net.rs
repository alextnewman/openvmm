// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Socket serial backend, usable for both TCP and Unix sockets (even on
//! Windows).

use futures::AsyncRead;
use futures::AsyncWrite;
use inspect::InspectMut;
use mesh::MeshPayload;
use pal_async::driver::Driver;
use pal_async::interest::PollEvents;
use pal_async::socket::PollReady;
use pal_async::socket::PolledSocket;
use serial_core::SerialIo;
use serial_core::resources::ResolveSerialBackendParams;
use serial_core::resources::ResolvedSerialBackend;
use socket2::Socket;
use std::io;
use std::net::TcpListener;
use std::net::TcpStream;
use std::pin::Pin;
use std::task::Context;
use std::task::Poll;
use std::task::ready;
use unix_socket::UnixListener;
use unix_socket::UnixStream;
use vm_resource::ResolveResource;
use vm_resource::Resource;
use vm_resource::ResourceId;
use vm_resource::declare_static_resolver;
use vm_resource::kind::SerialBackendHandle;

#[derive(Debug, MeshPayload)]
pub struct OpenSocketSerialConfig {
    pub current: Option<Socket>,
    pub listener: Option<Socket>,
}

impl ResourceId<SerialBackendHandle> for OpenSocketSerialConfig {
    const ID: &'static str = "socket";
}

pub struct SocketSerialResolver;
declare_static_resolver!(
    SocketSerialResolver,
    (SerialBackendHandle, OpenSocketSerialConfig)
);

impl ResolveResource<SerialBackendHandle, OpenSocketSerialConfig> for SocketSerialResolver {
    type Output = ResolvedSerialBackend;
    type Error = io::Error;

    fn resolve(
        &self,
        rsrc: OpenSocketSerialConfig,
        input: ResolveSerialBackendParams<'_>,
    ) -> Result<Self::Output, Self::Error> {
        Ok(SocketSerialBackend::new(input.driver, rsrc)?.into())
    }
}

impl From<UnixStream> for OpenSocketSerialConfig {
    fn from(stream: UnixStream) -> Self {
        Self {
            current: Some(stream.into()),
            listener: None,
        }
    }
}

impl From<UnixListener> for OpenSocketSerialConfig {
    fn from(listener: UnixListener) -> Self {
        Self {
            current: None,
            listener: Some(listener.into()),
        }
    }
}

impl From<TcpStream> for OpenSocketSerialConfig {
    fn from(stream: TcpStream) -> Self {
        Self {
            current: Some(stream.into()),
            listener: None,
        }
    }
}

impl From<TcpListener> for OpenSocketSerialConfig {
    fn from(listener: TcpListener) -> Self {
        Self {
            current: None,
            listener: Some(listener.into()),
        }
    }
}

pub struct SocketSerialBackend {
    driver: Box<dyn Driver>,
    current: Option<PolledSocket<Socket>>,
    listener: Option<PolledSocket<Socket>>,
}

impl InspectMut for SocketSerialBackend {
    fn inspect_mut(&mut self, req: inspect::Request<'_>) {
        req.respond().field_with("state", || {
            if self.current.is_some() {
                "connected"
            } else if self.listener.is_some() {
                "listening"
            } else {
                "done"
            }
        });
    }
}

impl SocketSerialBackend {
    pub fn new(driver: Box<dyn Driver>, config: OpenSocketSerialConfig) -> io::Result<Self> {
        let current = config
            .current
            .map(|s| PolledSocket::new(&driver, s))
            .transpose()?;
        let listener = config
            .listener
            .map(|s| PolledSocket::new(&driver, s))
            .transpose()?;
        Ok(Self {
            driver: Box::new(driver),
            current,
            listener,
        })
    }

    pub fn into_config(self) -> OpenSocketSerialConfig {
        OpenSocketSerialConfig {
            current: self.current.map(PolledSocket::into_inner),
            listener: self.listener.map(PolledSocket::into_inner),
        }
    }
}

impl From<SocketSerialBackend> for Resource<SerialBackendHandle> {
    fn from(value: SocketSerialBackend) -> Self {
        Resource::new(value.into_config())
    }
}

impl SerialIo for SocketSerialBackend {
    fn is_connected(&self) -> bool {
        self.current.is_some()
    }

    fn poll_connect(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.current.is_some() {
            Poll::Ready(Ok(()))
        } else if let Some(listener) = &mut self.listener {
            let (socket, _) = ready!(listener.poll_accept(cx))?;
            self.current = Some(PolledSocket::new(&self.driver, socket)?);
            Poll::Ready(Ok(()))
        } else {
            // This will never complete.
            Poll::Pending
        }
    }

    fn poll_disconnect(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(current) = &mut self.current {
            ready!(current.poll_ready(cx, PollEvents::RDHUP));
            self.current = None;
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for SocketSerialBackend {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let Some(current) = &mut self.current else {
            return Poll::Ready(Ok(0));
        };
        let r = ready!(Pin::new(current).poll_read(cx, buf));
        if matches!(r, Ok(0)) {
            self.current = None;
        }
        Poll::Ready(r)
    }
}

impl AsyncWrite for SocketSerialBackend {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let Some(current) = &mut self.current else {
            return Poll::Ready(Ok(buf.len()));
        };
        // Optimistically attempt a direct non-blocking send before deferring to
        // the readiness-gated async path.
        //
        // `PolledSocket::poll_write` only issues the underlying `send(2)` after
        // the reactor delivers a writable readiness edge. On edge-triggered
        // backends (e.g. kqueue `EV_CLEAR`) that edge is delivered once when the
        // socket first becomes writable; if it is consumed or missed relative to
        // a guest that busy-polls the UART TX flags from its own vCPU thread
        // (the polled-console path, with interrupts masked), the async drain can
        // stall indefinitely even though the socket has ample send-buffer space.
        // The vCPU never yields to let the reactor re-arm, so the guest wedges.
        //
        // The socket is non-blocking (set by `PolledSocket::new`), so trying the
        // syscall directly here is safe on the vCPU thread: it makes forward
        // progress whenever the socket can accept bytes and only falls back to
        // readiness registration on genuine backpressure (`WouldBlock`).
        match current.get().send(buf) {
            Ok(n) if n > 0 => return Poll::Ready(Ok(n)),
            Ok(_) => {}
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {}
            Err(err) if err.kind() == io::ErrorKind::BrokenPipe => {
                return Poll::Ready(Ok(buf.len()));
            }
            Err(err) => return Poll::Ready(Err(err)),
        }
        let r = ready!(Pin::new(current).poll_write(cx, buf));
        if matches!(&r, Err(err) if err.kind() == io::ErrorKind::BrokenPipe) {
            return Poll::Ready(Ok(buf.len()));
        }
        Poll::Ready(r)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let Some(current) = &mut self.current else {
            return Poll::Ready(Ok(()));
        };
        let r = ready!(Pin::new(current).poll_flush(cx));
        if matches!(&r, Err(err) if err.kind() == io::ErrorKind::BrokenPipe) {
            return Poll::Ready(Ok(()));
        }
        Poll::Ready(r)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let Some(current) = &mut self.current else {
            return Poll::Ready(Ok(()));
        };
        let r = ready!(Pin::new(current).poll_close(cx));
        if matches!(&r, Err(err) if err.kind() == io::ErrorKind::BrokenPipe) {
            return Poll::Ready(Ok(()));
        }
        Poll::Ready(r)
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use futures::AsyncWrite;
    use pal_async::DefaultDriver;
    use pal_async::async_test;
    use std::io::Read;
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    /// Regression test for the polled-console hang.
    ///
    /// A guest that busy-polls the UART TX flags from its own vCPU thread (with
    /// interrupts masked) drives `poll_write` with a `Context` whose waker never
    /// receives a reactor-delivered writable edge — the vCPU never yields to let
    /// the single-threaded reactor run. The readiness-gated async path would
    /// therefore park forever and the guest would wedge, even though the socket
    /// has ample send-buffer space.
    ///
    /// This drives that exact scenario deterministically: on the single-threaded
    /// `DefaultPool` executor+reactor, everything up to the first `.await` runs
    /// without the reactor servicing `kevent()`, so no writable readiness is
    /// ever delivered. The write must still make forward progress via the direct
    /// non-blocking send. Prior to the fix this returned `Poll::Pending` and the
    /// bytes never reached the peer.
    #[async_test]
    async fn direct_send_progresses_without_reactor_readiness(driver: DefaultDriver) {
        let (mut host, guest) = UnixStream::pair().unwrap();
        let guest = Socket::from(OwnedFd::from(guest));
        let sock = PolledSocket::new(&driver, guest).unwrap();
        let mut backend = SocketSerialBackend {
            driver: Box::new(driver.clone()),
            current: Some(sock),
            listener: None,
        };

        // Synchronous poll with a no-op waker: the reactor has had no chance to
        // deliver a writable edge, mirroring the busy-polling vCPU.
        let mut cx = Context::from_waker(std::task::Waker::noop());
        match Pin::new(&mut backend).poll_write(&mut cx, b"hello") {
            Poll::Ready(Ok(n)) => assert_eq!(n, 5),
            other => panic!(
                "expected the write to make progress without reactor readiness, got {other:?}"
            ),
        }

        // The bytes must have actually reached the peer.
        host.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut buf = [0u8; 5];
        host.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"hello");
    }
}
