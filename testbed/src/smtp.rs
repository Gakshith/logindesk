//! A minimal SMTP client (EHLO, MAIL, RCPT, DATA, QUIT) so the fake site can deliver to Mailpit.
//! Test-only: no TLS, no auth, loopback only.

use std::net::SocketAddr;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

use crate::site::Mail;

/// Deliver one message to the SMTP server at `addr`.
pub async fn send(addr: SocketAddr, mail: &Mail) -> std::io::Result<()> {
    let stream = TcpStream::connect(addr).await?;
    let (r, mut w) = stream.into_split();
    let mut r = BufReader::new(r);
    expect(&mut r, 220).await?;
    for (cmd, code) in [
        ("EHLO testbed.localhost".to_string(), 250),
        (format!("MAIL FROM:<{}>", mail.from_addr), 250),
        (format!("RCPT TO:<{}>", mail.to), 250),
        ("DATA".to_string(), 354),
    ] {
        w.write_all(format!("{cmd}\r\n").as_bytes()).await?;
        expect(&mut r, code).await?;
    }
    // Dot-stuff lines that start with '.'.
    let body: String = mail
        .rfc822()
        .split("\r\n")
        .map(|l| {
            if l.starts_with('.') {
                format!(".{l}")
            } else {
                l.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\r\n");
    w.write_all(format!("{body}\r\n.\r\n").as_bytes()).await?;
    expect(&mut r, 250).await?;
    w.write_all(b"QUIT\r\n").await?;
    Ok(())
}

async fn expect<R: tokio::io::AsyncBufRead + Unpin>(r: &mut R, code: u16) -> std::io::Result<()> {
    loop {
        let mut line = String::new();
        if r.read_line(&mut line).await? == 0 {
            return Err(std::io::Error::other("smtp: connection closed"));
        }
        let got: u16 = line.get(..3).and_then(|c| c.parse().ok()).unwrap_or(0);
        if got != code {
            return Err(std::io::Error::other(format!(
                "smtp: expected {code}, got {:?}",
                line.trim_end()
            )));
        }
        // "250-..." continues, "250 ..." ends the reply.
        if line.as_bytes().get(3) != Some(&b'-') {
            return Ok(());
        }
    }
}
