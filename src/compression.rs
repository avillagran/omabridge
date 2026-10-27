//! Negotiated deflate-block-v1: kind u8, wire length u32 BE, plain length u32 BE,
//! then payload. EOF only between frames. Dictionaries never cross frame boundaries.
use anyhow::{Result, ensure};
use flate2::{Compression, Decompress, FlushDecompress, Status, write::DeflateEncoder};
use std::io::Write;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
const BLOCK: usize = 32 * 1024;

pub(crate) async fn encode<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    read: &mut R,
    write: &mut W,
) -> Result<()> {
    let mut plain = vec![0; BLOCK];
    loop {
        let n = read.read(&mut plain).await?;
        if n == 0 {
            return Ok(());
        }
        let mut encoder = DeflateEncoder::new(Vec::with_capacity(BLOCK + 128), Compression::fast());
        // Small interactive messages do not justify compression work.
        let compressed = if n >= 256 {
            encoder.write_all(&plain[..n])?;
            encoder.finish()?
        } else {
            Vec::new()
        };
        let use_compressed = !compressed.is_empty() && compressed.len() + 32 < n;
        let payload = if use_compressed {
            compressed.as_slice()
        } else {
            &plain[..n]
        };
        write.write_u8(u8::from(use_compressed)).await?;
        write.write_u32(payload.len() as u32).await?;
        write.write_u32(n as u32).await?;
        write.write_all(payload).await?;
        // Do not wait to collect a full block: interactive traffic goes out immediately.
        write.flush().await?;
    }
}

pub(crate) async fn decode<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    read: &mut R,
    write: &mut W,
) -> Result<()> {
    let mut wire = vec![0; BLOCK];
    let mut plain = vec![0; BLOCK];
    loop {
        let mut kind = [0];
        if read.read(&mut kind).await? == 0 {
            return Ok(());
        }
        let len = read.read_u32().await? as usize;
        let size = read.read_u32().await? as usize;
        ensure!(
            len > 0 && len <= BLOCK && size > 0 && size <= BLOCK,
            "invalid compression frame length"
        );
        read.read_exact(&mut wire[..len]).await?;
        let payload = match kind[0] {
            0 => {
                ensure!(len == size, "invalid raw frame");
                &wire[..len]
            }
            1 => {
                let mut decoder = Decompress::new(false);
                let status = decoder.decompress(
                    &wire[..len],
                    &mut plain[..size],
                    FlushDecompress::Finish,
                )?;
                ensure!(
                    status == Status::StreamEnd
                        && decoder.total_in() == len as u64
                        && decoder.total_out() == size as u64,
                    "invalid compressed frame"
                );
                &plain[..size]
            }
            _ => anyhow::bail!("unknown compression frame"),
        };
        write.write_all(payload).await?;
        write.flush().await?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn round_trip_and_savings() -> Result<()> {
        for plain in [
            b"tiny".to_vec(),
            b"T3 event: repeated JSON payload\n".repeat(10000),
            (0..100000).map(|_| rand::random::<u8>()).collect(),
        ] {
            let mut wire = Vec::new();
            encode(&mut plain.as_slice(), &mut wire).await?;
            let mut restored = Vec::new();
            decode(&mut wire.as_slice(), &mut restored).await?;
            assert_eq!(plain, restored);
            eprintln!(
                "compression fixture: input={} wire={}",
                plain.len(),
                wire.len()
            );
            if plain.starts_with(b"T3 event") {
                assert!(wire.len() < plain.len() / 10);
            } else {
                assert!(wire.len() <= plain.len() + 9 * plain.len().div_ceil(BLOCK));
            }
        }
        Ok(())
    }
    #[tokio::test]
    async fn rejects_corruption_truncation_and_expansion() -> Result<()> {
        let mut wire = Vec::new();
        encode(&mut b"compress me".repeat(1000).as_slice(), &mut wire).await?;
        for end in 1..wire.len() {
            assert!(decode(&mut &wire[..end], &mut Vec::new()).await.is_err());
        }
        for bad in [
            vec![2, 0, 0, 0, 1, 0, 0, 0, 1, 0],
            vec![0, 0, 1, 0, 0, 0, 0, 0, 1],
            vec![1, 0, 0, 0, 1, 0, 0, 0, 1, 0],
        ] {
            assert!(decode(&mut bad.as_slice(), &mut Vec::new()).await.is_err());
        }
        wire[5..9].copy_from_slice(&1u32.to_be_bytes());
        assert!(decode(&mut wire.as_slice(), &mut Vec::new()).await.is_err());
        Ok(())
    }
}
