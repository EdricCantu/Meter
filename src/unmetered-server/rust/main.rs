use if_addrs::get_if_addrs;
use std::{collections::HashMap, env, io};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

#[tokio::main]
async fn main() -> io::Result<()> {
    list_private_ipv4s();

    let port = env::var("PORT").unwrap_or_else(|_| "8080".to_string());
    let addr = format!("0.0.0.0:{}", port);
    let listener = TcpListener::bind(&addr).await?;
    println!("Proxy server running on {}", addr);

    loop {
        let (mut client_socket, _) = listener.accept().await?;
        println!("Client connected to proxy");

        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            let n = match client_socket.read(&mut buf).await {
                Ok(n) if n > 0 => n,
                _ => return,
            };

            let data = &buf[..n];
            let request_str = String::from_utf8_lossy(data);
            let is_tls = request_str.contains("CONNECT");

            let (server_addr, server_port) = if is_tls {
                let addr = request_str
                    .split("CONNECT ")
                    .nth(1)
                    .and_then(|s| s.split(' ').next())
                    .unwrap_or_default()
                    .split(':')
                    .next()
                    .unwrap_or_default()
                    .to_string();
                println!("TLS CONNECT to: {}", addr);
                (addr, 443)
            } else {
                let addr = request_str
                    .lines()
                    .find(|line| line.starts_with("Host: "))
                    .and_then(|line| line.split("Host: ").nth(1))
                    .unwrap_or_default()
                    .to_string();
                (addr, 80)
            };

            match TcpStream::connect((&*server_addr, server_port)).await {
                Ok(mut server_socket) => {
                    println!("Proxy connected to server at {}:{}", server_addr, server_port);
                    if is_tls {
                        let _ = client_socket.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await;
                    } else {
                        let _ = server_socket.write_all(data).await;
                    }

                    let (mut cr, mut cw) = client_socket.split();
                    let (mut sr, mut sw) = server_socket.split();

                    let client_to_server = tokio::io::copy(&mut cr, &mut sw);
                    let server_to_client = tokio::io::copy(&mut sr, &mut cw);

                    tokio::select! {
                        _ = client_to_server => {},
                        _ = server_to_client => {},
                    }
                }
                Err(e) => {
                    println!("Failed to connect to server: {}", e);
                }
            }
        });
    }
}

fn list_private_ipv4s() {
    let interfaces = get_if_addrs().unwrap();
    let mut results: HashMap<String, Vec<String>> = HashMap::new();

    for iface in interfaces {
        if iface.is_loopback() || !iface.ip().is_ipv4() {
            continue;
        }

        results
            .entry(iface.name.clone())
            .or_insert_with(Vec::new)
            .push(iface.ip().to_string());
    }

    println!("Possible Private IPs:");
    for (name, ips) in results {
        println!("{}: {:?}", name, ips);
    }
}
