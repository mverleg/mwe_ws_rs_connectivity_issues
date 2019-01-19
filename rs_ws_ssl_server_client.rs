extern crate env_logger;
#[macro_use]
extern crate log;
extern crate openssl;
extern crate proc_macro;
extern crate url;
extern crate ws;

use std::fs::File;
use std::io::Read;
use std::rc::Rc;
use std::thread;
use std::time::Duration;

use log::LevelFilter;
use openssl::pkey::PKey;
use openssl::ssl::{SslConnector, SslMethod, SslStream, SslVerifyMode};
use openssl::ssl::SslAcceptor;
use openssl::x509::X509;
use ws::util::TcpStream;

/**
 * Server
 * https://github.com/housleyjk/ws-rs/blob/master/examples/ssl-server.rs
 */

struct Server {
    out: ws::Sender,
    ssl: Rc<SslAcceptor>,
}

impl ws::Handler for Server {
    fn on_message(&mut self, msg: ws::Message) -> ws::Result<()> {
        info!("server got message: {}", msg);
        self.out.send(msg) // simple echo
    }

    fn upgrade_ssl_server(&mut self, sock: TcpStream) -> ws::Result<SslStream<TcpStream>> {
        self.ssl.accept(sock).map_err(From::from)
    }
}

pub fn start_server() {
    let cert = {
        let data = read_file("ssl.cert").unwrap();
        X509::from_pem(data.as_ref()).unwrap()
    };

    let pkey = {
        let data = read_file("ssl.key").unwrap();
        PKey::private_key_from_pem(data.as_ref()).unwrap()
    };

    let acceptor = Rc::new({
        let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
        builder.set_private_key(&pkey).unwrap();
        builder.set_certificate(&cert).unwrap();

        builder.build()
    });

    ws::Builder::new()
        .with_settings(ws::Settings {
            encrypt_server: true,
            ..ws::Settings::default()
        })
        .build(|out: ws::Sender| Server {
            out: out,
            ssl: acceptor.clone(),
        })
        .unwrap()
        .listen("localhost:12321")
        .unwrap();
}

fn read_file(name: &str) -> std::io::Result<Vec<u8>> {
    let mut file = File::open(name)?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)?;
    Ok(buf)
}

/**
 * Client
 * https://github.com/housleyjk/ws-rs/blob/master/examples/unsafe-ssl-client.rs
 */

pub struct Client {
    pub out: ws::Sender,
}

impl ws::Handler for Client {
    fn on_message(&mut self, msg: ws::Message) -> ws::Result<()> {
        println!("msg = {}", msg);
        self.out.close(ws::CloseCode::Normal)
    }

    fn upgrade_ssl_client(
        &mut self,
        sock: TcpStream,
        _: &url::Url,
    ) -> ws::Result<SslStream<TcpStream>> {
        let mut builder = SslConnector::builder(SslMethod::tls()).map_err(|e| {
            ws::Error::new(
                ws::ErrorKind::Internal,
                format!("Failed to upgrade client to SSL: {}", e),
            )
        })?;
        builder.set_verify(SslVerifyMode::empty());

        let connector = builder.build()
            .configure()
            .unwrap()
            .use_server_name_indication(false)
            .verify_hostname(false)
            .connect("localhost:12321", sock)
            .unwrap();

        Ok(connector)
    }
}

/**
 * Main function
 */

fn main() {
    env_logger::Builder::new()
        .filter(None, LevelFilter::Debug)
        .init();

    // Server
    info!("starting server...");
    let server = thread::spawn(move || start_server());
    thread::sleep(Duration::from_millis(500));
    info!("...server running!");

    // Client
    ws::connect("wss://localhost:12321", |out| {
        out.send("Hello WebSocket").unwrap();

        Client { out }
    }).unwrap();

    server.join().unwrap();
}
