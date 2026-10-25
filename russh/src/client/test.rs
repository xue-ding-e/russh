#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    use log::debug;
    use ssh_key::PrivateKey;
    use tokio::net::TcpListener;

    use crate::cert::PublicKeyOrCertificate;
    // Import client types directly since we're in the client module
    use crate::Error;
    use crate::client::{Config, Handler, connect};
    use crate::keys::PrivateKeyWithHashAlg;
    use crate::server::{self, Auth, Handler as ServerHandler, Server, Session};
    use crate::{ChannelId, SshId}; // Import directly from crate root
    use rand::rng;

    #[derive(Clone)]
    struct TestServer {
        clients: Arc<Mutex<HashMap<(usize, ChannelId), server::Handle>>>,
        id: usize,
    }

    impl server::Server for TestServer {
        type Handler = Self;

        fn new_client(&mut self, _: Option<std::net::SocketAddr>) -> Self {
            let s = self.clone();
            self.id += 1;
            s
        }
    }

    impl ServerHandler for TestServer {
        type Error = Error;

        async fn channel_open_session(
            &mut self,
            channel: crate::channels::Channel<server::Msg>,
            reply: server::ChannelOpenHandle,
            session: &mut Session,
        ) -> Result<(), Self::Error> {
            {
                let mut clients = self.clients.lock().unwrap();
                clients.insert((self.id, channel.id()), session.handle());
            }
            reply.accept().await;
            Ok(())
        }

        async fn auth_publickey(
            &mut self,
            _: &str,
            _: &ssh_key::PublicKey,
        ) -> Result<Auth, Self::Error> {
            debug!("auth_publickey");
            Ok(Auth::Accept)
        }

        async fn data(
            &mut self,
            channel: ChannelId,
            data: &[u8],
            session: &mut Session,
        ) -> Result<(), Self::Error> {
            debug!("server received data: {:?}", std::str::from_utf8(data));
            session.data(channel, data.to_vec())?;
            Ok(())
        }

        async fn tcpip_forward(
            &mut self,
            _: &str,
            _: &mut u32,
            _: &mut Session,
        ) -> Result<bool, Self::Error> {
            Ok(true)
        }
    }

    struct Client {}

    impl Handler for Client {
        type Error = Error;

        async fn check_server_key(
            &mut self,
            _: &PublicKeyOrCertificate,
        ) -> Result<bool, Self::Error> {
            Ok(true)
        }
    }

    #[tokio::test]
    async fn test_client_connects_to_protocol_1_99() {
        let _ = env_logger::try_init();

        // Create a client key
        let client_key = PrivateKey::random(&mut rng(), ssh_key::Algorithm::Ed25519).unwrap();

        // Configure the server
        let mut config = server::Config::default();
        config.auth_rejection_time = std::time::Duration::from_secs(1);
        config.server_id = SshId::Standard("SSH-1.99-CustomServer_1.0".into());
        config.inactivity_timeout = None;
        config
            .keys
            .push(PrivateKey::random(&mut rng(), ssh_key::Algorithm::Ed25519).unwrap());
        let config = Arc::new(config);

        // Create server struct
        let mut server = TestServer {
            clients: Arc::new(Mutex::new(HashMap::new())),
            id: 0,
        };

        // Start the TCP listener for our mock server
        let socket = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();

        // Spawn a separate task that will handle the server connection
        tokio::spawn(async move {
            // Accept a connection
            let (socket, _) = socket.accept().await.unwrap();

            // Handle the connection with the server
            let server_handler = server.new_client(None);
            server::run_stream(config, socket, server_handler)
                .await
                .unwrap();
        });

        println!("Server listening on {addr}");

        // Configure the client
        let client_config = Arc::new(Config::default());

        // Connect to the server
        let mut session = connect(client_config, addr, Client {}).await.unwrap();

        // Unfortunately, we can't directly verify the protocol version from the client API
        // The Protocol199Stream wrapper ensures the server sends SSH-1.99-CustomServer_1.0
        // The test passing means the client accepted this protocol version

        // Try to authenticate
        let auth_result = session
            .authenticate_publickey(
                std::env::var("USER").unwrap_or("user".to_string()),
                PrivateKeyWithHashAlg::new(
                    Arc::new(client_key),
                    session.best_supported_rsa_hash().await.unwrap().flatten(),
                ),
            )
            .await
            .unwrap();

        assert!(auth_result.success());

        // Try opening a session channel
        let mut channel = session.channel_open_session().await.unwrap();

        // Send some data
        let test_data = b"Hello, 1.99 protocol server!";
        channel.data(&test_data[..]).await.unwrap();

        // Wait for response
        let msg = channel.wait().await.unwrap();
        match msg {
            crate::channels::ChannelMsg::Data { data: msg_data } => {
                assert_eq!(test_data.as_slice(), &msg_data[..]);
            }
            msg => panic!("Unexpected message {msg:?}"),
        }
    }

    #[tokio::test]
    async fn test_send_custom_global_request() {
        let _ = env_logger::try_init();

        let client_key = PrivateKey::random(&mut rng(), ssh_key::Algorithm::Ed25519).unwrap();

        let mut config = server::Config::default();
        config.auth_rejection_time = std::time::Duration::from_secs(1);
        config.inactivity_timeout = None;
        config
            .keys
            .push(PrivateKey::random(&mut rng(), ssh_key::Algorithm::Ed25519).unwrap());
        let config = Arc::new(config);

        let mut server = TestServer {
            clients: Arc::new(Mutex::new(HashMap::new())),
            id: 0,
        };

        let socket = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();

        tokio::spawn(async move {
            let (socket, _) = socket.accept().await.unwrap();
            let server_handler = server.new_client(None);
            server::run_stream(config, socket, server_handler)
                .await
                .unwrap();
        });

        let client_config = Arc::new(Config::default());
        let mut session = connect(client_config, addr, Client {}).await.unwrap();

        let auth_result = session
            .authenticate_publickey(
                std::env::var("USER").unwrap_or("user".to_string()),
                PrivateKeyWithHashAlg::new(
                    Arc::new(client_key),
                    session.best_supported_rsa_hash().await.unwrap().flatten(),
                ),
            )
            .await
            .unwrap();
        assert!(auth_result.success());

        // The default server has no handler for this request name, so it replies
        // with a failure, which surfaces as RequestDenied.
        let denied = session
            .send_global_request("custom-request@example.com", b"payload", true)
            .await;
        assert!(matches!(denied, Err(Error::RequestDenied)));

        // Without a reply requested the call returns immediately and the server
        // must stay silent. Queue a reply-wanting request right behind it: an
        // unsolicited failure for the first request would be matched to the
        // forward and turn its success into RequestDenied.
        let no_reply = session
            .send_global_request("custom-request@example.com", b"payload", false)
            .await
            .unwrap();
        assert!(no_reply.is_none());
        session.tcpip_forward("127.0.0.1", 12345).await.unwrap();
    }

    const PEER_REQUEST_NAME: &str = "russh-synthetic-peer-canary\n\u{1b}[31m\t@example.invalid";

    #[test]
    fn unhandled_global_request_warning_omits_peer_text() {
        use std::process::{Command, Stdio};
        use std::time::{Duration, Instant};

        // Other tests install a process-global logger. Run only this fixture in
        // a child process so their order cannot affect the captured warnings.
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "client::test::tests::unhandled_global_request_logging_fixture",
                "--ignored",
                "--nocapture",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(20);
        let failure = loop {
            match child.try_wait() {
                Ok(Some(_)) => break None,
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                result => {
                    let _ = child.kill();
                    break Some(format!("fixture did not finish: {result:?}"));
                }
            }
        };
        let output = child.wait_with_output().unwrap();
        let stdout = String::from_utf8(output.stdout).unwrap();
        let warnings = String::from_utf8(output.stderr).unwrap();
        assert!(
            failure.is_none() && output.status.success(),
            "fixture failed: {failure:?}\n{stdout}\n{warnings}"
        );
        assert!(
            warnings.contains("synthetic logger control"),
            "the warning logger must be active"
        );
        assert!(
            !warnings.contains("russh-synthetic-peer-canary"),
            "peer-controlled request text reached the warning logger"
        );
        for wants_reply in [0, 1] {
            let expected = format!(
                "Unhandled global request (name length: {} bytes, wants_reply: {wants_reply})",
                PEER_REQUEST_NAME.len()
            );
            assert_eq!(warnings.matches(&expected).count(), 1, "{warnings}");
        }
    }

    #[tokio::test]
    #[ignore = "run in isolation by unhandled_global_request_warning_omits_peer_text"]
    async fn unhandled_global_request_logging_fixture() {
        use ssh_encoding::Encode;
        use tokio::sync::oneshot;

        use crate::session::GlobalRequestResponse;

        struct RequestServer {
            replies: Vec<(u8, oneshot::Sender<bool>)>,
        }

        impl ServerHandler for RequestServer {
            type Error = Error;

            async fn auth_none(&mut self, _: &str) -> Result<Auth, Error> {
                Ok(Auth::Accept)
            }

            async fn auth_succeeded(&mut self, session: &mut Session) -> Result<(), Error> {
                for (wants_reply, reply) in self.replies.drain(..) {
                    // Track the current failure reply for either flag value;
                    // this logging regression does not change reply semantics.
                    session
                        .open_global_requests
                        .push_back(GlobalRequestResponse::CancelTcpIpForward(reply));
                    let enc = session.common.encrypted.as_mut().unwrap();
                    push_packet!(enc.write, {
                        crate::msg::GLOBAL_REQUEST.encode(&mut enc.write)?;
                        PEER_REQUEST_NAME.encode(&mut enc.write)?;
                        wants_reply.encode(&mut enc.write)?;
                    });
                }
                Ok(())
            }

            async fn channel_open_session(
                &mut self,
                _: crate::Channel<server::Msg>,
                reply: server::ChannelOpenHandle,
                _: &mut Session,
            ) -> Result<(), Error> {
                reply.accept().await;
                Ok(())
            }
        }

        env_logger::Builder::new()
            .filter_level(log::LevelFilter::Warn)
            .format_timestamp(None)
            .init();
        log::warn!(target: "russh::client::encrypted", "synthetic logger control");

        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            let mut config = server::Config::default();
            config
                .keys
                .push(PrivateKey::random(&mut rng(), ssh_key::Algorithm::Ed25519).unwrap());
            let mut replies = Vec::new();
            let mut results = Vec::new();
            for wants_reply in [0, 1] {
                let (reply, result) = oneshot::channel();
                replies.push((wants_reply, reply));
                results.push(result);
            }

            // Negotiate and authenticate real SSH sessions without sockets or
            // external services, then send the synthetic request on the wire.
            let (client_stream, server_stream) = tokio::io::duplex(64 * 1024);
            let (server, client) = tokio::join!(
                server::run_stream(Arc::new(config), server_stream, RequestServer { replies }),
                crate::client::connect_stream(
                    Arc::new(Config::default()),
                    client_stream,
                    Client {}
                )
            );
            let server = server.unwrap();
            let mut client = client.unwrap();
            assert!(
                client
                    .authenticate_none("synthetic-user")
                    .await
                    .unwrap()
                    .success()
            );
            for result in results {
                assert!(
                    !result.await.unwrap(),
                    "unknown request must still be rejected"
                );
            }
            let channel = client.channel_open_session().await.unwrap();
            channel.close().await.unwrap();
            client
                .disconnect(crate::Disconnect::ByApplication, "test complete", "")
                .await
                .unwrap();
            server.await.unwrap();
        })
        .await
        .unwrap();
    }
}
