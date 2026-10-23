use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};

use defguard_version::{SYSTEM_INFO_HEADER, VERSION_HEADER};
use tokio::{
    io::{copy, copy_bidirectional, sink},
    net::{TcpListener, TcpStream},
    sync::{mpsc, oneshot},
    time::{sleep, timeout},
};
use tokio_stream::wrappers::UnboundedReceiverStream;
use tonic::Request;

use super::mtls::{TestCerts, connect, init_crypto, spawn_test_gateway};
use crate::proto::gateway::CoreResponse;

const RPC_TIMEOUT: Duration = Duration::from_secs(10);

async fn start_blackhole_relay(
    upstream: SocketAddr,
) -> (u16, oneshot::Sender<()>, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .await
        .unwrap();
    let relay_port = listener.local_addr().unwrap().port();
    let (blackhole_tx, blackhole_rx) = oneshot::channel();

    let relay_task = tokio::spawn(async move {
        let (mut client, _) = listener.accept().await.unwrap();
        let mut gateway = TcpStream::connect(upstream).await.unwrap();

        tokio::select! {
            _ = copy_bidirectional(&mut client, &mut gateway) => {}
            _ = blackhole_rx => {
                let mut client_sink = sink();
                let mut gateway_sink = sink();
                let _ = tokio::join!(
                    copy(&mut client, &mut client_sink),
                    copy(&mut gateway, &mut gateway_sink),
                );
            }
        }
    });

    (relay_port, blackhole_tx, relay_task)
}

fn core_request(
    stream: UnboundedReceiverStream<CoreResponse>,
) -> Request<UnboundedReceiverStream<CoreResponse>> {
    let mut request = Request::new(stream);
    request
        .metadata_mut()
        .insert(VERSION_HEADER, "2.1.1".parse().unwrap());
    request
        .metadata_mut()
        .insert(SYSTEM_INFO_HEADER, "Linux;test;x86_64".parse().unwrap());
    request
}

#[tokio::test]
#[ignore = "waits for the 30-second HTTP/2 keepalive timeout"]
async fn test_silently_dropped_core_connection_releases_slot() {
    init_crypto();
    let certs = TestCerts::generate();
    let (gateway_port, shutdown_tx, gateway) = spawn_test_gateway(&certs).await;
    let upstream = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), gateway_port);
    let (relay_port, blackhole_tx, relay_task) = start_blackhole_relay(upstream).await;

    let identity = Some((
        certs.core_client_cert_pem.as_str(),
        certs.core_client_key_pem.as_str(),
    ));
    let mut first_client = timeout(
        RPC_TIMEOUT,
        connect(relay_port, &certs.ca_cert_pem, identity),
    )
    .await
    .expect("first Core connection timed out")
    .expect("first Core should connect through the relay");
    let (first_request_tx, first_request_rx) = mpsc::unbounded_channel();
    let first_response = timeout(
        RPC_TIMEOUT,
        first_client.bidi(core_request(UnboundedReceiverStream::new(first_request_rx))),
    )
    .await
    .expect("first Core bidi call timed out")
    .expect("first Core should be admitted");
    let mut first_response = first_response.into_inner();
    let first_message = timeout(RPC_TIMEOUT, first_response.message())
        .await
        .expect("first Core response timed out")
        .unwrap();
    assert!(first_message.is_some());
    assert!(gateway.lock().unwrap().client_tx.is_some());

    blackhole_tx.send(()).unwrap();
    let released = timeout(Duration::from_secs(35), async {
        loop {
            if gateway.lock().unwrap().client_tx.is_none() {
                break;
            }
            sleep(Duration::from_millis(100)).await;
        }
    })
    .await;
    assert!(
        released.is_ok(),
        "gateway did not release the slot in 35 seconds"
    );

    let mut second_client = timeout(
        RPC_TIMEOUT,
        connect(gateway_port, &certs.ca_cert_pem, identity),
    )
    .await
    .expect("second Core connection timed out")
    .expect("second Core should connect directly");
    let (second_request_tx, second_request_rx) = mpsc::unbounded_channel();
    let second_response = timeout(
        RPC_TIMEOUT,
        second_client.bidi(core_request(UnboundedReceiverStream::new(
            second_request_rx,
        ))),
    )
    .await
    .expect("second Core bidi call timed out")
    .expect("second Core should be admitted after keepalive closes the stale stream");
    let mut second_response = second_response.into_inner();
    let second_message = timeout(RPC_TIMEOUT, second_response.message())
        .await
        .expect("second Core response timed out")
        .unwrap();
    assert!(second_message.is_some());

    drop(first_request_tx);
    drop(first_response);
    drop(second_request_tx);
    let _ = shutdown_tx.send(());
    relay_task.abort();
    let _ = relay_task.await;
}
