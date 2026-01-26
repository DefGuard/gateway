use defguard_version::Version;
use tokio::sync::mpsc::Sender;
use tracing::{Event, Subscriber};
use tracing_subscriber::{Layer, layer::SubscriberExt, util::SubscriberInitExt};

use crate::proto::gateway::LogEntry;

pub fn init_tracing(own_version: &Version, level: &str, logs_tx: Option<Sender<LogEntry>>) {
    let subscriber = tracing_subscriber::registry();
    let subscriber =
        defguard_version::tracing::with_version_formatters(own_version, level, subscriber);

    if let Some(tx) = logs_tx {
        let sender_layer = LogSenderLayer::new(tx);
        subscriber.with(sender_layer).init();
    } else {
        subscriber.init();
    }

    info!("Tracing initialized");
}

/// A tracing layer that sends log entries to a gRPC logs channel.
pub struct LogSenderLayer {
    logs_tx: Sender<LogEntry>,
}

impl LogSenderLayer {
    #[must_use]
    pub const fn new(logs_tx: Sender<LogEntry>) -> Self {
        Self { logs_tx }
    }
}

impl<S> Layer<S> for LogSenderLayer
where
    S: Subscriber,
{
    fn on_event(&self, event: &Event<'_>, _ctx: tracing_subscriber::layer::Context<'_, S>) {
        if self.logs_tx.is_closed() {
            return;
        }

        let mut visitor = LogVisitor::default();
        event.record(&mut visitor);

        let entry = LogEntry {
            level: format!("{:?}", event.metadata().level()),
            target: event.metadata().target().to_string(),
            message: visitor.message,
            timestamp: chrono::Utc::now().to_rfc3339(),
            fields: visitor.fields,
        };

        // Drop the buffer overflow error for now
        let _ = self.logs_tx.try_send(entry);
    }
}

#[derive(Default)]
struct LogVisitor {
    message: String,
    fields: std::collections::HashMap<String, String>,
}

impl tracing::field::Visit for LogVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.message = format!("{value:?}");
        } else {
            self.fields
                .insert(field.name().to_string(), format!("{value:?}"));
        }
    }
}
