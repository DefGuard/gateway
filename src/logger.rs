use fern::colors::{Color, ColoredLevelConfig};

/// Configures fern loggin library
pub fn setup() -> Result<(), fern::InitError> {
    let colors = ColoredLevelConfig::new()
    .trace(Color::BrightWhite)
    .debug(Color::BrightCyan)
    .info(Color::BrightGreen)
    .warn(Color::BrightYellow)
    .error(Color::BrightRed);
    fern::Dispatch::new()
        .format(move |out, message, record| {
            out.finish(format_args!(
                "[{}][{}][{}] {}",
                chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f"),
                record.target(),
                colors.color(record.level()),
                message
            ))
        })
        .level(log::LevelFilter::Debug)
        .chain(std::io::stdout())
        .apply()?;
    Ok(())
}
