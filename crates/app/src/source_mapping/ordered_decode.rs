//! Decode bounded windows of independently framed records in canonical order.
use super::DecodeBudget;
use crate::{AppError, CancellationToken};

const FRAMES_PER_SLOT: usize = 256;

/// Frame weights reserve room for the raw frame and its decoded representation.
/// A record larger than the queue allowance uses the same sequential decoder.
pub fn decode_ordered<T, R>(
    budget: DecodeBudget,
    cancel: &CancellationToken,
    mut next: impl FnMut() -> Result<Option<(T, usize)>, AppError>,
    decode: impl Fn(T) -> R + Sync,
    mut emit: impl FnMut(R) -> Result<(), AppError>,
) -> Result<(), AppError>
where
    T: Send,
    R: Send,
{
    let workers = budget.workers().min(256);
    if workers == 1 || budget.queued_bytes() == 0 {
        while let Some((frame, _)) = next()? {
            check_cancel(cancel)?;
            emit(decode(frame))?;
        }
        return check_cancel(cancel);
    }
    let mut pending = None;
    loop {
        check_cancel(cancel)?;
        let mut window = Vec::new();
        let mut weight = 0usize;
        let end = loop {
            if window.len() == workers * FRAMES_PER_SLOT {
                break None;
            }
            let item = pending
                .take()
                .map_or_else(&mut next, |value| Ok(Some(value)));
            match item {
                Ok(Some((frame, bytes))) => {
                    let total = weight.saturating_add(bytes);
                    if total > budget.queued_bytes() && !window.is_empty() {
                        pending = Some((frame, bytes));
                        break None;
                    }
                    window.push(frame);
                    weight = total;
                    if weight >= budget.queued_bytes() {
                        break None;
                    }
                }
                Ok(None) => break Some(Ok(())),
                Err(error) => break Some(Err(error)),
            }
        };
        // Emit the prefix before an end-of-stream or framing error, just as the
        // sequential decoder would. A callback error still takes precedence.
        decode_window(window, workers, cancel, &decode, &mut emit)?;
        if let Some(result) = end {
            return result.and_then(|()| check_cancel(cancel));
        }
    }
}

fn decode_window<T, R>(
    window: Vec<T>,
    workers: usize,
    cancel: &CancellationToken,
    decode: &(impl Fn(T) -> R + Sync),
    emit: &mut impl FnMut(R) -> Result<(), AppError>,
) -> Result<(), AppError>
where
    T: Send,
    R: Send,
{
    if window.len() <= 1 {
        for frame in window {
            check_cancel(cancel)?;
            emit(decode(frame))?;
        }
        return Ok(());
    }
    let batch_size = window.len().div_ceil(workers);
    let mut remaining = window.into_iter();
    std::thread::scope(|scope| {
        let mut tasks = Vec::new();
        // The coordinator occupies one of the allocated slots.
        while remaining.len() > batch_size {
            let frames = remaining.by_ref().take(batch_size).collect::<Vec<_>>();
            tasks.push(
                std::thread::Builder::new()
                    .spawn_scoped(scope, move || decode_batch(frames, cancel, decode))
                    .map_err(|_| {
                        AppError::Storage("cannot start a bounded record worker".into())
                    })?,
            );
        }
        let last = decode_batch(remaining, cancel, decode);
        let mut result = Ok(());
        for task in tasks {
            let decoded = task
                .join()
                .map_err(|_| AppError::Storage("record decoder worker stopped unexpectedly".into()))
                .and_then(|decoded| decoded);
            if result.is_ok() {
                result = decoded.and_then(|rows| emit_batch(rows, cancel, emit));
            }
        }
        result
            .and(last)
            .and_then(|rows| emit_batch(rows, cancel, emit))
    })
}

fn decode_batch<T, R>(
    frames: impl IntoIterator<Item = T>,
    cancel: &CancellationToken,
    decode: &impl Fn(T) -> R,
) -> Result<Vec<R>, AppError> {
    frames
        .into_iter()
        .map(|frame| {
            check_cancel(cancel)?;
            Ok(decode(frame))
        })
        .collect()
}

fn emit_batch<R>(
    rows: Vec<R>,
    cancel: &CancellationToken,
    emit: &mut impl FnMut(R) -> Result<(), AppError>,
) -> Result<(), AppError> {
    for row in rows {
        check_cancel(cancel)?;
        emit(row)?;
    }
    Ok(())
}

fn check_cancel(cancel: &CancellationToken) -> Result<(), AppError> {
    if cancel.is_cancelled() {
        Err(AppError::Cancelled)
    } else {
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::{collections::HashSet, num::NonZeroUsize};

    #[test]
    fn decoding_runs_on_multiple_threads_and_emits_in_record_order() {
        let mut input = 0..1025;
        let mut output = Vec::new();
        let mut threads = HashSet::new();
        decode_ordered(
            DecodeBudget::new(NonZeroUsize::new(4).unwrap(), 4096),
            &CancellationToken::new(),
            || Ok(input.next().map(|n| (n, 1))),
            |n| (n, std::thread::current().id()),
            |(n, thread)| {
                output.push(n);
                threads.insert(thread);
                Ok(())
            },
        )
        .unwrap();
        assert!(threads.len() >= 4);
        assert!(output.into_iter().eq(0..1025));
    }

    #[test]
    fn callback_error_preserves_its_priority_over_a_later_framing_error() {
        let mut input = [
            Ok(Some((0, 1))),
            Err(AppError::Policy("framing error".into())),
        ]
        .into_iter();
        let result = decode_ordered(
            DecodeBudget::new(NonZeroUsize::new(2).unwrap(), 4096),
            &CancellationToken::new(),
            || input.next().unwrap_or(Ok(None)),
            |n| n,
            |_| Err(AppError::Cancelled),
        );
        assert!(matches!(result, Err(AppError::Cancelled)));
    }

    #[test]
    fn cancellation_stops_emission_and_joins_the_bounded_window() {
        let cancel = CancellationToken::new();
        let mut emitted = 0;
        let result = decode_ordered(
            DecodeBudget::new(NonZeroUsize::new(4).unwrap(), 256),
            &cancel,
            || Ok(Some((0, 1))),
            |n| n,
            |_| {
                emitted += 1;
                cancel.cancel();
                Ok(())
            },
        );
        assert!(matches!(result, Err(AppError::Cancelled)));
        assert_eq!(emitted, 1);
    }
}
