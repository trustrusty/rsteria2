//! Brutal congestion controller — a quinn port of Hysteria2's signature
//! fixed-rate, loss-tolerant controller (Go: core/internal/congestion/brutal).
//!
//! Brutal sends at a configured constant bitrate and never backs off on loss.
//! Instead it tracks the recent ACK success rate and *speeds up* to compensate
//! for losses (sending `rate / ackRate`, so 20% loss → ~25% faster).
//!
//! Mapping to quinn: quinn derives its pacing rate from the congestion window
//! (`window / srtt`), so unlike the Go reference (which has an independent
//! pacer) we encode the target rate into the window itself:
//! `window = bps * srtt / ackRate`. quinn's window-capped pacing then emits at
//! ~`bps / ackRate`. `on_congestion_event` deliberately does **not** shrink the
//! window — that is the whole point of Brutal.

use std::{
    any::Any,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use quinn_proto::congestion::{BbrConfig, Controller, ControllerFactory};
use quinn_proto::RttEstimator;

const SLOT_COUNT: usize = 5; // seconds of ACK/loss history
const MIN_SAMPLE_COUNT: u64 = 50;
const MIN_ACK_RATE: f64 = 0.8;

#[derive(Clone, Copy, Default)]
struct Slot {
    ts: i64, // seconds since `base`
    ack: u64,
    loss: u64,
}

#[derive(Clone)]
pub struct Brutal {
    /// Shared target send rate in bytes/sec. Read live on every `window()` so
    /// it can be clamped to the server's advertised Rx after the handshake
    /// (quinn cannot swap the controller itself, but it can read a new rate).
    rate: Arc<AtomicU64>,
    mtu: u64,
    base: Instant,
    srtt: Duration,
    ack_rate: f64,
    slots: [Slot; SLOT_COUNT],
}

impl Brutal {
    fn new(rate: Arc<AtomicU64>, mtu: u16) -> Self {
        Self {
            rate,
            mtu: mtu as u64,
            base: Instant::now(),
            srtt: Duration::ZERO,
            ack_rate: 1.0,
            slots: [Slot::default(); SLOT_COUNT],
        }
    }

    fn secs(&self, now: Instant) -> i64 {
        now.saturating_duration_since(self.base).as_secs() as i64
    }

    fn record(&mut self, now: Instant, ack: u64, loss: u64) {
        let ts = self.secs(now);
        let slot = &mut self.slots[(ts as usize) % SLOT_COUNT];
        if slot.ts == ts {
            slot.ack += ack;
            slot.loss += loss;
        } else {
            slot.ts = ts;
            slot.ack = ack;
            slot.loss = loss;
        }
        self.update_ack_rate(ts);
    }

    fn update_ack_rate(&mut self, now_ts: i64) {
        let min_ts = now_ts - SLOT_COUNT as i64;
        let (mut acks, mut losses) = (0u64, 0u64);
        for s in &self.slots {
            if s.ts < min_ts {
                continue;
            }
            acks += s.ack;
            losses += s.loss;
        }
        if acks + losses < MIN_SAMPLE_COUNT {
            self.ack_rate = 1.0;
            return;
        }
        let rate = acks as f64 / (acks + losses) as f64;
        self.ack_rate = rate.max(MIN_ACK_RATE);
    }
}

impl Controller for Brutal {
    fn on_ack(
        &mut self,
        now: Instant,
        _sent: Instant,
        _bytes: u64,
        _app_limited: bool,
        rtt: &RttEstimator,
    ) {
        self.srtt = rtt.get();
        self.record(now, 1, 0);
    }

    fn on_congestion_event(
        &mut self,
        now: Instant,
        _sent: Instant,
        _is_persistent_congestion: bool,
        lost_bytes: u64,
    ) {
        // Record loss for the ACK-rate estimate, but never shrink the window.
        let lost_pkts = (lost_bytes / self.mtu.max(1)).max(1);
        self.record(now, 0, lost_pkts);
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.mtu = new_mtu as u64;
    }

    fn window(&self) -> u64 {
        let floor = (self.mtu * 2).max(10_240);
        if self.srtt.is_zero() {
            return floor;
        }
        let bps = self.rate.load(Ordering::Relaxed) as f64;
        let cwnd = bps * self.srtt.as_secs_f64() / self.ack_rate;
        (cwnd as u64).max(floor)
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(self.clone())
    }

    fn initial_window(&self) -> u64 {
        (self.mtu * 2).max(10_240)
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

/// Factory that builds a fresh [`Brutal`] controller per connection, all
/// sharing the same live [`rate`](Self::rate) handle.
pub struct BrutalFactory {
    /// Shared target send rate in bytes/sec (see [`Brutal::rate`]).
    pub rate: Arc<AtomicU64>,
}

impl ControllerFactory for BrutalFactory {
    fn build(self: Arc<Self>, _now: Instant, current_mtu: u16) -> Box<dyn Controller> {
        Box::new(Brutal::new(self.rate.clone(), current_mtu))
    }
}

/// A controller that runs both Brutal and BBR in parallel and lets either one
/// govern the send window via a shared flag. This is how the client honours the
/// server's post-handshake `CC-RX: auto` (switch Brutal → BBR) despite quinn
/// fixing the controller at connect time: quinn only ever sees this one
/// wrapper, while we flip which inner controller's `window()` is authoritative.
///
/// Both inner controllers are fed every path event so the inactive one stays
/// warm and the switch is seamless.
pub(crate) struct SwitchableController {
    brutal: Brutal,
    bbr: Box<dyn Controller>,
    use_bbr: Arc<AtomicBool>,
}

impl SwitchableController {
    fn bbr_active(&self) -> bool {
        self.use_bbr.load(Ordering::Relaxed)
    }
}

impl Controller for SwitchableController {
    fn on_sent(&mut self, now: Instant, bytes: u64, last_packet_number: u64) {
        self.brutal.on_sent(now, bytes, last_packet_number);
        self.bbr.on_sent(now, bytes, last_packet_number);
    }

    fn on_ack(
        &mut self,
        now: Instant,
        sent: Instant,
        bytes: u64,
        app_limited: bool,
        rtt: &RttEstimator,
    ) {
        self.brutal.on_ack(now, sent, bytes, app_limited, rtt);
        self.bbr.on_ack(now, sent, bytes, app_limited, rtt);
    }

    fn on_end_acks(
        &mut self,
        now: Instant,
        in_flight: u64,
        app_limited: bool,
        largest_packet_num_acked: Option<u64>,
    ) {
        self.brutal
            .on_end_acks(now, in_flight, app_limited, largest_packet_num_acked);
        self.bbr
            .on_end_acks(now, in_flight, app_limited, largest_packet_num_acked);
    }

    fn on_congestion_event(
        &mut self,
        now: Instant,
        sent: Instant,
        is_persistent_congestion: bool,
        lost_bytes: u64,
    ) {
        self.brutal
            .on_congestion_event(now, sent, is_persistent_congestion, lost_bytes);
        self.bbr
            .on_congestion_event(now, sent, is_persistent_congestion, lost_bytes);
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.brutal.on_mtu_update(new_mtu);
        self.bbr.on_mtu_update(new_mtu);
    }

    fn window(&self) -> u64 {
        if self.bbr_active() {
            self.bbr.window()
        } else {
            self.brutal.window()
        }
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(SwitchableController {
            brutal: self.brutal.clone(),
            bbr: self.bbr.clone_box(),
            use_bbr: self.use_bbr.clone(),
        })
    }

    fn initial_window(&self) -> u64 {
        if self.bbr_active() {
            self.bbr.initial_window()
        } else {
            self.brutal.initial_window()
        }
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

/// Factory for [`SwitchableController`]. `rate` drives Brutal; flipping
/// `use_bbr` hands the window over to BBR.
pub(crate) struct SwitchableFactory {
    pub rate: Arc<AtomicU64>,
    pub use_bbr: Arc<AtomicBool>,
}

impl ControllerFactory for SwitchableFactory {
    fn build(self: Arc<Self>, now: Instant, current_mtu: u16) -> Box<dyn Controller> {
        let brutal = Brutal::new(self.rate.clone(), current_mtu);
        let bbr = Arc::new(BbrConfig::default()).build(now, current_mtu);
        Box::new(SwitchableController {
            brutal,
            bbr,
            use_bbr: self.use_bbr.clone(),
        })
    }
}
