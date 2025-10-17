use prometheus::{
    Counter, Gauge, Histogram, IntCounter, IntGauge, Registry, Opts, HistogramOpts,
};
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Clone)]
pub struct LegionMetrics {
    registry: Arc<Registry>,
    
    // Stage A metrics
    pub stage_a_requests_total: IntCounter,
    pub stage_a_rejections_total: IntCounter,
    pub stage_a_replay_attempts_total: IntCounter,
    pub stage_a_processing_duration: Histogram,
    
    // Stage B metrics
    pub stage_b_queue_depth: IntGauge,
    pub stage_b_batch_size: Histogram,
    pub stage_b_proof_hit_rate: Gauge,
    pub stage_b_verification_duration: Histogram,
    
    // System metrics
    pub active_connections: IntGauge,
    pub key_rotations_total: IntCounter,
    pub config_reloads_total: IntCounter,
}

impl LegionMetrics {
    pub fn new() -> prometheus::Result<Self> {
        let registry = Arc::new(Registry::new());
        
        let stage_a_requests_total = IntCounter::with_opts(
            Opts::new("legion_stage_a_requests_total", "Total Stage A requests")
        )?;
        
        let stage_a_rejections_total = IntCounter::with_opts(
            Opts::new("legion_stage_a_rejections_total", "Total Stage A rejections")
        )?;
        
        let stage_a_replay_attempts_total = IntCounter::with_opts(
            Opts::new("legion_stage_a_replay_attempts_total", "Total replay attempts detected")
        )?;
        
        let stage_a_processing_duration = Histogram::with_opts(
            HistogramOpts::new("legion_stage_a_processing_duration_seconds", "Stage A processing time")
        )?;
        
        let stage_b_queue_depth = IntGauge::with_opts(
            Opts::new("legion_stage_b_queue_depth", "Current Stage B queue depth")
        )?;
        
        let stage_b_batch_size = Histogram::with_opts(
            HistogramOpts::new("legion_stage_b_batch_size", "Stage B batch sizes")
        )?;
        
        let stage_b_proof_hit_rate = Gauge::with_opts(
            Opts::new("legion_stage_b_proof_hit_rate", "Stage B proof verification hit rate")
        )?;
        
        let stage_b_verification_duration = Histogram::with_opts(
            HistogramOpts::new("legion_stage_b_verification_duration_seconds", "Stage B verification time")
        )?;
        
        let active_connections = IntGauge::with_opts(
            Opts::new("legion_active_connections", "Current active connections")
        )?;
        
        let key_rotations_total = IntCounter::with_opts(
            Opts::new("legion_key_rotations_total", "Total key rotations performed")
        )?;
        
        let config_reloads_total = IntCounter::with_opts(
            Opts::new("legion_config_reloads_total", "Total configuration reloads")
        )?;
        
        // Register all metrics
        registry.register(Box::new(stage_a_requests_total.clone()))?;
        registry.register(Box::new(stage_a_rejections_total.clone()))?;
        registry.register(Box::new(stage_a_replay_attempts_total.clone()))?;
        registry.register(Box::new(stage_a_processing_duration.clone()))?;
        registry.register(Box::new(stage_b_queue_depth.clone()))?;
        registry.register(Box::new(stage_b_batch_size.clone()))?;
        registry.register(Box::new(stage_b_proof_hit_rate.clone()))?;
        registry.register(Box::new(stage_b_verification_duration.clone()))?;
        registry.register(Box::new(active_connections.clone()))?;
        registry.register(Box::new(key_rotations_total.clone()))?;
        registry.register(Box::new(config_reloads_total.clone()))?;
        
        Ok(Self {
            registry,
            stage_a_requests_total,
            stage_a_rejections_total,
            stage_a_replay_attempts_total,
            stage_a_processing_duration,
            stage_b_queue_depth,
            stage_b_batch_size,
            stage_b_proof_hit_rate,
            stage_b_verification_duration,
            active_connections,
            key_rotations_total,
            config_reloads_total,
        })
    }
    
    pub fn registry(&self) -> Arc<Registry> {
        self.registry.clone()
    }
    
    pub fn record_stage_a_request(&self, rejected: bool, replay_attempt: bool, duration: f64) {
        self.stage_a_requests_total.inc();
        if rejected {
            self.stage_a_rejections_total.inc();
        }
        if replay_attempt {
            self.stage_a_replay_attempts_total.inc();
        }
        self.stage_a_processing_duration.observe(duration);
    }
    
    pub fn record_stage_b_batch(&self, batch_size: usize, hit_rate: f64, duration: f64) {
        self.stage_b_batch_size.observe(batch_size as f64);
        self.stage_b_proof_hit_rate.set(hit_rate);
        self.stage_b_verification_duration.observe(duration);
    }
    
    pub fn update_queue_depth(&self, depth: i64) {
        self.stage_b_queue_depth.set(depth);
    }
    
    pub fn record_key_rotation(&self) {
        self.key_rotations_total.inc();
    }
    
    pub fn record_config_reload(&self) {
        self.config_reloads_total.inc();
    }
    
    pub fn get_reject_rate(&self) -> f64 {
        let total = self.stage_a_requests_total.get() as f64;
        let rejections = self.stage_a_rejections_total.get() as f64;
        if total > 0.0 { rejections / total } else { 0.0 }
    }
}