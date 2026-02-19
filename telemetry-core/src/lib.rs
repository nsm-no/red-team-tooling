pub mod config {
    #[derive(Debug, Clone)]
    pub struct TelemetryConfig {
        pub seed: u64,
        pub runtime_seconds: u32,
        pub network: Option<NetworkConfig>,  // <-- ADD THIS
    }

    #[derive(Debug, Clone)]
    pub struct NetworkConfig {
        pub http_target_ip: String,
        pub http_port: u16,
    }

    impl Default for TelemetryConfig {
        fn default() -> Self {
            Self {
                seed: 0x424242,
                runtime_seconds: 120,
                network: Some(NetworkConfig {  // <-- ADD DEFAULT
                    http_target_ip: "127.0.0.1".to_string(),
                    http_port: 8080,
                }),
            }
        }
    }
}