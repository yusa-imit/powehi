/// Generated types and service stubs for the inter-region gRPC mesh.
pub mod region {
    // tonic emits `Result<Response<T>, Status>` signatures whose Err variant is over
    // clippy's large-error threshold (`result_large_err`, newly triggered on this code
    // by Rust 1.98). The signatures come from generated code and cannot be reshaped
    // here, so the lint is silenced for this module only.
    #![allow(clippy::result_large_err)]

    tonic::include_proto!("region");
}

#[cfg(test)]
mod tests {
    use super::region::*;

    #[test]
    fn forward_status_accepted_has_correct_value() {
        assert_eq!(ForwardStatus::Accepted as i32, 1);
    }

    #[test]
    fn health_status_healthy_has_correct_value() {
        assert_eq!(HealthStatus::Healthy as i32, 1);
    }

    #[test]
    fn consume_status_consumed_has_correct_value() {
        assert_eq!(ConsumeStatus::Consumed as i32, 1);
    }

    #[test]
    fn envelope_type_application_has_correct_value() {
        assert_eq!(EnvelopeType::Application as i32, 1);
    }
}
