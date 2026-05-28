/// Generated types and service stubs for the inter-region gRPC mesh.
pub mod region {
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
