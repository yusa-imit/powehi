use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use powehi_domain::{
    device::DeviceId,
    error::DomainError,
    key_package::{KeyPackage, KeyPackageId},
};
use powehi_port_inbound::key_package::KeyPackageUseCase;
use powehi_port_outbound::key_package_repo::KeyPackageRepository;
use tracing::instrument;

pub struct KeyPackageService {
    kp_repo: Arc<dyn KeyPackageRepository>,
}

impl KeyPackageService {
    pub fn new(kp_repo: Arc<dyn KeyPackageRepository>) -> Self {
        Self { kp_repo }
    }
}

#[async_trait]
impl KeyPackageUseCase for KeyPackageService {
    #[instrument(skip(self, packages), fields(device_id = %device_id, count = packages.len()))]
    async fn upload(
        &self,
        device_id: &DeviceId,
        packages: Vec<Bytes>,
    ) -> Result<Vec<KeyPackageId>, DomainError> {
        let mut ids = Vec::with_capacity(packages.len());
        for data in packages {
            let kp = KeyPackage::new(device_id.clone(), data.to_vec());
            let id = kp.id.clone();
            self.kp_repo.save(&kp).await?;
            ids.push(id);
        }
        Ok(ids)
    }

    #[instrument(skip(self), fields(target_device_id = %target_device_id))]
    async fn fetch_one(
        &self,
        target_device_id: &DeviceId,
    ) -> Result<Bytes, DomainError> {
        let kp = self
            .kp_repo
            .fetch_one(target_device_id)
            .await?
            .ok_or_else(|| DomainError::NotFound("key_package".into()))?;
        Ok(Bytes::from(kp.data))
    }

    #[instrument(skip(self), fields(device_id = %device_id))]
    async fn count(
        &self,
        device_id: &DeviceId,
    ) -> Result<u64, DomainError> {
        self.kp_repo.count_available(device_id).await
    }
}
