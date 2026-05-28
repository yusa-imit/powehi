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
    async fn fetch_one(&self, target_device_id: &DeviceId) -> Result<Bytes, DomainError> {
        let kp = self
            .kp_repo
            .fetch_one(target_device_id)
            .await?
            .ok_or_else(|| DomainError::NotFound("key_package".into()))?;
        Ok(Bytes::from(kp.data))
    }

    #[instrument(skip(self), fields(device_id = %device_id))]
    async fn count(&self, device_id: &DeviceId) -> Result<u64, DomainError> {
        self.kp_repo.count_available(device_id).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use powehi_domain::key_package::{KeyPackage, KeyPackageId};
    use powehi_port_outbound::key_package_repo::KeyPackageRepository;
    use std::collections::HashMap;
    use std::sync::Mutex;

    struct FakeKpRepo {
        store: Mutex<HashMap<KeyPackageId, KeyPackage>>,
    }
    impl FakeKpRepo {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                store: Mutex::new(HashMap::new()),
            })
        }
    }
    #[async_trait::async_trait]
    impl KeyPackageRepository for FakeKpRepo {
        async fn save(&self, kp: &KeyPackage) -> Result<(), DomainError> {
            self.store.lock().unwrap().insert(kp.id.clone(), kp.clone());
            Ok(())
        }
        async fn fetch_one(&self, device_id: &DeviceId) -> Result<Option<KeyPackage>, DomainError> {
            let mut store = self.store.lock().unwrap();
            let key = store
                .values()
                .find(|kp| kp.device_id == *device_id && !kp.consumed)
                .map(|kp| kp.id.clone());
            if let Some(k) = key {
                let kp = store.get_mut(&k).unwrap();
                kp.consumed = true;
                return Ok(Some(kp.clone()));
            }
            Ok(None)
        }
        async fn count_available(&self, device_id: &DeviceId) -> Result<u64, DomainError> {
            let count = self
                .store
                .lock()
                .unwrap()
                .values()
                .filter(|kp| kp.device_id == *device_id && !kp.consumed)
                .count() as u64;
            Ok(count)
        }
        async fn delete(&self, id: &KeyPackageId) -> Result<(), DomainError> {
            self.store.lock().unwrap().remove(id);
            Ok(())
        }
        async fn mark_consumed(
            &self,
            id: &KeyPackageId,
        ) -> Result<powehi_domain::key_package::ConsumeResult, DomainError> {
            use powehi_domain::key_package::ConsumeResult;
            let mut store = self.store.lock().unwrap();
            match store.get_mut(id) {
                Some(kp) if kp.consumed => Ok(ConsumeResult::AlreadyConsumed),
                Some(kp) => {
                    kp.consumed = true;
                    Ok(ConsumeResult::Consumed)
                }
                None => Ok(ConsumeResult::NotFound),
            }
        }
    }

    #[tokio::test]
    async fn upload_returns_ids_for_all_packages() {
        let repo = FakeKpRepo::new();
        let svc = KeyPackageService::new(repo.clone());
        let device = DeviceId::new();
        let ids = svc
            .upload(
                &device,
                vec![Bytes::from_static(b"kp1"), Bytes::from_static(b"kp2")],
            )
            .await
            .unwrap();
        assert_eq!(ids.len(), 2);
        assert_eq!(repo.store.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn fetch_one_returns_raw_data() {
        let repo = FakeKpRepo::new();
        let svc = KeyPackageService::new(repo.clone());
        let device = DeviceId::new();
        svc.upload(&device, vec![Bytes::from_static(b"kp-data")])
            .await
            .unwrap();
        let data = svc.fetch_one(&device).await.unwrap();
        assert_eq!(data.as_ref(), b"kp-data");
    }

    #[tokio::test]
    async fn fetch_one_empty_returns_not_found() {
        let svc = KeyPackageService::new(FakeKpRepo::new());
        let err = svc.fetch_one(&DeviceId::new()).await.unwrap_err();
        assert!(matches!(err, DomainError::NotFound(_)));
    }

    #[tokio::test]
    async fn count_reflects_available_packages() {
        let repo = FakeKpRepo::new();
        let svc = KeyPackageService::new(repo.clone());
        let device = DeviceId::new();
        assert_eq!(svc.count(&device).await.unwrap(), 0);
        svc.upload(
            &device,
            vec![
                Bytes::from_static(b"a"),
                Bytes::from_static(b"b"),
                Bytes::from_static(b"c"),
            ],
        )
        .await
        .unwrap();
        assert_eq!(svc.count(&device).await.unwrap(), 3);
        svc.fetch_one(&device).await.unwrap();
        assert_eq!(svc.count(&device).await.unwrap(), 2);
    }
}
