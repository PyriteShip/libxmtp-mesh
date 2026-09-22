use xmtp_proto::mls_v1::{
    FetchKeyPackagesRequest, FetchKeyPackagesResponse, UploadKeyPackageRequest,
    fetch_key_packages_response::KeyPackage,
};

use super::{MeshNode, NodeEvent};
use crate::MeshError;
use crate::mls_parse::verify_key_package;

impl MeshNode {
    pub(crate) fn upload_key_package(&self, req: UploadKeyPackageRequest) -> Result<(), MeshError> {
        let bytes = req
            .key_package
            .ok_or_else(|| MeshError::InvalidRequest("missing key_package".into()))?
            .key_package_tls_serialized;
        let installation = verify_key_package(&bytes)?;
        {
            let mut store = self.inner.store.lock();
            // D7: one installation per inbox. Check/set the local installation
            // *before* writing anything, so a rejected installation's key
            // package is never stored (and can't leak out via FetchKeyPackages).
            match store.local_installation()? {
                None => store.set_local_installation(&installation)?,
                Some(local) if local != installation => {
                    return Err(MeshError::InvalidRequest(
                        "a mesh node serves exactly one local installation".into(),
                    ));
                }
                Some(_) => {}
            }
            store.put_key_package(&installation, &bytes)?;
        }
        self.emit(vec![NodeEvent::LocalKeyPackageChanged]);
        Ok(())
    }

    pub(crate) fn fetch_key_packages(
        &self,
        req: FetchKeyPackagesRequest,
    ) -> Result<FetchKeyPackagesResponse, MeshError> {
        let mut store = self.inner.store.lock();
        let key_packages = req
            .installation_keys
            .iter()
            .map(|installation| {
                store
                    .key_package(installation)?
                    .map(|kp| KeyPackage {
                        key_package_tls_serialized: kp,
                    })
                    .ok_or_else(|| {
                        MeshError::NotFound(format!("key package for {}", hex::encode(installation)))
                    })
            })
            .collect::<Result<Vec<_>, MeshError>>()?;
        Ok(FetchKeyPackagesResponse { key_packages })
    }

    pub fn has_key_package(&self, installation: &[u8]) -> Result<bool, MeshError> {
        Ok(self.inner.store.lock().key_package(installation)?.is_some())
    }
}
