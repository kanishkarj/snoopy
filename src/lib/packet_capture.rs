use pcap::Device;
use std::fmt::{Display, Formatter};

pub struct PacketCapture {
    device: Device
}

impl PacketCapture {

    pub fn new(device : Device) -> PacketCapture {
        PacketCapture {
            device
        }
    }

    pub fn list_devices() -> Result<Vec<String>, pcap::Error> {
        Ok(Device::list()?
            .iter()
            .map(|val| val.name.clone())
            .collect())
    }

}
