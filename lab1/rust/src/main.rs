fn main() {
    use pcap::Device;

    let interface = Device::list()
        .unwrap()
        .into_iter()
        .find(|d| d.name == "en0")
        .unwrap();

    let mut cap = pcap::Capture::from_device(interface)
        .unwrap()
        .promisc(true)
        .snaplen(65535)
        .timeout(1000)
        .open()
        .unwrap();

    while let running = 1{
        match cap.next_packet() {
            Ok(packet) => {
                println!("\n------ NEW PACKET ------\n{:?}\n------------------------", packet);
            }
            Err(e) => {
                println!("Error receiving packet: {:?}", e);
            }
        }
    } 
}
