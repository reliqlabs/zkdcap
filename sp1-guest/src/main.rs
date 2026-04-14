#![no_main]
sp1_zkvm::entrypoint!(main);

use dcap_qvl::verify::PreVerifiedInputs;
use zkdcap_core::DcapJournal;

pub fn main() {
    let quote: Vec<u8> = sp1_zkvm::io::read();
    let pre_verified: PreVerifiedInputs = sp1_zkvm::io::read();
    let now_secs: u64 = sp1_zkvm::io::read();

    let report = dcap_qvl::verify::sp1::verify_lite(&quote, &pre_verified)
        .expect("DCAP verification failed");

    let td_report = report.report.as_td10().expect("not a TDX quote");

    let journal = DcapJournal {
        quote_hash: DcapJournal::hash_quote(&quote),
        quote_verified: true,
        tcb_status: report.status.clone(),
        advisory_ids: report.advisory_ids.clone(),
        mr_td: hex::encode(td_report.mr_td),
        rtmr0: hex::encode(td_report.rt_mr0),
        rtmr1: hex::encode(td_report.rt_mr1),
        rtmr2: hex::encode(td_report.rt_mr2),
        rtmr3: hex::encode(td_report.rt_mr3),
        report_data: hex::encode(td_report.report_data),
        verification_timestamp: now_secs,
    };

    sp1_zkvm::io::commit(&journal);
}
