#![no_main]
use irmind_app::subagents::*;
use libfuzzer_sys::fuzz_target;

fn check<T: SubagentRecord>(bytes: &[u8]) {
    if let Ok(record) = T::decode(bytes) {
        let canonical = record.canonical().unwrap();
        assert_eq!(canonical, bytes);
        assert_eq!(
            record.identity().unwrap(),
            T::decode(&canonical).unwrap().identity().unwrap()
        );
        let mut extra = canonical;
        extra.push(b' ');
        assert!(T::decode(&extra).is_err());
    }
}

fuzz_target!(|bytes: &[u8]| {
    if bytes.len() > 1024 * 1024 {
        return;
    }
    check::<SubagentSourcePageV1>(bytes);
    check::<SubagentSourceSetV1>(bytes);
    check::<SubagentTypeSnapshotV1>(bytes);
    check::<SubagentPlanV1>(bytes);
    check::<SubagentPlanApprovalV1>(bytes);
    check::<SubagentReservationV1>(bytes);
    check::<SubagentCheckpointV1>(bytes);
    check::<SubagentResultV1>(bytes);
    if let Ok(entry) = SubagentBranchEntry::decode(bytes) {
        assert_eq!(entry.canonical().unwrap(), bytes);
        assert_eq!(entry.hash, entry.body.identity().unwrap());
        let mut changed = entry.clone();
        changed.body.at ^= 1;
        assert!(changed.canonical().is_err());
    }
});
