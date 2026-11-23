use super::*;
use irmind_mod_parser_elb::ElbSourceDecoder;
use std::sync::Arc;

#[test]
fn source_mapping_contract_for_both_load_balancer_layouts() {
    let mapper = Arc::new(ElbMapping::new().unwrap());
    for (name, fixture) in [
        (
            "alb.log",
            include_bytes!("../../../testkit/fixtures/parser-elb/source/alb.log").as_slice(),
        ),
        (
            "classic.log",
            include_bytes!("../../../testkit/fixtures/parser-elb/source/classic.log").as_slice(),
        ),
    ] {
        irmind_testkit::run_source_mapping_contract(
            Arc::new(ElbSourceDecoder),
            mapper.clone(),
            name,
            fixture,
            2,
        )
        .unwrap();
    }
}
