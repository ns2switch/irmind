use super::{
    AuditLog, AutomationContext, CaseCommand, Command, FindingKind, JsonParser, LargeCaseUseCases,
    Repository, Result, Severity, anyhow, audit_source_name, input_files_large,
    parse_approval_args, parse_id, terminal_safe_path,
};

impl AutomationContext<'_, '_> {
    pub(crate) fn run(self, command: Command) -> Result<bool> {
        match command {
            Command::Demo { .. } => {
                Err(anyhow!("demo must start before opening persistent storage"))
            }
            cmd @ Command::Case { .. } => self.handle_case(cmd),
            cmd @ Command::Ingest { .. } => self.handle_ingest(cmd),
            cmd @ Command::Migrate { .. } => self.handle_migrate(cmd),
            cmd @ Command::Ask { .. } => self.handle_ask(cmd),
            cmd @ (Command::Approvals { .. }
            | Command::Approve { .. }
            | Command::Deny { .. }
            | Command::EditApproval { .. }) => self.handle_approvals(cmd),
            cmd @ (Command::AddFinding { .. }
            | Command::ConfirmFinding { .. }
            | Command::DismissFinding { .. }
            | Command::Findings { .. }) => self.handle_findings(cmd),
            cmd @ (Command::Report { .. } | Command::Evidence { .. } | Command::Seal { .. }) => {
                self.handle_custody(cmd)
            }
            cmd @ Command::Verify { .. } => self.handle_verify(cmd),
            cmd @ (Command::Graph { .. }
            | Command::GraphRebuild { .. }
            | Command::VerifyGraph { .. }
            | Command::Timeline { .. }) => self.handle_graph_summary(cmd),
            cmd @ (Command::Entity { .. }
            | Command::Neighbors { .. }
            | Command::EntityTimeline { .. }
            | Command::GraphPath { .. }) => self.handle_graph_entities(cmd),
            cmd @ (Command::TextSearch { .. } | Command::RawRecords { .. }) => {
                self.handle_graph_search(cmd)
            }
            cmd @ (Command::Export { .. } | Command::VerifyExport { .. } | Command::Tui { .. }) => {
                self.handle_export_and_tui(cmd)
            }
        }
    }

    fn handle_case(self, command: Command) -> Result<bool> {
        let Self {
            engine,
            store,
            guard,
            ..
        } = self;
        match command {
            Command::Case { command } => match command {
                CaseCommand::New {
                    title,
                    scope,
                    severity,
                } => {
                    let severity = Severity::parse(&severity)
                        .map_err(|_| anyhow!("severity must be low, medium, high or critical"))?;
                    let case = engine.create_case_with_severity(&title, severity, &scope)?;
                    println!("{}", case.id.as_str());
                }
                CaseCommand::List => {
                    for case in store.list_cases()? {
                        println!(
                            "{}\t{}\t{}",
                            case.id.as_str(),
                            if case.sealed { "sealed" } else { "open" },
                            irmind_app::ContentGuard::screen(guard.as_ref(), &case.title)?.text
                        );
                    }
                }
                CaseCommand::Show { case_id } => {
                    let case = store.get_case(&parse_id(&case_id)?)?;
                    println!(
                        "{}\nTitle: {}\nSeverity: {}\nScope: {}\nSealed: {}",
                        case.id.as_str(),
                        irmind_app::ContentGuard::screen(guard.as_ref(), &case.title)?.text,
                        case.severity.as_str(),
                        irmind_app::ContentGuard::screen(guard.as_ref(), &case.scope)?.text,
                        case.sealed
                    );
                }
                CaseCommand::Scope { case_id, scope } => {
                    engine.change_scope(&parse_id(&case_id)?, &scope)?;
                    println!("case scope updated and signed");
                }
            },
            _ => return Err(anyhow!("invalid command dispatch")),
        }
        Ok(false)
    }

    fn handle_ingest(self, command: Command) -> Result<bool> {
        let Self {
            engine,
            store,
            cancel,
            ..
        } = self;
        match command {
            Command::Ingest {
                case_id,
                path,
                copy_original,
            } => {
                let id = parse_id(&case_id)?;
                engine.verify_cancelable(&id, cancel)?;
                if store.get_case(&id)?.sealed {
                    return Err(anyhow!("case is sealed"));
                }
                let files = input_files_large(&path)?;
                let indexed: std::collections::BTreeMap<String, irmind_domain::SourceManifestV1> =
                    store
                        .entries(&id)?
                        .into_iter()
                        .filter(|entry| {
                            entry.kind == irmind_domain::AuditEventKind::SourceManifestV1
                        })
                        .filter_map(|entry| {
                            irmind_domain::SourceManifestV1::decode(&entry.payload)
                                .ok()
                                .map(|source| (source.source.clone(), source))
                        })
                        .collect();
                let parser = JsonParser;
                let large = LargeCaseUseCases {
                    engine,
                    store: store.as_ref(),
                    parser: &parser,
                };
                let source_root = if path.is_dir() {
                    path.as_path()
                } else {
                    path.parent()
                        .ok_or_else(|| anyhow!("source has no parent"))?
                };
                for files in files.chunks(4) {
                    let mut pending = Vec::new();
                    for file in files {
                        let source = audit_source_name(&path, file)?;
                        if let Some(existing) = indexed.get(&source) {
                            large
                                .store
                                .verify_local_source(source_root, existing, cancel)?;
                            println!("skipped {}", terminal_safe_path(file));
                        } else {
                            pending.push(source);
                        }
                    }
                    for (source, hash) in large.ingest_local_batch(
                        &id,
                        source_root,
                        &pending,
                        copy_original,
                        cancel,
                    )? {
                        println!(
                            "{} {}",
                            hash.as_str(),
                            terminal_safe_path(&source_root.join(source))
                        );
                    }
                }
                let bundles = large.compact_case(&id, cancel)?;
                println!("created {bundles} signed Parquet bundles");
            }
            _ => return Err(anyhow!("invalid command dispatch")),
        }
        Ok(false)
    }

    fn handle_migrate(self, command: Command) -> Result<bool> {
        let Self {
            engine,
            store,
            cancel,
            ..
        } = self;
        let Command::Migrate { case_id } = command else {
            return Err(anyhow!("invalid command dispatch"));
        };
        let id = parse_id(&case_id)?;
        let parser = JsonParser;
        let large = LargeCaseUseCases {
            engine,
            store: store.as_ref(),
            parser: &parser,
        };
        let count = large.migrate_legacy(&id, cancel)?;
        let bundles = if engine.repo.get_case(&id)?.sealed {
            0
        } else {
            large.compact_case(&id, cancel)?
        };
        println!("converted {count} legacy copied sources to signed Parquet artifacts");
        println!("created {bundles} signed Parquet bundles");
        Ok(false)
    }

    fn handle_ask(self, command: Command) -> Result<bool> {
        let Self {
            engine,
            registry,
            llm_module,
            cancel,
            ..
        } = self;
        match command {
            Command::Ask { case_id, alert } => {
                let model = registry.llm(llm_module.ok_or_else(|| {
                    anyhow!("select an approved LLM explicitly with --llm-module")
                })?)?;
                println!(
                    "{}",
                    engine.investigate_with_cancel(&parse_id(&case_id)?, &alert, model, cancel)?
                );
            }
            _ => return Err(anyhow!("invalid command dispatch")),
        }
        Ok(false)
    }

    fn handle_approvals(self, command: Command) -> Result<bool> {
        let Self { engine, .. } = self;
        match command {
            Command::Approvals { case_id } => {
                for request in engine.pending_approvals(&parse_id(&case_id)?)? {
                    println!(
                        "{} {:?} {} {:?}",
                        request.id,
                        request.mode,
                        request.tool.as_str(),
                        request.args
                    );
                }
            }
            Command::Approve {
                case_id,
                request_id,
            } => {
                println!("{}", engine.approve(&parse_id(&case_id)?, &request_id)?);
            }
            Command::Deny {
                case_id,
                request_id,
                reason,
            } => {
                println!(
                    "{}",
                    engine.deny(&parse_id(&case_id)?, &request_id, &reason)?
                );
            }
            Command::EditApproval {
                case_id,
                request_id,
                args_json,
            } => {
                let args = parse_approval_args(&args_json)?;
                println!(
                    "{}",
                    engine.edit_approval(&parse_id(&case_id)?, &request_id, args)?
                );
            }
            _ => return Err(anyhow!("invalid command dispatch")),
        }
        Ok(false)
    }

    fn handle_findings(self, command: Command) -> Result<bool> {
        let Self { engine, guard, .. } = self;
        match command {
            Command::AddFinding {
                case_id,
                kind,
                value,
                evidence_hash,
            } => println!(
                "{}",
                engine.add_finding(
                    &parse_id(&case_id)?,
                    FindingKind::parse(&kind)?,
                    &value,
                    &evidence_hash
                )?
            ),
            Command::ConfirmFinding {
                case_id,
                finding_id,
            } => {
                engine.confirm_finding(&parse_id(&case_id)?, &finding_id)?;
                println!("finding confirmed");
            }
            Command::DismissFinding {
                case_id,
                finding_id,
                reason,
            } => {
                engine.dismiss_finding(&parse_id(&case_id)?, &finding_id, &reason)?;
                println!("finding dismissed");
            }
            Command::Findings { case_id } => {
                for finding in engine.findings(&parse_id(&case_id)?)? {
                    println!(
                        "{} {:?} {} {} [{}]",
                        finding.id,
                        finding.kind,
                        if finding.confirmed {
                            "confirmed"
                        } else if finding.dismissed {
                            "dismissed"
                        } else {
                            "proposed"
                        },
                        irmind_app::ContentGuard::screen(guard.as_ref(), &finding.value)?.text,
                        finding.evidence_hash
                    );
                }
            }
            _ => return Err(anyhow!("invalid command dispatch")),
        }
        Ok(false)
    }
}
