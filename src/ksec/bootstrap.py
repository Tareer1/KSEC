"""Application bootstrap.

Wires configuration, logging, the database, migrations and core services
together (spec: Startup Sequence).
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ksec.adapters.registry import AdapterRegistry
from ksec.adversary.service import AdversaryService
from ksec.api.tokens import TokenStore
from ksec.assets.service import AssetService
from ksec.audit.service import AuditService
from ksec.authorization.service import AuthorizationService
from ksec.backups.service import BackupService
from ksec.capabilities.explain import ExplanationService
from ksec.capabilities.registry import CapabilityRegistry
from ksec.cases.service import CaseService
from ksec.config.loader import KsecConfig
from ksec.correlation.service import CorrelationService
from ksec.db.connection import Database
from ksec.db.migrations import MigrationRunner
from ksec.dfir.service import DfirService
from ksec.evidence.service import EvidenceService
from ksec.endpoint.service import EndpointService
from ksec.findings.service import FindingService
from ksec.grc.service import GrcService
from ksec.malware.service import MalwareService
from ksec.installer.service import ToolInstallManager
from ksec.jobs.models import JobRepository
from ksec.knowledge.service import KnowledgeService
from ksec.learning.service import LearningService
from ksec.logging_setup import setup_logging
from ksec.notifications.service import EventBus, NotificationService
from ksec.plugins.manager import PluginManager
from ksec.policies.engine import PolicyEngine
from ksec.redteam.service import AtomicService
from ksec.vuln.service import VulnService
from ksec.rbac.roles import RbacService
from ksec.reporting.service import ReportService
from ksec.scheduler.service import Scheduler
from ksec.sessions.manager import SessionManager
from ksec.soc.alerts import AlertService
from ksec.soc.normalizer import EventStore
from ksec.soc.pipeline import SocPipeline
from ksec.soc.rules import RuleStore
from ksec.threat_intel.service import ThreatIntelService
from ksec.updates.service import UpdateService
from ksec.workflows.engine import WorkflowEngine
from ksec.workflows.store import WorkflowStore
from ksec.workflows.triggers import TriggerStore
from ksec.modules.registry import ModuleRegistry
from ksec.purple.service import PurpleService
from ksec.change.service import ChangeService

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
MIGRATIONS_DIR = PROJECT_ROOT / "migrations"
BUNDLED_PLUGINS_DIR = PROJECT_ROOT / "plugins"


@dataclass
class KsecContext:
    """Holds every initialized service for the lifetime of one CLI run."""

    config: KsecConfig
    db: Database
    rbac: RbacService
    authz: AuthorizationService
    audit: AuditService
    sessions: SessionManager
    policy: PolicyEngine
    jobs: JobRepository
    adapters: AdapterRegistry
    capabilities: CapabilityRegistry
    plugins: PluginManager
    scheduler: Scheduler
    workflows: WorkflowEngine
    assets: AssetService
    findings: FindingService
    evidence: EvidenceService
    cases: CaseService
    correlation: CorrelationService
    installer: ToolInstallManager
    learning: LearningService
    reports: ReportService
    notifications: NotificationService
    events: EventBus
    backups: BackupService
    workflow_store: WorkflowStore
    dfir: DfirService
    intel: ThreatIntelService
    explain: ExplanationService
    knowledge: KnowledgeService
    api_tokens: TokenStore
    soc: SocPipeline
    soc_events: EventStore
    soc_rules: RuleStore
    soc_alerts: AlertService
    adversary: AdversaryService
    vuln: VulnService
    atomic: AtomicService
    updates: UpdateService
    grc: GrcService
    malware: MalwareService
    endpoint: EndpointService
    modules: ModuleRegistry
    purple: PurpleService
    change: ChangeService
    triggers: TriggerStore

    def close(self) -> None:
        self.scheduler.stop()
        self.db.close()


def bootstrap(overrides: dict | None = None, run_migrations: bool = True) -> KsecContext:
    config = KsecConfig.load(overrides)
    config.data_dir.mkdir(parents=True, exist_ok=True)
    setup_logging(config.log_level, str(config.log_file))

    db = Database(config.db_path).connect()
    if run_migrations:
        MigrationRunner(db, MIGRATIONS_DIR).apply()

    rbac = RbacService(db)
    rbac.seed()
    audit = AuditService(db, config)
    authz = AuthorizationService(db, audit)
    sessions = SessionManager(db, rbac, audit)
    policy = PolicyEngine(db, rbac, authz, config)

    jobs = JobRepository(db)
    adapters = AdapterRegistry()
    capabilities = CapabilityRegistry(db)
    plugins = PluginManager(db, config, adapters, audit, bundled_dir=BUNDLED_PLUGINS_DIR)
    plugins.discover()  # validate + sync bundled/user plugin registry rows
    plugins.load_enabled()  # register trusted plugins' adapters/parsers
    scheduler = Scheduler(db, config, adapters, plugin_manager=plugins, audit=audit)
    scheduler.recover()

    assets = AssetService(db)
    findings = FindingService(db)
    evidence = EvidenceService(db)
    cases = CaseService(db, audit)
    correlation = CorrelationService(db, assets)
    workflows = WorkflowEngine(db, policy, scheduler, jobs, correlation=correlation)
    installer = ToolInstallManager(capabilities, audit)
    learning = LearningService(db)
    reports = ReportService(db, authz, assets, findings, evidence, cases)
    events = EventBus()
    # Notification providers from config ([notifications.providers.<name>]).
    _provider_cfg = getattr(config, "notification_providers", {}) or {}
    notifications = NotificationService(db, providers=_provider_cfg)
    backups = BackupService(db, config, audit)
    workflow_store = WorkflowStore(db, capabilities=capabilities, adapters=adapters)
    triggers = TriggerStore(db)
    dfir = DfirService(db, audit)
    intel = ThreatIntelService(db)
    # Auto-register IOCs from every completed job's evidence.
    scheduler.intel_service = intel
    explain = ExplanationService(capabilities)
    knowledge = KnowledgeService()
    api_tokens = TokenStore(db)

    adversary = AdversaryService(db)
    vuln = VulnService(db, policy, findings, audit)
    atomic = AtomicService(db, policy, workflows, audit)
    updates = UpdateService(db, MIGRATIONS_DIR, backups=backups, plugins=plugins)

    soc_events = EventStore(db)
    soc_rules = RuleStore(db)
    soc_alerts = AlertService(db, audit)
    soc = SocPipeline(
        db,
        events=soc_events,
        rules=soc_rules,
        alerts=soc_alerts,
        assets=assets,
        cases=cases,
        intel=intel,
        notifications=notifications,
    )

    grc = GrcService(db, audit, config=config, evidence=evidence, vuln=vuln, backups=backups)
    malware = MalwareService(db, evidence=evidence, intel=intel, findings=findings, audit=audit)
    endpoint = EndpointService(db, findings=findings, audit=audit)
    modules = ModuleRegistry(db, audit=audit)
    purple = PurpleService(db, audit=audit, notifications=notifications)
    change = ChangeService(db, audit=audit, notifications=notifications)

    return KsecContext(
        config=config,
        db=db,
        rbac=rbac,
        authz=authz,
        audit=audit,
        sessions=sessions,
        policy=policy,
        jobs=jobs,
        adapters=adapters,
        capabilities=capabilities,
        plugins=plugins,
        scheduler=scheduler,
        workflows=workflows,
        assets=assets,
        findings=findings,
        evidence=evidence,
        cases=cases,
        correlation=correlation,
        installer=installer,
        learning=learning,
        reports=reports,
        notifications=notifications,
        events=events,
        backups=backups,
        workflow_store=workflow_store,
        dfir=dfir,
        intel=intel,
        explain=explain,
        knowledge=knowledge,
        api_tokens=api_tokens,
        soc=soc,
        soc_events=soc_events,
        soc_rules=soc_rules,
        soc_alerts=soc_alerts,
    adversary=adversary,
    vuln=vuln,
    atomic=atomic,
    updates=updates,
    grc=grc,
    malware=malware,
    endpoint=endpoint,
    modules=modules,
    purple=purple,
    change=change,
    triggers=triggers,
    )