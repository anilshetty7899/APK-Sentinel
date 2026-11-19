/** TypeScript type definitions for APK Sentinel analysis data. */

export type AnalysisStatusType = 'QUEUED' | 'RUNNING' | 'COMPLETED' | 'FAILED';
export type RiskLevel = 'LOW' | 'MODERATE' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export interface AnalysisSummary {
  id: string;
  sha256: string;
  original_filename: string;
  file_size: number;
  status: AnalysisStatusType;
  created_at: string;
  risk_score: number | null;
  risk_level: RiskLevel | null;
}

export interface AnalysisStatus {
  id: string;
  sha256: string;
  original_filename: string;
  file_size: number;
  status: AnalysisStatusType;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
  risk_score: number | null;
  risk_level: RiskLevel | null;
  error_message: string | null;
}

export interface ScoreContribution {
  rule_id: string;
  category: string;
  severity: string;
  points: number;
  evidence: string;
  explanation: string;
}

export interface CategoryScore {
  raw_points: number;
  capped_points: number;
  normalized: number;
  weighted: number;
  max_raw: number;
  weight: number;
  contributions: ScoreContribution[];
}

export interface ScoreBreakdown {
  total: number;
  level: RiskLevel;
  breakdown: {
    permissions: CategoryScore;
    code_api: CategoryScore;
    components: CategoryScore;
    indicators: CategoryScore;
  };
}

export interface Permission {
  name: string;
  classification: string;
  description: string;
}

export interface Component {
  name: string;
  type: string;
  exported: boolean;
  permission_protected: boolean;
  permission?: string;
  intent_filters?: string[];
}

export interface SuspiciousApi {
  category: string;
  matched_api: string;
  file: string;
  line?: number;
  severity: string;
  explanation: string;
}

export interface NetworkIndicator {
  indicator: string;
  type: string;
  source_file: string;
  context: string;
}

export interface PotentialSecret {
  type: string;
  pattern_matched: string;
  source_file: string;
  line: number;
  redacted_evidence: string;
  confidence: string;
}

export interface ObfuscationInfo {
  score: number;
  indicators: string[];
  explanation: string;
}

export interface CertificateInfo {
  sha256_fingerprint?: string;
  sha1_fingerprint?: string;
  issuer?: string;
  subject?: string;
  valid_from?: string;
  valid_to?: string;
  signature_scheme?: string;
}

export interface ComponentSummary {
  total_activities: number;
  total_services: number;
  total_receivers: number;
  total_providers: number;
  exported_activities: number;
  exported_services: number;
  exported_receivers: number;
  exported_providers: number;
  unprotected_exported: number;
}

export interface ApkMetadata {
  package: string;
  application_label?: string;
  version_name?: string;
  version_code?: string;
  min_sdk?: number;
  target_sdk?: number;
  sha256: string;
  file_size: number;
}

export interface AnalysisResults {
  id: string;
  status: AnalysisStatusType;
  risk_score: number | null;
  risk_level: RiskLevel | null;
  results: {
    analysis_id: string;
    apk: ApkMetadata;
    permissions: Permission[];
    permission_correlations: { rule_id: string; severity: string; evidence: string; description: string; points: number }[];
    components: Component[];
    component_summary: ComponentSummary;
    suspicious_apis: SuspiciousApi[];
    network_indicators: NetworkIndicator[];
    potential_secrets: PotentialSecret[];
    obfuscation: ObfuscationInfo;
    certificate: CertificateInfo;
    score: ScoreBreakdown;
  } | null;
}

export interface AiReportFinding {
  title: string;
  severity: string;
  category: string;
  description: string;
  evidence: string;
  implication: string;
  recommendation: string;
}

export interface AiReport {
  executive_summary: string;
  risk_assessment: string;
  key_findings: AiReportFinding[];
  security_implications: string;
  recommended_actions: string[];
  limitations: string;
}

export interface AnalysisReportResponse {
  id: string;
  status: AnalysisStatusType;
  ai_report: AiReport | { error: string; detail: string; note: string } | null;
  report_available: boolean;
}
