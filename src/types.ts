export type Severity =
  | 'LOW'
  | 'MODERATE'
  | 'HIGH'
  | 'CRITICAL';

export type Ecosystem =
  | 'npm' | 'pip' | 'rubygems' | 'go' | 'crates'
  | 'maven' | 'nuget' | 'composer' | 'swift' | 'pub' | 'erlang';

export interface CweInfo {
  cweId: string;
  name:  string;
}

export interface CvssInfo {
  score:        number;
  vectorString: string;
}

// Raw advisory as returned by the CTI feed (Component 2)
export interface Advisory {
  ghsaId:                 string;
  summary:                string;
  description:            string | null;
  cwes:                   CweInfo[];
  cvss:                   CvssInfo | null;
  severity:               Severity;
  packageName:            string;
  vulnerableVersionRange: string | null;
  firstPatchedVersion:    string | null;
  ecosystem:              Ecosystem;
}

// Advisory enriched with deployment context and priority score (Component 5 output)
export interface Threat extends Advisory {
  contextualRisk:  string;
  isDevDependency: boolean;
  priorityScore:   number;
}
