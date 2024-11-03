# Architecture Overview

## System Architecture

```mermaid
flowchart TB
    subgraph Frontend["Frontend Layer"]
        CLI[CLI Interface]
        API[API Interface]
    end

    subgraph Core["Core Layer"]
        Pipeline[Security Pipeline]
        Scanner[Security Scanner]
        Analyzer[AI Analyzer]
    end

    subgraph AI["AI Layer"]
        OpenAI[OpenAI Service]
        Claude[Claude Service]
        Models[AI Models]
    end

    subgraph Security["Security Layer"]
        OWASP[OWASP ZAP]
        Nuclei[Nuclei]
        DependencyCheck[Dependency Check]
    end

    subgraph Integration["Integration Layer"]
        Git[Git Integration]
        Notifications[Notifications]
        Reports[Reports]
    end

    Frontend --> Core
    Core --> AI
    Core --> Security
    Core --> Integration

    classDef default fill:#1a1a1a,stroke:#00ff00,color:#fff
    classDef ai fill:#2a2a2a,stroke:#00ffff,color:#fff
    classDef security fill:#2a2a2a,stroke:#ff00ff,color:#fff
    
    class Frontend,Core default
    class AI,Models,OpenAI,Claude ai
    class Security,OWASP,Nuclei,DependencyCheck security
```

## Component Interaction

```mermaid
sequenceDiagram
    participant CLI as CLI Interface
    participant Pipeline as Security Pipeline
    participant AI as AI Services
    participant Security as Security Tools
    participant Git as Git Integration

    CLI->>Pipeline: Initialize Scan
    Pipeline->>Security: Run Security Checks
    Security-->>Pipeline: Security Results
    Pipeline->>AI: Analyze Vulnerabilities
    AI-->>Pipeline: Fix Suggestions
    Pipeline->>AI: Generate Fixes
    AI-->>Pipeline: Implementation Code
    Pipeline->>Security: Validate Fixes
    Security-->>Pipeline: Validation Results
    Pipeline->>Git: Create PR
    Git-->>CLI: PR URL
```

## Data Flow

```mermaid
flowchart LR
    subgraph Input["Input Sources"]
        Code[Source Code]
        Web[Web Apps]
        Config[Configuration]
    end

    subgraph Processing["Processing"]
        Scanner[Security Scanner]
        Analyzer[AI Analyzer]
        Generator[Fix Generator]
    end

    subgraph Storage["Data Storage"]
        Reports[Security Reports]
        Models[AI Models]
        Cache[Result Cache]
    end

    subgraph Output["Output"]
        PR[Pull Requests]
        Notifications[Notifications]
        Metrics[Security Metrics]
    end

    Input --> Processing
    Processing --> Storage
    Processing --> Output

    classDef default fill:#1a1a1a,stroke:#00ff00,color:#fff
    classDef storage fill:#2a2a2a,stroke:#00ffff,color:#fff
    classDef output fill:#2a2a2a,stroke:#ff00ff,color:#fff
    
    class Input,Processing default
    class Storage storage
    class Output output
```

## Directory Structure

```mermaid
graph TD
    Root["/"] --> SRC[src/]
    Root --> Tests[tests/]
    Root --> Docs[docs/]
    Root --> Config[config/]
    
    SRC --> Core[core/]
    SRC --> AI[ai/]
    SRC --> Security[security/]
    SRC --> Utils[utils/]
    
    Core --> Pipeline[pipeline.py]
    Core --> Scanner[scanner.py]
    Core --> Analyzer[analyzer.py]
    
    AI --> Models[models.py]
    AI --> Services[services.py]
    
    Security --> Tools[tools.py]
    Security --> Validators[validators.py]
    
    Utils --> Helpers[helpers.py]
    Utils --> Logger[logger.py]
    
    classDef default fill:#1a1a1a,stroke:#00ff00,color:#fff
    classDef core fill:#2a2a2a,stroke:#00ffff,color:#fff
    classDef utils fill:#2a2a2a,stroke:#ff00ff,color:#fff
    
    class Root,SRC,Tests,Docs,Config default
    class Core,AI,Security core
    class Utils utils
```

## Further Reading

- [Data Flow Details](data-flow.md)
- [Component Details](components.md)
- [Integration Details](integration.md)
- [Implementation Guide](../implementation/README.md)
