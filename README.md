# miniRunAsTI

Yet another RunAsTI. Part of RebuildTool

## How it works

### RunElevated (RunAs) mode

<details>
    <summary>Show</summary>

```mermaid
graph TD
    A[Start RunElevated] --> B{Prepare command and parameters};
    B --> C[Create SHELLEXECUTEINFOW struct];
    C --> D[Set lpVerb = runas];
    D --> E[Call ShellExecuteExW];
    E --> F{System checks privileges};
    F -->|Already admin| G[Launch process with admin rights];
    F -->|Not admin| H[Show UAC prompt];
    H -->|User accepts| G;
    H -->|User denies| I[Error, process not launched];
    G --> Z[End: Success];
    I --> Z;
```

</details>

### System mode

<details>
    <summary>Show</summary>

```mermaid
graph TD
    A[Start RunAsSystem] --> B[Enable SeDebugPrivilege];
    B --> C[Find winlogon.exe PID];
    C --> D[Open winlogon.exe process];
    D --> E[Get process token];
    E --> F[Duplicate token for impersonation];
    F --> G[Apply token to current thread];
    G --> H[Get current thread's SYSTEM token];
    H --> I[Create primary duplicate of the token];
    I --> J[Call CreateProcessAsUserW];
    J --> K[End: Process launched as SYSTEM];
```

</details>

### TrustedInstaller (RunAsTi) mode

<details>
    <summary>Show</summary>

```mermaid
graph TD
    A[Start RunAsTi] --> B[Execute ImpersonateSystem routine];
    B --> C{Thread is now running as SYSTEM};
    C --> D[Open Service Control Manager];
    D --> E[Open TrustedInstaller service];
    E --> F{Check service status};
    F -->|Stopped| G[Start the service];
    G --> H[Wait for 'Running' status];
    F -->|Already running| H;
    H --> I[Get service process PID];
    I --> J[Open TrustedInstaller process];
    J --> K[Get its token];
    K --> L[Create primary duplicate of the token];
    L --> M[Call CreateProcessAsUserW];
    M --> N[End: Process launched as TrustedInstaller];
```

</details>

### RunAsNormalUser mode

<details>
    <summary>Show</summary>

```mermaid
graph TD
    A[Start RunAsNormalUser] --> B{Is process running as admin?};
    B -->|No| B_Error[Error - Requires admin privileges];
    B -->|Yes| C{Attempt to enable SeTcbPrivilege};
    subgraph Scenario 1: Running as SYSTEM
        C -->|Success| D[Get token of desktop user];
        D --> E[Form command with runas.exe];
        E --> F[Launch runas.exe with user's token];
    end

    subgraph Scenario 2: Running as Administrator
        C -->|Fails with Not assigned| G{Is UAC enabled?};
        G -->|Yes| H[Use Safer API for restricted token];
        H --> I[Launch process with restricted token];
        G -->|No| J[Use ShellExecuteExW to launch runas.exe];
    end

    C -->|Other error| C_Error[Error - Privilege check failed];
    F --> Z[End: Process launched as Normal User];
    I --> Z;
    J --> Z;
```

</details>